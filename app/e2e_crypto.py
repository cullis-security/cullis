"""
End-to-end encryption for inter-agent messages.

Schema:
  sender:    sign(plaintext) -> encrypt({payload, inner_sig}) with recipient pubkey -> sign(ciphertext)
  broker:    verify outer signature on ciphertext (transport integrity), forward opaque blob
  recipient: decrypt -> verify inner signature on plaintext (non-repudiation)

Supports both RSA and EC keys:
  RSA: AES-256-GCM + RSA-OAEP-SHA256 key wrapping
  EC:  AES-256-GCM + ECDH ephemeral key agreement + HKDF key derivation
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization


def _b64url_decode(s: str) -> bytes:
    """Decode base64url with or without padding (RFC 4648 §5 / JWT convention)."""
    if isinstance(s, bytes):
        s = s.decode("ascii")
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _encrypt_aes_key_rsa(pubkey, aes_key: bytes) -> dict:
    """Wrap AES key with RSA-OAEP."""
    encrypted_key = pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {"encrypted_key": base64.urlsafe_b64encode(encrypted_key).decode()}


def _encrypt_aes_key_ec(pubkey, aes_key: bytes) -> dict:
    """Wrap AES key with ECDH + HKDF."""
    ephemeral_key = ec.generate_private_key(pubkey.curve)
    shared_secret = ephemeral_key.exchange(ec.ECDH(), pubkey)
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"cullis-e2e-v1",
    ).derive(shared_secret)
    # XOR the AES key with the derived key
    encrypted_key = bytes(a ^ b for a, b in zip(aes_key, derived_key))
    ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "encrypted_key": base64.urlsafe_b64encode(encrypted_key).decode(),
        "ephemeral_pubkey": base64.urlsafe_b64encode(ephemeral_pub_bytes).decode(),
    }


def encrypt_for_agent(
    recipient_pubkey_pem: str,
    plaintext_dict: dict,
    inner_signature: str,
    session_id: str,
    sender_agent_id: str,
    client_seq: int | None = None,
) -> dict:
    """
    Cifra payload e firma interna con la chiave pubblica del destinatario.

    Schema ibrido: AES-256-GCM per i dati, RSA-OAEP o ECDH per la chiave AES.
    L'AAD (Additional Authenticated Data) lega il ciphertext al contesto di sessione.

    Ritorna: {ciphertext: base64, encrypted_key: base64, iv: base64, [ephemeral_pubkey: base64]}
    """
    pubkey = serialization.load_pem_public_key(recipient_pubkey_pem.encode())

    plaintext = json.dumps(
        {"payload": plaintext_dict, "inner_signature": inner_signature},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    aes_key = os.urandom(32)
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    if client_seq is not None:
        aad = f"{session_id}|{sender_agent_id}|{client_seq}".encode()
    else:
        aad = f"{session_id}|{sender_agent_id}".encode()
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)

    if isinstance(pubkey, rsa.RSAPublicKey):
        key_data = _encrypt_aes_key_rsa(pubkey, aes_key)
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        key_data = _encrypt_aes_key_ec(pubkey, aes_key)
    else:
        raise ValueError(f"Unsupported key type: {type(pubkey).__name__}")

    result = {
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
        "iv": base64.urlsafe_b64encode(iv).decode(),
    }
    result.update(key_data)
    return result


def _decrypt_aes_key_rsa(privkey, cipher_blob: dict) -> bytes:
    """Unwrap AES key with RSA-OAEP."""
    encrypted_key = _b64url_decode(cipher_blob["encrypted_key"])
    return privkey.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _decrypt_aes_key_ec(privkey, cipher_blob: dict) -> bytes:
    """Unwrap AES key with ECDH + HKDF."""
    encrypted_key = _b64url_decode(cipher_blob["encrypted_key"])
    ephemeral_pub_pem = _b64url_decode(cipher_blob["ephemeral_pubkey"])
    ephemeral_pub = serialization.load_pem_public_key(ephemeral_pub_pem)
    shared_secret = privkey.exchange(ec.ECDH(), ephemeral_pub)
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"cullis-e2e-v1",
    ).derive(shared_secret)
    return bytes(a ^ b for a, b in zip(encrypted_key, derived_key))


def decrypt_from_agent(
    recipient_privkey_pem: str,
    cipher_blob: dict,
    session_id: str,
    sender_agent_id: str,
    client_seq: int | None = None,
) -> tuple[dict, str]:
    """
    Decifra un blob cifrato. Ritorna (payload_dict, inner_signature).

    Supporta sia RSA-OAEP che ECDH per l'unwrap della chiave AES.
    """
    privkey = serialization.load_pem_private_key(
        recipient_privkey_pem.encode(), password=None
    )

    iv = _b64url_decode(cipher_blob["iv"])
    ciphertext = _b64url_decode(cipher_blob["ciphertext"])

    if isinstance(privkey, rsa.RSAPrivateKey):
        aes_key = _decrypt_aes_key_rsa(privkey, cipher_blob)
    elif isinstance(privkey, ec.EllipticCurvePrivateKey):
        aes_key = _decrypt_aes_key_ec(privkey, cipher_blob)
    else:
        raise ValueError(f"Unsupported key type: {type(privkey).__name__}")

    aesgcm = AESGCM(aes_key)
    if client_seq is not None:
        aad = f"{session_id}|{sender_agent_id}|{client_seq}".encode()
    else:
        aad = f"{session_id}|{sender_agent_id}".encode()
    plaintext = aesgcm.decrypt(iv, ciphertext, aad)
    data = json.loads(plaintext)

    return data["payload"], data["inner_signature"]


def verify_inner_signature(
    sender_cert_pem: str,
    inner_signature_b64: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
    client_seq: int | None = None,
) -> bool:
    """
    Verify the inner (plaintext) signature after E2E decryption.

    This provides non-repudiation: the recipient can prove the sender
    signed the plaintext, not just the ciphertext. Returns True if valid,
    raises ValueError if invalid.
    """
    from cryptography import x509 as crypto_x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding as asym_pad

    cert = crypto_x509.load_pem_x509_certificate(sender_cert_pem.encode())
    pub_key = cert.public_key()
    sig = _b64url_decode(inner_signature_b64)

    # Canonical format must match sign_message() in message_signer.py
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if client_seq is not None:
        canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{client_seq}|{payload_str}".encode("utf-8")
    else:
        canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{payload_str}".encode("utf-8")

    try:
        if isinstance(pub_key, rsa.RSAPublicKey):
            pss_padding = asym_pad.PSS(
                mgf=asym_pad.MGF1(hashes.SHA256()),
                salt_length=asym_pad.PSS.MAX_LENGTH,
            )
            pub_key.verify(sig, canonical, pss_padding, hashes.SHA256())
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(sig, canonical, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported key type: {type(pub_key).__name__}")
        return True
    except InvalidSignature:
        raise ValueError("Inner signature verification failed — message may have been tampered with")
