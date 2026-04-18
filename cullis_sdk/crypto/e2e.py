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
import re

# url-safe base64 alphabet (RFC 4648 section 5).
_B64URL_ALPHABET_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64url_decode(s: str) -> bytes:
    """Strict base64url decode — tolerates padding, rejects garbage bits.

    Mirrors ``app.utils.validation.strict_b64url_decode`` — the SDK
    deliberately vendors the implementation so it has zero runtime deps
    on ``app/``. Both must stay in sync (audit F-C-3).
    """
    if isinstance(s, bytes):
        s = s.decode("ascii")
    stripped = s.rstrip("=")
    if not _B64URL_ALPHABET_RE.fullmatch(stripped):
        raise ValueError("base64url contains non-url-safe characters")
    rem = len(stripped) % 4
    if rem == 1:
        raise ValueError("base64url length is not valid (length % 4 == 1)")
    padded = stripped + ("=" * ((4 - rem) % 4))
    decoded = base64.urlsafe_b64decode(padded)
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != stripped:
        raise ValueError(
            "base64url contains non-canonical trailing bits — "
            "decoded bytes do not round-trip to the input"
        )
    return decoded

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
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
    Encrypt payload and inner signature with the recipient's public key.

    Hybrid scheme: AES-256-GCM for data, RSA-OAEP or ECDH for AES key wrapping.
    AAD (Additional Authenticated Data) binds the ciphertext to the session context.

    Returns: {ciphertext: base64, encrypted_key: base64, iv: base64, [ephemeral_pubkey: base64]}
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
    Decrypt an encrypted blob. Returns (payload_dict, inner_signature).

    Supports both RSA-OAEP and ECDH for AES key unwrapping.
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
    from cryptography.hazmat.primitives import serialization

    # Accept either a full X.509 certificate PEM or a bare SPKI public
    # key PEM — different Cullis surfaces return one or the other (the
    # Mastio public-key endpoint returns SPKI, the broker registry
    # historically returned the cert). Matches the pattern in
    # ``message_signer.verify_oneshot_envelope_signature``.
    pem_bytes = sender_cert_pem.encode()
    if b"CERTIFICATE" in pem_bytes:
        cert = crypto_x509.load_pem_x509_certificate(pem_bytes)
        pub_key = cert.public_key()
    else:
        pub_key = serialization.load_pem_public_key(pem_bytes)
    sig = _b64url_decode(inner_signature_b64)

    # Canonical format must match sign_message() in message_signer.py
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if client_seq is not None:
        canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{client_seq}|{payload_str}".encode("utf-8")
    else:
        canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{payload_str}".encode("utf-8")

    try:
        if isinstance(pub_key, rsa.RSAPublicKey):
            _PSS_PADDING = asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            )
            pub_key.verify(sig, canonical, _PSS_PADDING, hashes.SHA256())
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key.verify(sig, canonical, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported key type: {type(pub_key).__name__}")
        return True
    except InvalidSignature:
        raise ValueError("Inner signature verification failed — message may have been tampered with")
