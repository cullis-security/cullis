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

from app.utils.validation import strict_b64url_decode


def _b64url_decode(s: str) -> bytes:
    """Strict base64url decode — tolerates padding, rejects garbage bits.

    Delegated to ``app.utils.validation.strict_b64url_decode`` so every
    callsite in app/ agrees on the same canonical rules (audit F-C-3).
    """
    return strict_b64url_decode(s)
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap


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
    """Wrap AES key with ECDH + HKDF + AES-KW (RFC 3394).

    The HKDF-derived 256-bit KEK is consumed by AES Key Wrap, which is a
    deterministic AEAD designed for wrapping symmetric keys. The wrapped
    output is 8 bytes longer than the input (40 bytes for a 32-byte key)
    and any single-bit tamper is detected by the integrity check during
    unwrap (raises ``InvalidUnwrap``).
    """
    ephemeral_key = ec.generate_private_key(pubkey.curve)
    shared_secret = ephemeral_key.exchange(ec.ECDH(), pubkey)
    kek = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"cullis-e2e-v2-aeskw",
    ).derive(shared_secret)
    encrypted_key = aes_key_wrap(kek, aes_key)
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
    """Unwrap AES key with ECDH + HKDF + AES-KW (RFC 3394).

    AES key unwrap raises ``cryptography.hazmat.primitives.keywrap.InvalidUnwrap``
    on any tamper to the wrapped key bytes; the caller propagates as a
    decryption failure.
    """
    encrypted_key = _b64url_decode(cipher_blob["encrypted_key"])
    ephemeral_pub_pem = _b64url_decode(cipher_blob["ephemeral_pubkey"])
    ephemeral_pub = serialization.load_pem_public_key(ephemeral_pub_pem)
    shared_secret = privkey.exchange(ec.ECDH(), ephemeral_pub)
    kek = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b"cullis-e2e-v2-aeskw",
    ).derive(shared_secret)
    return aes_key_unwrap(kek, encrypted_key)


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


# Wave B E1 (audit 2026-05-11) — ``verify_inner_signature`` removed.
#
# The broker copy of ``verify_inner_signature`` was a footgun: pre-fix
# it accepted any cert whose keypair matched the signature, with no
# binding of the cert to the claimed ``sender_agent_id``. The SDK
# twin (``cullis_sdk.crypto.e2e.verify_inner_signature``) was hardened
# by the H7 audit to delegate to ``verify_cert_for_sender`` (proper
# SAN/CN binding + trust anchors); the broker copy never received the
# fix, so importing it would re-introduce the impersonation gap.
#
# Audit verified no production caller existed (only tests/cert_factory
# imports the encrypt half here, and the verify path is referenced
# exclusively from ``cullis_sdk.crypto.e2e`` in
# ``tests/test_oneshot_cross_envelope.py``). Deleting the dead branch
# closes the footgun for future maintainers.
