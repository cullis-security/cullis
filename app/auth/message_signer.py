"""
Cryptographic signing and verification of inter-agent messages.

Schema:
  canonical = f"{session_id}|{sender_agent_id}|{nonce}|{canonical_json(payload)}"
  signature = RSA-PSS-SHA256(canonical)
  encoding  = base64url (URL-safe, no padding issues in headers or JSON)

The canonical JSON is deterministic: sort_keys=True, no spaces, ensure_ascii=True.
Any modification to the payload, session_id, nonce, or sender invalidates the signature.
"""
import base64
import json

from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import HTTPException, status

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def _canonical(session_id: str, sender_agent_id: str, nonce: str, timestamp: int, payload: dict) -> bytes:
    """Deterministic canonical string to be signed."""
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{payload_str}".encode("utf-8")


def sign_message(
    private_key_pem: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
) -> str:
    """
    Sign the message with the agent's private key (RSA-PSS-SHA256).
    Returns the signature as a URL-safe base64 string.
    Used by agents/sdk.py before sending each message.
    """
    priv_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    canonical = _canonical(session_id, sender_agent_id, nonce, timestamp, payload)
    signature = priv_key.sign(canonical, _PSS_PADDING, hashes.SHA256())
    return base64.urlsafe_b64encode(signature).decode()


def verify_message_signature(
    cert_pem: str,
    signature_b64: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
) -> None:
    """
    Verify the message signature using the public key in the agent's certificate.
    Raises HTTPException 401 if the signature is invalid.
    Used by the broker in POST /broker/sessions/{id}/messages.
    """
    try:
        cert = crypto_x509.load_pem_x509_certificate(cert_pem.encode())
        pub_key = cert.public_key()
        sig = base64.urlsafe_b64decode(signature_b64)
        canonical = _canonical(session_id, sender_agent_id, nonce, timestamp, payload)
        pub_key.verify(sig, canonical, _PSS_PADDING, hashes.SHA256())
    except InvalidSignature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid message signature — cannot verify the sender",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Signature verification error: {exc}",
        )
