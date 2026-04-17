"""
Cryptographic signing and verification of inter-agent messages.

Schema:
  canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{canonical_json(payload)}"
  signature = RSA-PSS-SHA256 or ECDSA-SHA256 depending on key type
  encoding  = base64url (URL-safe, no padding issues in headers or JSON)

The canonical JSON is deterministic: sort_keys=True, no spaces, ensure_ascii=True.
Any modification to the payload, session_id, nonce, or sender invalidates the signature.
"""
import base64
import json

from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as ec_alg, padding, rsa as rsa_alg

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def _b64url_decode(s: str) -> bytes:
    """Decode base64url with or without padding (RFC 4648 §5 / JWT convention)."""
    if isinstance(s, bytes):
        s = s.decode("ascii")
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def _canonical(session_id: str, sender_agent_id: str, nonce: str, timestamp: int,
               payload: dict, client_seq: int | None = None) -> bytes:
    """Deterministic canonical string to be signed."""
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if client_seq is not None:
        return f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{client_seq}|{payload_str}".encode("utf-8")
    return f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{payload_str}".encode("utf-8")


def sign_message(
    private_key_pem: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
    client_seq: int | None = None,
) -> str:
    """
    Sign the message with the agent's private key.
    Returns the signature as a URL-safe base64 string.
    """
    priv_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    canonical = _canonical(session_id, sender_agent_id, nonce, timestamp, payload, client_seq)
    if isinstance(priv_key, rsa_alg.RSAPrivateKey):
        signature = priv_key.sign(canonical, _PSS_PADDING, hashes.SHA256())
    elif isinstance(priv_key, ec_alg.EllipticCurvePrivateKey):
        signature = priv_key.sign(canonical, ec_alg.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported key type: {type(priv_key).__name__}")
    return base64.urlsafe_b64encode(signature).decode()


# ── ADR-008 audit F-A-1 / F-A-3: one-shot envelope signing (v2) ────────
#
# Mirrors ``app/auth/message_signer.py`` — see the module docstring there
# for the threat model. Senders ship ``v=2`` in the wire envelope and
# sign the full envelope identity (mode, reply_to, correlation_id,
# timestamp, nonce, payload) with a distinct domain separator so v1
# payload-only signatures cannot satisfy a v2 verify.


ONESHOT_ENVELOPE_PROTO_VERSION = 2


def compute_oneshot_envelope_sig_input(
    correlation_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    mode: str,
    reply_to: str | None,
    payload: dict,
) -> bytes:
    """Canonical bytes signed for the one-shot envelope outer signature."""
    payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    reply_to_s = reply_to or ""
    return (
        f"oneshot-env:v{ONESHOT_ENVELOPE_PROTO_VERSION}"
        f"|{correlation_id}|{sender_agent_id}|{nonce}|{timestamp}"
        f"|{mode}|{reply_to_s}|{payload_str}"
    ).encode("utf-8")


def sign_oneshot_envelope(
    private_key_pem: str,
    *,
    correlation_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    mode: str,
    reply_to: str | None,
    payload: dict,
) -> str:
    """Sign a v2 one-shot envelope. Returns url-safe base64 signature."""
    priv_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    canonical = compute_oneshot_envelope_sig_input(
        correlation_id=correlation_id,
        sender_agent_id=sender_agent_id,
        nonce=nonce,
        timestamp=timestamp,
        mode=mode,
        reply_to=reply_to,
        payload=payload,
    )
    if isinstance(priv_key, rsa_alg.RSAPrivateKey):
        signature = priv_key.sign(canonical, _PSS_PADDING, hashes.SHA256())
    elif isinstance(priv_key, ec_alg.EllipticCurvePrivateKey):
        signature = priv_key.sign(canonical, ec_alg.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported key type: {type(priv_key).__name__}")
    return base64.urlsafe_b64encode(signature).decode()


def verify_oneshot_envelope_signature(
    cert_or_pubkey_pem: str,
    signature_b64: str,
    *,
    correlation_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    mode: str,
    reply_to: str | None,
    payload: dict,
) -> bool:
    """Return True if the v2 envelope signature verifies, False otherwise."""
    pem_bytes = cert_or_pubkey_pem.encode()
    try:
        if b"CERTIFICATE" in pem_bytes:
            cert = crypto_x509.load_pem_x509_certificate(pem_bytes)
            pub_key = cert.public_key()
        else:
            pub_key = serialization.load_pem_public_key(pem_bytes)
    except Exception:
        return False

    sig = _b64url_decode(signature_b64)
    canonical = compute_oneshot_envelope_sig_input(
        correlation_id=correlation_id,
        sender_agent_id=sender_agent_id,
        nonce=nonce,
        timestamp=timestamp,
        mode=mode,
        reply_to=reply_to,
        payload=payload,
    )
    try:
        if isinstance(pub_key, rsa_alg.RSAPublicKey):
            pub_key.verify(sig, canonical, _PSS_PADDING, hashes.SHA256())
        elif isinstance(pub_key, ec_alg.EllipticCurvePublicKey):
            pub_key.verify(sig, canonical, ec_alg.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except InvalidSignature:
        return False


def verify_signature(
    cert_or_pubkey_pem: str,
    signature_b64: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
    client_seq: int | None = None,
) -> bool:
    """
    Verify a message signature. Returns True if valid, False if invalid.

    Accepts either a PEM certificate or a PEM public key.
    """
    pem_bytes = cert_or_pubkey_pem.encode()
    try:
        if b"CERTIFICATE" in pem_bytes:
            cert = crypto_x509.load_pem_x509_certificate(pem_bytes)
            pub_key = cert.public_key()
        else:
            pub_key = serialization.load_pem_public_key(pem_bytes)
    except Exception:
        return False

    sig = _b64url_decode(signature_b64)
    canonical = _canonical(session_id, sender_agent_id, nonce, timestamp, payload, client_seq)
    try:
        if isinstance(pub_key, rsa_alg.RSAPublicKey):
            pub_key.verify(sig, canonical, _PSS_PADDING, hashes.SHA256())
        elif isinstance(pub_key, ec_alg.EllipticCurvePublicKey):
            pub_key.verify(sig, canonical, ec_alg.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except InvalidSignature:
        return False
