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
from cryptography.hazmat.primitives.asymmetric import ec as ec_alg, padding, rsa as rsa_alg
from fastapi import HTTPException, status

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


# ── ADR-008 audit F-A-1 / F-A-3: one-shot envelope signing ─────────────
#
# The v1 one-shot wire used ``canonical = f"oneshot:<corr>|<sender>|<nonce>|..."``
# which covered only ``payload``. Fields that the broker and local stores
# persist alongside the payload — ``mode``, ``reply_to``, ``correlation_id``,
# ``timestamp``, ``nonce`` — were outside the signed region. An attacker
# with DB/process access could flip those fields post-storage without
# invalidating the signature. Most critically, flipping ``mode`` from
# ``envelope`` to ``mtls-only`` caused the recipient SDK to return an
# attacker-chosen plaintext with ``sender_verified=False`` but no other
# signal (callers ignored the flag).
#
# v2 covers the full envelope identity with a distinct domain separator:
#   "oneshot-env:v2|<corr>|<sender>|<nonce>|<ts>|<mode>|<reply_to>|<payload_json>"
# Senders set ``v=2`` in the wire envelope. Broker ingest and recipient
# SDK decrypt both verify over v2 and hard-reject v1. Domain separation
# via the ``oneshot-env:v2`` prefix prevents cross-protocol replay with
# session messages or inner signatures.


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
    """Canonical bytes to sign for the one-shot envelope outer signature.

    Covers every field the broker and the recipient store — any tamper to
    ``mode``, ``reply_to``, ``correlation_id``, ``timestamp``, ``nonce``
    or ``payload`` invalidates the signature. See
    ``ONESHOT_ENVELOPE_PROTO_VERSION`` for the on-wire version pin.
    """
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
    cert_pem: str,
    signature_b64: str,
    *,
    correlation_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    mode: str,
    reply_to: str | None,
    payload: dict,
) -> None:
    """Verify a v2 one-shot envelope signature.

    Raises ``HTTPException(401)`` on invalid signature or unsupported key.
    Use ``verify_oneshot_envelope_signature_bool`` from the SDK when a
    boolean return is preferred.
    """
    try:
        cert = crypto_x509.load_pem_x509_certificate(cert_pem.encode())
        pub_key = cert.public_key()
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
        if isinstance(pub_key, rsa_alg.RSAPublicKey):
            pub_key.verify(sig, canonical, _PSS_PADDING, hashes.SHA256())
        elif isinstance(pub_key, ec_alg.EllipticCurvePublicKey):
            pub_key.verify(sig, canonical, ec_alg.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported key type: {type(pub_key).__name__}")
    except InvalidSignature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid one-shot envelope signature — cannot verify the sender",
        )
    except HTTPException:
        raise
    except Exception as exc:
        import logging
        logging.getLogger("agent_trust").error(
            "One-shot envelope signature verification error: %s", exc,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="One-shot envelope signature verification failed",
        )


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
    Sign the message with the agent's private key (RSA-PSS-SHA256).
    Returns the signature as a URL-safe base64 string.
    Used by agents/sdk.py before sending each message.
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


def verify_message_signature(
    cert_pem: str,
    signature_b64: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
    client_seq: int | None = None,
) -> None:
    """
    Verify the message signature using the public key in the agent's certificate.
    Raises HTTPException 401 if the signature is invalid.
    Used by the broker in POST /broker/sessions/{id}/messages.
    """
    try:
        cert = crypto_x509.load_pem_x509_certificate(cert_pem.encode())
        pub_key = cert.public_key()
        sig = _b64url_decode(signature_b64)
        canonical = _canonical(session_id, sender_agent_id, nonce, timestamp, payload, client_seq)
        if isinstance(pub_key, rsa_alg.RSAPublicKey):
            pub_key.verify(sig, canonical, _PSS_PADDING, hashes.SHA256())
        elif isinstance(pub_key, ec_alg.EllipticCurvePublicKey):
            pub_key.verify(sig, canonical, ec_alg.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported key type: {type(pub_key).__name__}")
    except InvalidSignature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid message signature — cannot verify the sender",
        )
    except Exception as exc:
        import logging
        logging.getLogger("agent_trust").error("Signature verification error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signature verification failed",
        )
