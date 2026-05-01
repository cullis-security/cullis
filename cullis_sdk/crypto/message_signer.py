"""
Cryptographic signing and verification of inter-agent messages.

Schema:
  canonical = f"{session_id}|{sender_agent_id}|{nonce}|{timestamp}|{canonical_json(payload)}"
  signature = RSA-PSS-SHA256 or ECDSA-SHA256 depending on key type
  encoding  = base64url (URL-safe, no padding issues in headers or JSON)

The canonical JSON is deterministic: sort_keys=True, no spaces, ensure_ascii=True.
Any modification to the payload, session_id, nonce, or sender invalidates the signature.

H7 audit fix: ``verify_signature`` and ``verify_oneshot_envelope_signature``
no longer accept a bare SPKI public key, always bind the cert subject to
the claimed ``sender_agent_id``, and accept an optional ``trust_anchors_pem``
to chain-validate the cert against the Org CA. See ``_cert_trust`` for the
full rationale.
"""
import base64
import json
import re
from collections.abc import Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec as ec_alg, padding, rsa as rsa_alg

from cullis_sdk.crypto._cert_trust import verify_cert_for_sender

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


_B64URL_ALPHABET_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64url_decode(s: str) -> bytes:
    """Strict base64url decode — tolerates padding, rejects garbage bits.

    Mirrors ``app.utils.validation.strict_b64url_decode`` — the SDK
    vendors the implementation to keep ``app/`` out of its runtime deps
    (audit F-C-3).
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
    trust_anchors_pem: Sequence[str] | None = None,
) -> bool:
    """Return True if the v2 envelope signature verifies, else False.

    H7 audit fix: ``cert_pem`` MUST be a full X.509 certificate PEM.
    Bare SPKI public keys (the silent-fallback the audit flagged) are
    rejected because a bare SPKI carries no identity, so the verifying
    key cannot be bound to ``sender_agent_id``.

    The cert subject (CN or SPIFFE SAN) must identify
    ``sender_agent_id`` — without that bind any valid signature from
    any cert would be accepted as proof the claimed agent sent the
    message.

    When ``trust_anchors_pem`` is supplied (e.g. by the SDK consumer
    threading the operator-pinned Org CA bundle), the cert must also
    chain to one of the anchors. Without anchors the verifier still
    enforces the parse + bind step, which is enough to stop the
    substitution attacks the audit flagged.
    """
    cert = verify_cert_for_sender(cert_pem, sender_agent_id, trust_anchors_pem)
    if cert is None:
        return False
    pub_key = cert.public_key()

    try:
        sig = _b64url_decode(signature_b64)
    except Exception:
        return False
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
    cert_pem: str,
    signature_b64: str,
    session_id: str,
    sender_agent_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
    client_seq: int | None = None,
    *,
    trust_anchors_pem: Sequence[str] | None = None,
) -> bool:
    """
    Verify a message signature. Returns True if valid, False if invalid.

    H7 audit fix: ``cert_pem`` MUST be a full X.509 certificate PEM.
    Bare SPKI public keys are rejected. The cert subject (CN or SPIFFE
    SAN) must identify ``sender_agent_id``. When ``trust_anchors_pem``
    is supplied, the cert must also chain to one of the anchors.
    """
    cert = verify_cert_for_sender(cert_pem, sender_agent_id, trust_anchors_pem)
    if cert is None:
        return False
    pub_key = cert.public_key()

    try:
        sig = _b64url_decode(signature_b64)
    except Exception:
        return False
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
