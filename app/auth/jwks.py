"""
JWKS utilities — convert broker RSA public key to JWK format (RFC 7517)
and compute key IDs via JWK Thumbprint (RFC 7638).
"""
import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import load_pem_x509_certificate


def _b64url(data: bytes) -> str:
    """Base64url-encode without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_bytes(n: int) -> bytes:
    """Convert a positive integer to big-endian bytes (no leading zero padding beyond what's needed)."""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder="big")


def rsa_pem_to_jwk(public_key_pem: str, kid: str | None = None) -> dict:
    """Convert an RSA public key PEM string to a JWK dict (RFC 7517).

    If *kid* is not supplied it is computed via ``compute_kid``.
    """
    pem_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem

    # Try loading as a raw public key first, then as an X.509 certificate
    try:
        pub_key = serialization.load_pem_public_key(pem_bytes)
    except (ValueError, TypeError):
        cert = load_pem_x509_certificate(pem_bytes)
        pub_key = cert.public_key()

    if not isinstance(pub_key, RSAPublicKey):
        raise ValueError("Only RSA keys are supported")

    numbers = pub_key.public_numbers()
    n_b64 = _b64url(_int_to_bytes(numbers.n))
    e_b64 = _b64url(_int_to_bytes(numbers.e))

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid or compute_kid(public_key_pem),
        "n": n_b64,
        "e": e_b64,
    }
    return jwk


def compute_kid(public_key_pem: str) -> str:
    """Compute the JWK Thumbprint (RFC 7638) as a key ID.

    The thumbprint is the base64url-encoded SHA-256 hash of the canonical
    JSON representation of the JWK's required members (alphabetical order,
    no whitespace).
    """
    pem_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem

    try:
        pub_key = serialization.load_pem_public_key(pem_bytes)
    except (ValueError, TypeError):
        cert = load_pem_x509_certificate(pem_bytes)
        pub_key = cert.public_key()

    if not isinstance(pub_key, RSAPublicKey):
        raise ValueError("Only RSA keys are supported")

    numbers = pub_key.public_numbers()
    n_b64 = _b64url(_int_to_bytes(numbers.n))
    e_b64 = _b64url(_int_to_bytes(numbers.e))

    # RFC 7638 §3.2: canonical JSON with required members in alphabetical order
    canonical = json.dumps(
        {"e": e_b64, "kty": "RSA", "n": n_b64},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("ascii")).digest()
    return _b64url(digest)


def build_jwks(keys: list[dict]) -> dict:
    """Wrap JWK dicts into a JWKS response (RFC 7517 §5)."""
    return {"keys": keys}
