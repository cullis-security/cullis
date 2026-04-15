"""
Authentication helpers: DPoP proof generation and x509 client assertion building.

These are pure functions used by CullisClient internally. Exposed for advanced
use cases (custom auth flows, testing).
"""
import base64
import datetime
import hashlib
import time
import uuid

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import jwt as jose_jwt


def generate_dpop_keypair() -> tuple[ec.EllipticCurvePrivateKey, dict]:
    """
    Generate an ephemeral EC P-256 key pair for DPoP proofs.

    Returns (private_key, jwk_dict) where jwk_dict contains {kty, crv, x, y}.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    nums = pub.public_numbers()
    x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
    jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}
    return priv, jwk


def build_dpop_proof(
    private_key: ec.EllipticCurvePrivateKey,
    public_jwk: dict,
    method: str,
    url: str,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    """
    Build a DPoP proof JWT (RFC 9449).

    Args:
        private_key: The ephemeral EC private key.
        public_jwk: The corresponding JWK dict {kty, crv, x, y}.
        method: HTTP method (GET, POST, etc.).
        url: Full URL of the request.
        access_token: If provided, adds ath (access token hash) claim.
        nonce: Server-issued nonce for replay protection.

    Returns:
        Signed DPoP proof JWT string.
    """
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    now = int(time.time())
    claims: dict = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": url,
        "iat": now,
    }
    if access_token:
        claims["ath"] = (
            base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode()).digest()
            ).rstrip(b"=").decode()
        )
    if nonce:
        claims["nonce"] = nonce

    return jose_jwt.encode(
        claims,
        priv_pem,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": public_jwk},
    )


def build_client_assertion(
    agent_id: str,
    cert_pem: str,
    key_pem: str,
) -> tuple[str, str]:
    """
    Build an x509 client assertion JWT for /v1/auth/token.

    Args:
        agent_id: The agent's identifier (e.g. "org::agent").
        cert_pem: PEM-encoded agent certificate.
        key_pem: PEM-encoded agent private key.

    Returns:
        (assertion_jwt, jwt_algorithm) tuple.
    """
    cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
    # Accept either a single PEM cert (classic BYOCA) or a concatenation of
    # PEM blocks (SPIFFE/SPIRE SVID → [leaf, intermediate, …]). In the latter
    # case we include the full chain in x5c so the broker can walk it back
    # to the registered Org CA (the trust anchor is never included — it
    # stays server-side).
    chain_certs = crypto_x509.load_pem_x509_certificates(cert_bytes)
    if not chain_certs:
        raise ValueError("cert_pem contains no certificate")
    cert = chain_certs[0]
    x5c = [
        base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
        for c in chain_certs
    ]

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": agent_id,
        "iss": agent_id,
        "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "jti": str(uuid.uuid4()),
    }

    # Detect key type for JWT algorithm selection
    key_bytes = key_pem.encode() if isinstance(key_pem, str) else key_pem
    priv = serialization.load_pem_private_key(key_bytes, password=None)
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        jwt_alg = "ES256"
    elif isinstance(priv, rsa.RSAPrivateKey):
        jwt_alg = "RS256"
    else:
        raise ValueError(f"Unsupported key type: {type(priv).__name__}")

    assertion = jose_jwt.encode(
        payload, key_pem, algorithm=jwt_alg, headers={"x5c": x5c}
    )
    return assertion, jwt_alg
