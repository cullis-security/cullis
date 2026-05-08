"""
DPoP (Demonstrating Proof of Possession) — RFC 9449 implementation for MCP Proxy.

Standalone port from app/auth/dpop.py — no imports from app/.

Public API:
  verify_dpop_proof(proof_jwt, htm, htu, access_token=None, require_nonce=True) -> jkt
  compute_jkt(jwk_dict) -> str
  generate_dpop_nonce() -> str
  get_current_dpop_nonce() -> str
  set_dpop_nonce_header(response) -> None

Every validation failure raises HTTPException 401.
The DPoP JTI is consumed only after all checks pass — no partial state on failure.
"""
import asyncio
import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import time
from urllib.parse import urlparse, urlunparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from fastapi import HTTPException, Response, status
import jwt as jose_jwt

from mcp_proxy.config import get_settings
from mcp_proxy.utils.validation import (
    canonicalize_b64url as _canonicalize_b64url_impl,
    strict_b64url_decode as _strict_b64url_decode,
)

_log = logging.getLogger("mcp_proxy")


# ─────────────────────────────────────────────────────────────────────────────
# Server Nonce (RFC 9449 section 8)
# ─────────────────────────────────────────────────────────────────────────────

_NONCE_ROTATION_INTERVAL = 300  # 5 minutes
_current_nonce: str = ""
_previous_nonce: str = ""
_nonce_generated_at: float = 0


def generate_dpop_nonce() -> str:
    """Generate a fresh server nonce. Called at startup and periodically."""
    global _current_nonce, _previous_nonce, _nonce_generated_at
    _previous_nonce = _current_nonce
    _current_nonce = os.urandom(16).hex()
    _nonce_generated_at = time.time()
    return _current_nonce


def get_current_dpop_nonce() -> str:
    """Return the current server nonce, rotating if expired."""
    if _current_nonce and (time.time() - _nonce_generated_at) <= _NONCE_ROTATION_INTERVAL:
        return _current_nonce
    return generate_dpop_nonce()


def _is_valid_nonce(nonce: str) -> bool:
    """Check if the nonce matches the current or previous nonce."""
    return (
        _hmac.compare_digest(nonce, _current_nonce or "")
        or _hmac.compare_digest(nonce, _previous_nonce or "")
    )


def set_dpop_nonce_header(response: Response) -> None:
    """Set the DPoP-Nonce header on the response."""
    response.headers["DPoP-Nonce"] = get_current_dpop_nonce()


# ─────────────────────────────────────────────────────────────────────────────
# Base64url helpers
# ─────────────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str | bytes) -> bytes:
    """Strict base64url decode — delegates to ``mcp_proxy.utils.validation``.

    Audit S8: previously inlined; now imports from the single vendored copy
    so all Mastio paths stay in sync with ``app.utils.validation``.
    """
    return _strict_b64url_decode(s)


def _canonicalize_b64url(s: str) -> str:
    """Round-trip ``s`` through strict decode -> no-pad encode.

    Used for JKT canonicalization — collapses padding / tail-bit variants
    of the same key into a single canonical form before hashing.
    """
    return _canonicalize_b64url_impl(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ─────────────────────────────────────────────────────────────────────────────
# JWK Thumbprint (RFC 7638)
# ─────────────────────────────────────────────────────────────────────────────

def compute_jkt(jwk: dict) -> str:
    """Compute the RFC 7638 JWK Thumbprint (SHA-256, base64url, no padding).

    Required members by key type:
      EC  -> crv, kty, x, y  (alphabetical)
      RSA -> e, kty, n       (alphabetical)
    """
    kty = jwk.get("kty")
    if kty == "EC":
        raw = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
        try:
            raw["x"] = _canonicalize_b64url(raw["x"])
            raw["y"] = _canonicalize_b64url(raw["y"])
        except ValueError as exc:
            raise ValueError(f"malformed EC JWK coordinate: {exc}") from exc
        required = raw
    elif kty == "RSA":
        raw = {k: jwk[k] for k in ("e", "kty", "n")}
        try:
            raw["n"] = _canonicalize_b64url(raw["n"])
            raw["e"] = _canonicalize_b64url(raw["e"])
        except ValueError as exc:
            raise ValueError(f"malformed RSA JWK coordinate: {exc}") from exc
        required = raw
    else:
        raise ValueError(f"Unsupported kty: {kty!r}")

    canonical = json.dumps(required, sort_keys=True, separators=(",", ":")).encode()
    return _b64url_encode(hashlib.sha256(canonical).digest())


# ─────────────────────────────────────────────────────────────────────────────
# JWK -> cryptography public key
# ─────────────────────────────────────────────────────────────────────────────

def _jwk_to_public_key(jwk: dict):
    """Convert a JWK dict to a cryptography public key object."""
    kty = jwk.get("kty")
    if kty == "EC":
        crv = jwk.get("crv")
        if crv != "P-256":
            raise ValueError(f"Unsupported EC curve: {crv!r}")
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        pub_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
        return pub_numbers.public_key()
    elif kty == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return RSAPublicNumbers(e=e, n=n).public_key()
    else:
        raise ValueError(f"Unsupported kty: {kty!r}")


# ─────────────────────────────────────────────────────────────────────────────
# HTU normalization
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_htu(url: str) -> str:
    """Normalize an HTU for comparison (RFC 9449 section 4.3).

    - Strip query string and fragment
    - Lowercase scheme and host
    - Normalize ws:// -> http:// and wss:// -> https://
    """
    url = url.replace("wss://", "https://").replace("ws://", "http://")
    p = urlparse(url)
    return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path, "", "", ""))


# ─────────────────────────────────────────────────────────────────────────────
# JTI store (replay protection) — delegated to dpop_jti_store module
# ─────────────────────────────────────────────────────────────────────────────
#
# Previously this module defined its own InMemoryDpopJtiStore singleton. The
# dual-backend factory lives in ``mcp_proxy.auth.dpop_jti_store`` so that
# multi-worker deploys can share a Redis-backed store (audit F-B-12 / #182).


# ─────────────────────────────────────────────────────────────────────────────
# Main verifier
# ─────────────────────────────────────────────────────────────────────────────

async def verify_dpop_proof(
    proof_jwt: str,
    htm: str,
    htu: str,
    access_token: str | None = None,
    require_nonce: bool = True,
) -> str:
    """Validate a DPoP proof JWT (RFC 9449 section 4.3 + section 8 server nonce).

    Returns the JWK thumbprint (jkt) on success.
    Raises HTTPException 401 on any failure.
    JTI is consumed only after all checks pass.

    12-point verification:
      1. JWT structurally valid
      2. typ == "dpop+jwt"
      3. alg in {ES256, PS256}
      4. jwk present and public (no 'd' field)
      5. jkt computable
      6. Signature valid
      7. jti present and not replayed
      8. iat within [-clock_skew, iat_window]
      9. htm matches (case-insensitive)
      10. htu matches (normalized)
      11. ath == base64url(SHA-256(access_token)) if provided
      12. nonce matches if require_nonce
    """
    settings = get_settings()

    # -- 1. Decode header without signature verification
    try:
        raw_header = proof_jwt.split(".")[0]
        header = json.loads(_b64url_decode(raw_header))
    except Exception:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: malformed JWT"
        )

    # -- 2. typ
    if header.get("typ") != "dpop+jwt":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: typ must be 'dpop+jwt'"
        )

    # -- 3. alg (asymmetric only)
    alg = header.get("alg", "")
    if alg not in ("ES256", "PS256"):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            f"Invalid DPoP proof: unsupported algorithm {alg!r}",
        )

    # -- 4. jwk present and public
    jwk = header.get("jwk")
    if not jwk or not isinstance(jwk, dict):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: missing jwk in header"
        )
    if "d" in jwk:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid DPoP proof: jwk contains private key material",
        )

    # -- 5. jkt
    try:
        jkt = compute_jkt(jwk)
    except Exception:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid DPoP proof: cannot compute JWK thumbprint",
        )

    # -- 6. Signature verification
    try:
        pub_key = _jwk_to_public_key(jwk)
        pub_pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        claims = jose_jwt.decode(
            proof_jwt,
            pub_pem,
            algorithms=[alg],
            options={"verify_exp": False, "verify_aud": False, "verify_iat": False},
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid DPoP proof: signature verification failed",
        )

    # -- 7. jti present
    jti = claims.get("jti")
    if not jti:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: missing jti"
        )

    # -- 8. iat freshness
    iat = claims.get("iat")
    if iat is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: missing iat"
        )
    age = time.time() - float(iat)
    if not (-settings.dpop_clock_skew <= age <= settings.dpop_iat_window):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid DPoP proof: iat out of acceptable window",
        )

    # -- 9. htm
    if claims.get("htm", "").upper() != htm.upper():
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: htm mismatch"
        )

    # -- 10. htu
    if _normalize_htu(claims.get("htu", "")) != _normalize_htu(htu):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: htu mismatch"
        )

    # -- 11. ath (access token hash)
    if access_token is not None:
        expected_ath = _b64url_encode(
            hashlib.sha256(access_token.encode()).digest()
        )
        if not _hmac.compare_digest(claims.get("ath", ""), expected_ath):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Invalid DPoP proof: ath mismatch"
            )

    # -- 12. Server nonce (RFC 9449 section 8)
    if require_nonce:
        proof_nonce = claims.get("nonce")
        if not proof_nonce:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "use_dpop_nonce",
                headers={"DPoP-Nonce": get_current_dpop_nonce()},
            )
        if not _is_valid_nonce(proof_nonce):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "use_dpop_nonce",
                headers={"DPoP-Nonce": get_current_dpop_nonce()},
            )

    # -- 13. Consume JTI atomically (only after all checks pass)
    from mcp_proxy.auth.dpop_jti_store import get_dpop_jti_store
    is_new = await get_dpop_jti_store().consume_jti(jti)
    if not is_new:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "DPoP proof replay detected"
        )

    _log.debug("DPoP proof verified: jkt=%s htm=%s", jkt, htm)
    return jkt
