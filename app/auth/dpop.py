"""
DPoP (Demonstrating Proof of Possession) — RFC 9449 implementation.

Public API:
  verify_dpop_proof(proof_jwt, htm, htu, access_token=None, expected_nonce=None) → jkt
  compute_jkt(jwk_dict) → str
  build_htu(request, settings) → str
  generate_dpop_nonce() → str
  get_current_dpop_nonce() → str

Every validation failure raises HTTPException 401 with a descriptive detail.
The DPoP JTI is consumed (registered in the store) only after every check
passes — no partial state if verification fails partway through.

Server Nonce (RFC 9449 §8): the server issues a nonce that the client must
include in the next DPoP proof. This eliminates clock skew issues and reduces
the replay window to a single use.
"""
import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import time
from urllib.parse import urlparse, urlunparse

from fastapi import HTTPException, Request, Response, status
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
import jwt as jose_jwt

from app.auth.dpop_jti_store import get_dpop_jti_store

_log = logging.getLogger("agent_trust")

_IAT_WINDOW = 60   # seconds — maximum age of a DPoP proof
_CLOCK_SKEW  = 5   # seconds — tolerance for clock differences between client/server

# ─────────────────────────────────────────────────────────────────────────────
# Server Nonce (RFC 9449 §8)
# ─────────────────────────────────────────────────────────────────────────────

_NONCE_ROTATION_INTERVAL = 300  # seconds — rotate nonce every 5 minutes
_current_nonce: str = ""
_previous_nonce: str = ""
_nonce_generated_at: float = 0


def generate_dpop_nonce() -> str:
    """Generate a fresh server nonce. Called at startup and periodically.

    No lock needed: asyncio event loop is single-threaded, so module-level
    globals cannot be torn by concurrent access within a single worker.
    """
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
    return _hmac.compare_digest(nonce, _current_nonce or "") or _hmac.compare_digest(nonce, _previous_nonce or "")


def set_dpop_nonce_header(response: Response) -> None:
    """Set the DPoP-Nonce header on the response."""
    response.headers["DPoP-Nonce"] = get_current_dpop_nonce()


# ─────────────────────────────────────────────────────────────────────────────
# Base64url helpers
# ─────────────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ─────────────────────────────────────────────────────────────────────────────
# JWK Thumbprint (RFC 7638)
# ─────────────────────────────────────────────────────────────────────────────

def compute_jkt(jwk: dict) -> str:
    """
    Compute the RFC 7638 JWK Thumbprint: SHA-256 of the canonical required
    members, base64url-encoded (no padding).

    Required members by key type:
      EC  → crv, kty, x, y   (alphabetical order)
      RSA → e, kty, n         (alphabetical order)
    """
    kty = jwk.get("kty")
    if kty == "EC":
        required = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif kty == "RSA":
        required = {k: jwk[k] for k in ("e", "kty", "n")}
    else:
        raise ValueError(f"Unsupported kty: {kty!r}")

    canonical = json.dumps(required, sort_keys=True, separators=(",", ":")).encode()
    return _b64url_encode(hashlib.sha256(canonical).digest())


# ─────────────────────────────────────────────────────────────────────────────
# JWK → cryptography public key
# ─────────────────────────────────────────────────────────────────────────────

def _jwk_to_public_key(jwk: dict):
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
    """
    Normalize an HTU for comparison (RFC 9449 §4.3):
    - Strip query string and fragment
    - Lowercase scheme and host
    - Normalize ws:// → http:// and wss:// → https:// (WS upgrade = HTTP GET)
    """
    url = url.replace("wss://", "https://").replace("ws://", "http://")
    p = urlparse(url)
    return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path, "", "", ""))


def build_htu(request: Request, settings) -> str:
    """
    Build the canonical HTU for the current request.

    Priority:
    1. settings.broker_public_url + request path  — explicit override, use in
       production behind a reverse proxy / load balancer.
    2. X-Forwarded-Host / X-Forwarded-Proto — ADR-004: agents reach the broker
       via their local proxy, which sets these headers from the original Host
       seen by the SDK. uvicorn's --proxy-headers handles X-Forwarded-Proto
       and X-Forwarded-For but not Host, so the broker has to promote it
       itself. FORWARDED_ALLOW_IPS is the trust boundary (same as uvicorn).
    3. Starlette-reconstructed URL — works when no proxy is in the path.

    Query string and fragment are always stripped (RFC 9449 §4.3).
    """
    if settings.broker_public_url:
        base = settings.broker_public_url.rstrip("/")
        return _normalize_htu(base + request.url.path)

    fwd_host = request.headers.get("x-forwarded-host")
    if fwd_host:
        fwd_proto = request.headers.get("x-forwarded-proto") or request.url.scheme
        return _normalize_htu(f"{fwd_proto}://{fwd_host}{request.url.path}")

    return _normalize_htu(str(request.url))


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
    """
    Validate a DPoP proof JWT (RFC 9449 §4.3 + §8 server nonce).

    Returns the JWK thumbprint (jkt) on success.
    Raises HTTPException 401 on any failure.
    The JTI is registered in the store only after all checks pass.

    Checks performed (in order):
      1. JWT is structurally valid
      2. typ == "dpop+jwt"
      3. alg ∈ {ES256, PS256}
      4. jwk present and is a public key (no 'd')
      5. jkt computable from jwk
      6. Signature valid with jwk
      7. jti present and not replayed
      8. iat within [-CLOCK_SKEW, IAT_WINDOW] seconds of now
      9. htm matches (case-insensitive)
      10. htu matches (normalized)
      11. ath == base64url(SHA-256(access_token))  — if access_token provided
      12. nonce matches server nonce (RFC 9449 §8) — if require_nonce
    """
    # ── 1. Decode header without signature verification ───────────────────────
    try:
        raw_header = proof_jwt.split(".")[0]
        header = json.loads(_b64url_decode(raw_header))
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: malformed JWT")

    # ── 2. typ ────────────────────────────────────────────────────────────────
    if header.get("typ") != "dpop+jwt":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: typ must be 'dpop+jwt'")

    # ── 3. alg — asymmetric only ──────────────────────────────────────────────
    alg = header.get("alg", "")
    if alg not in ("ES256", "PS256"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            f"Invalid DPoP proof: unsupported algorithm {alg!r}")

    # ── 4. jwk present and public ────────────────────────────────────────────
    jwk = header.get("jwk")
    if not jwk or not isinstance(jwk, dict):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: missing jwk in header")
    if "d" in jwk:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: jwk contains private key material")

    # ── 5. jkt ────────────────────────────────────────────────────────────────
    try:
        jkt = compute_jkt(jwk)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: cannot compute JWK thumbprint")

    # ── 6. Signature ──────────────────────────────────────────────────────────
    try:
        pub_key = _jwk_to_public_key(jwk)
        pub_pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        claims = jose_jwt.decode(
            proof_jwt, pub_pem, algorithms=[alg],
            options={"verify_exp": False, "verify_aud": False, "verify_iat": False},
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: signature verification failed")

    # ── 7. jti — present ────────────────────────────────────────────────────
    jti = claims.get("jti")
    if not jti:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: missing jti")

    # ── 8. iat — freshness ───────────────────────────────────────────────────
    iat = claims.get("iat")
    if iat is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: missing iat")
    age = time.time() - float(iat)
    if not (-_CLOCK_SKEW <= age <= _IAT_WINDOW):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: iat out of acceptable window")

    # ── 9. htm ────────────────────────────────────────────────────────────────
    if claims.get("htm", "").upper() != htm.upper():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: htm mismatch")

    # ── 10. htu ───────────────────────────────────────────────────────────────
    if _normalize_htu(claims.get("htu", "")) != _normalize_htu(htu):
        # Log both URLs to make this debuggable in production. Without
        # the actual values, "htu mismatch" is impossible to diagnose
        # when it happens behind a reverse proxy or with a misconfigured
        # BROKER_PUBLIC_URL — see imp/plan.md item 4 bonus 1.
        _log.warning(
            "DPoP htu mismatch: proof_htu=%r expected_htu=%r — "
            "check BROKER_PUBLIC_URL and reverse proxy headers",
            claims.get("htu", ""), htu,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "Invalid DPoP proof: htu mismatch")

    # ── 11. ath — access token hash ───────────────────────────────────────────
    if access_token is not None:
        expected_ath = _b64url_encode(
            hashlib.sha256(access_token.encode()).digest()
        )
        if not _hmac.compare_digest(claims.get("ath", ""), expected_ath):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "Invalid DPoP proof: ath mismatch")

    # ── 12. Server nonce (RFC 9449 §8) ──────────────────────────────────────
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

    # ── 13. Consume JTI atomically — only after all other checks pass ────────
    store = get_dpop_jti_store()
    is_new = await store.consume_jti(jti)
    if not is_new:
        from app.telemetry_metrics import DPOP_JTI_REPLAY_COUNTER
        DPOP_JTI_REPLAY_COUNTER.add(1)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "DPoP proof replay detected")

    _log.debug("DPoP proof verified: jkt=%s htm=%s", jkt, htm)
    return jkt
