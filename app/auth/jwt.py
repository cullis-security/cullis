"""
JWT utilities — token creation, verification and revocation.

Algorithm: RS256 (broker private key for signing, public key for verification).

DPoP binding: every token includes a cnf.jkt claim (JWK thumbprint of the
agent's ephemeral DPoP key).  Requests must carry Authorization: DPoP <token>
plus a valid DPoP proof header.  Plain Bearer tokens are rejected.

Replay protection: every token has a unique jti (JWT ID).
JTIs already used to open sessions are tracked in the DB.

Keys are retrieved via the KMSProvider abstraction (app/kms/).
The active backend is selected by the KMS_BACKEND environment variable:
  KMS_BACKEND=local  → reads from disk (default; dev + tests)
  KMS_BACKEND=vault  → HashiCorp Vault KV v2

Note for tests:
  The module variables _broker_private_key_pem and _broker_public_key_pem can
  be set by conftest before the tests run to bypass KMS entirely.
"""
import uuid
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from fastapi import Depends, HTTPException, Request, status
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings, Settings
from app.auth.models import TokenPayload
from app.db.database import get_db
from app.spiffe import internal_id_to_spiffe


# All algorithms the broker accepts when it decodes its own access tokens.
# Signing algorithm is picked from the broker key type at token creation.
_ACCEPTED_SIGNING_ALGS = ["RS256", "ES256", "ES384", "ES512"]


def _signing_alg_for_pem(priv_pem: str) -> str:
    """Pick the JWT signing algorithm that matches the broker private key."""
    pem_bytes = priv_pem.encode() if isinstance(priv_pem, str) else priv_pem
    priv_key = serialization.load_pem_private_key(pem_bytes, password=None)
    if isinstance(priv_key, RSAPrivateKey):
        return "RS256"
    if isinstance(priv_key, EllipticCurvePrivateKey):
        curve = priv_key.curve.name
        return {"secp256r1": "ES256",
                "secp384r1": "ES384",
                "secp521r1": "ES512"}.get(curve, "ES256")
    raise ValueError(f"Unsupported broker key type: {type(priv_key).__name__}")

_TOKEN_ISSUER   = "cullis-broker"
_TOKEN_AUDIENCE = "cullis"

# ─────────────────────────────────────────────────────────────────────────────
# Test overrides — set by conftest to bypass KMS (no filesystem or Vault needed)
# ─────────────────────────────────────────────────────────────────────────────
_broker_private_key_pem: str | None = None
_broker_public_key_pem: str | None = None


async def _get_broker_keys(settings: Settings | None = None) -> tuple[str, str]:
    """
    Return (private_key_pem, public_key_pem) via the configured KMS backend.
    Falls back to the test-override module variables when set (conftest).
    """
    if _broker_private_key_pem and _broker_public_key_pem:
        return _broker_private_key_pem, _broker_public_key_pem

    from app.kms.factory import get_kms_provider
    kms = get_kms_provider()
    priv_pem = await kms.get_broker_private_key_pem()
    pub_pem  = await kms.get_broker_public_key_pem()
    return priv_pem, pub_pem


async def create_access_token(
    agent_id: str,
    org_id: str,
    scope: list[str] | None = None,
    settings: Settings | None = None,
    dpop_jkt: str = "",
    principal_type: str = "agent",
    trust_domain: str | None = None,
) -> tuple[str, int]:
    """
    Create an RS256 JWT signed with the broker's private key.
    dpop_jkt must be the JWK thumbprint of the agent's DPoP key (RFC 9449 §6).
    Returns (token, expires_in_seconds).

    ``trust_domain`` overrides ``settings.trust_domain`` when the
    caller has resolved the org's federated trust domain (per-org
    domains are common in multi-tenant deploys; the SPIFFE ``sub``
    claim must match the cert SAN the verifier just authenticated).
    """
    if settings is None:
        settings = get_settings()

    priv_pem, pub_pem = await _get_broker_keys(settings)

    from app.auth.jwks import compute_kid
    kid = compute_kid(pub_pem)

    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    jti = str(uuid.uuid4())

    effective_td = trust_domain or settings.trust_domain
    # ADR-020 — agent_id can be the legacy 2-segment ``{org}::{name}`` or
    # the typed 3-segment ``{org}::{type}::{name}`` for user / workload
    # principals. Build a SPIFFE URI that matches the cert SAN format
    # the verifier emitted so ``sub`` round-trips correctly.
    if principal_type == "agent":
        spiffe_id = internal_id_to_spiffe(agent_id, effective_td)
    else:
        # ``{org}::{type}::{name}`` → ``spiffe://td/{org}/{type}/{name}``
        parts = agent_id.split("::", 2)
        if len(parts) != 3:
            raise ValueError(
                f"typed agent_id must be ``{{org}}::{{type}}::{{name}}``: "
                f"got {agent_id!r}",
            )
        org_part, type_part, name_part = parts
        spiffe_id = (
            f"spiffe://{effective_td}"
            f"/{org_part}/{type_part}/{name_part}"
        )

    payload = {
        "iss": _TOKEN_ISSUER,
        "aud": _TOKEN_AUDIENCE,
        "sub": spiffe_id,        # SPIFFE ID — standard identity for A2A and external systems
        "agent_id": agent_id,    # internal format org::agent — DB primary key
        "org": org_id,
        "scope": scope or [],
        "principal_type": principal_type,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": jti,
        "cnf": {"jkt": dpop_jkt},  # DPoP key binding — RFC 9449 §6
    }

    alg = _signing_alg_for_pem(priv_pem)
    token = jwt.encode(payload, priv_pem, algorithm=alg, headers={"kid": kid})
    expires_in = settings.jwt_access_token_expire_minutes * 60
    return token, expires_in


async def decode_token(token: str, settings: Settings | None = None) -> TokenPayload:
    """
    Decode and validate an RS256 JWT.
    Raises HTTPException 401 if invalid.
    """
    if settings is None:
        settings = get_settings()

    _, pub_pem = await _get_broker_keys(settings)

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalid or expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        raw = jwt.decode(
            token,
            pub_pem,
            algorithms=_ACCEPTED_SIGNING_ALGS,
            audience=_TOKEN_AUDIENCE,
        )
        if raw.get("iss") != _TOKEN_ISSUER:
            raise credentials_exception
        return TokenPayload(**raw)
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception


async def get_current_agent(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenPayload:
    """
    FastAPI dependency — authenticate via DPoP-bound JWT (RFC 9449).

    Requires:
      Authorization: DPoP <token>     (plain Bearer is rejected)
      DPoP: <proof-jwt>               (per-request proof of key possession)

    The proof's htm/htu are verified against the current request.
    The proof's ath claim is verified against the access token.
    """
    from app.registry.store import get_agent_by_id  # deferred to avoid circular import
    from app.auth.dpop import verify_dpop_proof, build_htu

    _dpop_www_auth = 'DPoP realm="agent-trust", algs="ES256 PS256"'

    # ── 1. Authorization header — must be "DPoP <token>" ─────────────────────
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("dpop "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="DPoP token required — plain Bearer is not accepted",
            headers={"WWW-Authenticate": _dpop_www_auth},
        )
    token = auth_header[5:]  # strip "DPoP "

    # ── 2. Decode and validate the access token ───────────────────────────────
    payload = await decode_token(token)

    # ── 3. Token must be DPoP-bound (cnf.jkt present) ────────────────────────
    if not payload.cnf or "jkt" not in payload.cnf:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not DPoP-bound (missing cnf.jkt)",
            headers={"WWW-Authenticate": _dpop_www_auth},
        )

    # ── 4. DPoP proof header — mandatory ─────────────────────────────────────
    dpop_header = request.headers.get("DPoP")
    if not dpop_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="DPoP proof header required",
            headers={"WWW-Authenticate": _dpop_www_auth},
        )

    # ── 5. Verify proof (htm, htu, ath, jti, iat, signature) ─────────────────
    settings = get_settings()
    htu = build_htu(request, settings)
    jkt = await verify_dpop_proof(
        dpop_header,
        htm=request.method,
        htu=htu,
        access_token=token,
    )

    # ── 6. Proof key must match the token binding ─────────────────────────────
    if jkt != payload.cnf["jkt"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="DPoP proof key does not match token binding",
            headers={"WWW-Authenticate": _dpop_www_auth},
        )

    # ── 7. Revocation check ───────────────────────────────────────────────────
    agent = await get_agent_by_id(db, payload.agent_id)
    if agent and agent.token_invalidated_at is not None:
        token_iat = datetime.fromtimestamp(payload.iat, tz=timezone.utc)
        invalidated_at = agent.token_invalidated_at
        if invalidated_at.tzinfo is None:  # SQLite returns naive datetimes
            invalidated_at = invalidated_at.replace(tzinfo=timezone.utc)
        if token_iat <= invalidated_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": _dpop_www_auth},
            )

    return payload
