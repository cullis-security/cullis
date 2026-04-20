"""ADR-012 Phase 4 — FastAPI dependency that accepts either a
Mastio-local Bearer JWT (ADR-012 Phase 2 onwards) or the legacy
DPoP-bound token the ingress handlers have used since ADR-011.

Lookup order:
  1. If ``settings.local_auth_enabled`` is true *and* the request
     carries ``Authorization: Bearer …``, validate the token via the
     in-process ``LocalIssuer`` and return a ``TokenPayload`` synthesized
     from the local claims + a DB lookup for the agent's capabilities.
  2. Otherwise fall through to ``get_authenticated_agent`` (DPoP).

The adapter keeps handler code unchanged — they still receive a
``TokenPayload`` — while the Court is kept out of the loop for intra-org
traffic. Handlers that need to reach a broker for cross-org operations
continue to use ``BrokerBridge``, which takes the agent_id surfaced
here and performs its own lazy Court login (``_create_client``).
"""
from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

import jwt as jose_jwt

from mcp_proxy.auth.local_validator import LocalTokenError, validate_local_token
from mcp_proxy.config import get_settings
from mcp_proxy.db import get_agent
from mcp_proxy.models import InternalAgent, TokenPayload

_log = logging.getLogger("mcp_proxy.auth.local_agent_dep")


def _extract_bearer_or_dpop_token(request: Request) -> str | None:
    """Pull the opaque JWT from ``Authorization: Bearer …`` OR
    ``Authorization: DPoP …``. The SDK's ``login_via_proxy`` path still
    sends the token with the ``DPoP`` scheme on the downstream request
    even when the Mastio handed it a LOCAL_TOKEN (Phase 2 kept the wire
    format stable). Both shapes must funnel into the local-first branch.
    """
    auth = request.headers.get("Authorization", "")
    lower = auth.lower()
    if lower.startswith("bearer "):
        return auth[7:].strip() or None
    if lower.startswith("dpop "):
        return auth[5:].strip() or None
    return None


def _is_local_kid(token: str, issuer) -> bool:
    """Cheap pre-check: unverified header kid == LocalIssuer's kid.

    Used to decide whether a ``Authorization: DPoP <jwt>`` should funnel
    into the local validator (and pre-empt the DPoP path) or be left
    alone. Broker-issued JWTs carry a different kid, so that path
    continues to reach ``_get_authenticated_agent_dpop`` unchanged.
    """
    try:
        header = jose_jwt.get_unverified_header(token)
    except jose_jwt.PyJWTError:
        return False
    return header.get("kid") == issuer.kid


async def _maybe_local_token(request: Request) -> TokenPayload | None:
    """Return a TokenPayload if the request bears a valid LOCAL_TOKEN,
    else ``None`` so the caller falls through to the DPoP path.
    """
    settings = get_settings()
    if not settings.local_auth_enabled:
        return None

    issuer = getattr(request.app.state, "local_issuer", None)
    if issuer is None:
        return None

    token = _extract_bearer_or_dpop_token(request)
    if token is None:
        return None

    # When the scheme is DPoP, the token might be a broker-issued JWT
    # (different kid) the caller legitimately wants handled by the DPoP
    # path. Pre-filter by kid so we only intercept tokens this Mastio
    # actually signed.
    if not _is_local_kid(token, issuer):
        return None

    try:
        payload = validate_local_token(token, issuer)
    except LocalTokenError as exc:
        # kid matched this Mastio but validation still failed — that's a
        # spoofing or tamper attempt, surface 401 rather than falling
        # through silently.
        _log.info("local token rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"local token: {exc}",
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        ) from exc

    record = await get_agent(payload.agent_id)
    if record is None or not record.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="agent not registered or deactivated",
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        )

    capabilities = record.get("capabilities") or []
    if isinstance(capabilities, str):
        # Defensive: some DB backends store JSON as TEXT; split if needed.
        import json
        try:
            capabilities = json.loads(capabilities)
        except Exception:
            capabilities = [c for c in capabilities.split(",") if c]

    return TokenPayload(
        sub=payload.agent_id,
        agent_id=payload.agent_id,
        org=payload.org_id,
        exp=payload.expires_at,
        iat=payload.issued_at,
        jti=payload.jti,
        scope=list(capabilities),
        cnf=None,
    )


async def _maybe_local_internal_agent(request: Request) -> InternalAgent | None:
    """Egress variant of ``_maybe_local_token``.

    Egress handlers consume ``InternalAgent`` (API-key + DB shape), not
    ``TokenPayload``. Accept a Bearer LOCAL_TOKEN here so an SDK that
    logged in via the Mastio's ``/v1/auth/token`` (ADR-012 Phase 2) can
    also drive ``/v1/egress/*`` without re-authenticating. When the send
    is cross-org, the handlers then delegate to ``BrokerBridge`` which
    lazily performs its own per-agent login_from_pem against the Court
    — the ``LOCAL_TOKEN`` never leaves this process.
    """
    settings = get_settings()
    if not settings.local_auth_enabled:
        return None

    issuer = getattr(request.app.state, "local_issuer", None)
    if issuer is None:
        return None

    token = _extract_bearer_or_dpop_token(request)
    if token is None:
        return None
    if not _is_local_kid(token, issuer):
        return None

    try:
        payload = validate_local_token(token, issuer)
    except LocalTokenError as exc:
        _log.info("local token rejected (egress): %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"local token: {exc}",
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        ) from exc

    record = await get_agent(payload.agent_id)
    if record is None or not record.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="agent not registered or deactivated",
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        )

    capabilities = record.get("capabilities") or []
    if isinstance(capabilities, str):
        import json
        try:
            capabilities = json.loads(capabilities)
        except Exception:
            capabilities = [c for c in capabilities.split(",") if c]

    return InternalAgent(
        agent_id=payload.agent_id,
        display_name=record.get("display_name") or payload.agent_id,
        capabilities=list(capabilities),
        created_at=str(record.get("created_at") or ""),
        is_active=bool(record.get("is_active", True)),
        cert_pem=record.get("cert_pem"),
        dpop_jkt=record.get("dpop_jkt"),
    )


