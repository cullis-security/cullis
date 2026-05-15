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


async def _enforce_local_token_dpop_binding(
    request: Request,
    payload,
    token: str,
) -> None:
    """Wave B C1 — close the LOCAL_TOKEN replay window.

    When the token carries ``cnf.jkt`` (post-fix mint), require a fresh
    DPoP proof from the inbound request:
      * proof must cover ``request.method`` + the request URL (htu)
      * proof's jwk thumbprint must match the token's ``cnf.jkt``
      * proof's ``ath`` must hash this LOCAL_TOKEN
      * jti is consumed once (replay protection via the shared store)

    When the token has NO ``cnf.jkt`` (legacy, minted before this fix):
      * if ``local_token_require_dpop=true`` → 401
      * else log WARN and accept (back-compat for in-flight tokens
        within the existing TTL window)

    Raises HTTPException(401) on any mismatch. Returns None on success
    so callers stay terse.
    """
    cnf = payload.extra.get("cnf") if isinstance(payload.extra, dict) else None
    expected_jkt = (cnf or {}).get("jkt") if isinstance(cnf, dict) else None

    if expected_jkt is None:
        if get_settings().local_token_require_dpop:
            _log.warning(
                "LOCAL_TOKEN sub=%s rejected: no cnf.jkt and "
                "local_token_require_dpop=true",
                payload.agent_id,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="LOCAL_TOKEN missing cnf.jkt — re-login required",
                headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
            )
        _log.warning(
            "LOCAL_TOKEN sub=%s accepted without DPoP binding (legacy "
            "token; flip MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP=true once "
            "all clients have re-logged in)",
            payload.agent_id,
        )
        return

    proof = request.headers.get("DPoP")
    if not proof:
        _log.info(
            "LOCAL_TOKEN sub=%s rejected: cnf.jkt present but no DPoP "
            "proof header on request",
            payload.agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="LOCAL_TOKEN is DPoP-bound but no DPoP proof presented",
            headers={"WWW-Authenticate": 'DPoP realm="mcp-proxy"'},
        )

    from mcp_proxy.auth.dpop import verify_dpop_proof
    htu = str(request.url).split("?", 1)[0]
    try:
        proof_jkt = await verify_dpop_proof(
            proof, request.method, htu,
            access_token=token, require_nonce=False,
        )
    except HTTPException:
        # verify_dpop_proof already raises 401 with a meaningful detail
        # (which is intentionally generic in upstream telemetry); just
        # propagate.
        raise
    if proof_jkt != expected_jkt:
        _log.info(
            "LOCAL_TOKEN sub=%s rejected: DPoP proof jkt %s does not "
            "match cnf.jkt %s",
            payload.agent_id, proof_jkt, expected_jkt,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="DPoP proof key does not match LOCAL_TOKEN cnf.jkt",
            headers={"WWW-Authenticate": 'DPoP realm="mcp-proxy"'},
        )

    # P1.2 — stamp the verified jkt into the per-request contextvar.
    # log_audit() reads it as a fallback so the row that records this
    # request links to the DPoP key without per-callsite plumbing.
    from mcp_proxy.auth.dpop_context import set_dpop_jkt
    set_dpop_jkt(proof_jkt)


async def _is_known_local_kid(token: str, keystore) -> bool:
    """Pre-check: the token's ``kid`` matches a keystore row that is
    still valid for verification (active OR within the grace window).

    Used to decide whether a ``Authorization: DPoP <jwt>`` should funnel
    into the local validator (and pre-empt the DPoP path) or be left
    alone. Broker-issued JWTs carry a different kid, so that path
    continues to reach ``_get_authenticated_agent_dpop`` unchanged.

    Previously this compared against ``issuer.kid`` only — the current
    active kid. That silently dropped tokens minted under the *old* kid
    during a Phase 2.1 rotation grace window: the JWKS endpoint, the
    keystore filter, and the validator all accepted them, but the dep
    short-circuited before any of that ran. See issue #279.
    """
    try:
        header = jose_jwt.get_unverified_header(token)
    except jose_jwt.PyJWTError:
        return False
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        return False
    key = await keystore.find_by_kid(kid)
    return key is not None and key.is_valid_for_verification


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

    keystore = getattr(request.app.state, "local_keystore", None)
    if keystore is None:
        return None

    token = _extract_bearer_or_dpop_token(request)
    if token is None:
        return None

    # When the scheme is DPoP, the token might be a broker-issued JWT
    # (different kid) the caller legitimately wants handled by the DPoP
    # path. Pre-filter against the keystore so we intercept any kid
    # this Mastio minted (active OR within rotation grace), and leave
    # broker-issued kids alone.
    if not await _is_known_local_kid(token, keystore):
        return None

    try:
        payload = await validate_local_token(
            token, keystore, expected_issuer=issuer.issuer,
        )
    except LocalTokenError as exc:
        # kid matched this Mastio but validation still failed — that's a
        # spoofing or tamper attempt, surface 401 rather than falling
        # through silently.
        # Audit H-IO-2 — server log carries the rejection reason; HTTP
        # detail is generic so an attacker can't probe which check fired.
        _log.info("local token rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="local token rejected",
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        ) from exc

    # Wave B C1 (audit 2026-05-11) — enforce DPoP binding when the
    # token carries cnf.jkt. Legacy tokens (no cnf.jkt) fall back per
    # the local_token_require_dpop flag.
    await _enforce_local_token_dpop_binding(request, payload, token)

    # ADR-020 — typed principals (user / workload) skip the
    # internal_agents lookup. Mirrors the analogous branch in
    # ``_maybe_local_internal_agent`` below + ``client_cert.py``: their
    # SPIFFE ids live outside the workload registry. Without the
    # bypass the ingress dep on /v1/mcp 401s every Frontdesk chat
    # tool-use round-trip even though the LOCAL_TOKEN was minted by
    # this same Mastio just now.
    is_typed_principal = (
        "::user::" in payload.agent_id
        or "::workload::" in payload.agent_id
    )
    if is_typed_principal:
        return TokenPayload(
            sub=payload.agent_id,
            agent_id=payload.agent_id,
            org=payload.org_id,
            exp=payload.expires_at,
            iat=payload.issued_at,
            jti=payload.jti,
            scope=[],
            cnf=None,
        )

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

    keystore = getattr(request.app.state, "local_keystore", None)
    if keystore is None:
        return None

    token = _extract_bearer_or_dpop_token(request)
    if token is None:
        return None
    if not await _is_known_local_kid(token, keystore):
        return None

    try:
        payload = await validate_local_token(
            token, keystore, expected_issuer=issuer.issuer,
        )
    except LocalTokenError as exc:
        # Audit H-IO-2 — server log carries the rejection reason.
        _log.info("local token rejected (egress): %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="local token rejected",
            headers={"WWW-Authenticate": 'Bearer realm="mcp-proxy"'},
        ) from exc

    # Wave B C1 (audit 2026-05-11) — same DPoP binding enforcement on
    # the egress dep so /v1/egress/* doesn't accept replay of an
    # exfiltrated LOCAL_TOKEN. Mirrors _maybe_local_token above.
    await _enforce_local_token_dpop_binding(request, payload, token)

    # ADR-020 — typed principals (user / workload) authenticate via the
    # token's ``::user::`` / ``::workload::`` SPIFFE id, validated above
    # by ``validate_local_token`` against the keystore. They are NOT in
    # ``internal_agents`` (the workload registry); user principals live
    # in ``local_user_principals``. Looking them up + 401'ing on
    # absence is the same trap ``client_cert.py`` had — fixed here for
    # the LOCAL_TOKEN path so chat / MCP via the Connector's
    # ``login_via_proxy_with_local_key`` round-trip lands the per-user
    # InternalAgent envelope downstream consumers (audit, rate-limit)
    # need to attribute the request correctly.
    is_typed_principal = (
        "::user::" in payload.agent_id
        or "::workload::" in payload.agent_id
    )

    if is_typed_principal:
        # ADR-013 Phase 4 — record auth for the anomaly detector.
        from mcp_proxy.observability.traffic_recorder import record_agent_request
        record_agent_request(request, payload.agent_id)

        principal_type = (
            "user" if "::user::" in payload.agent_id else "workload"
        )
        # Strip the ``<org>::user::`` prefix to derive a human-readable
        # display name. Falls back to the full id if the split fails so
        # downstream logging never sees an empty string.
        display = payload.agent_id.split("::", 2)[-1] if "::" in payload.agent_id else payload.agent_id
        from datetime import datetime, timezone
        return InternalAgent(
            agent_id=payload.agent_id,
            display_name=display,
            capabilities=[],
            created_at=datetime.now(timezone.utc).isoformat(),
            is_active=True,
            cert_pem=None,
            dpop_jkt=None,
            reach="intra",
            principal_type=principal_type,
        )

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

    # ADR-013 Phase 4 — record successful auth for the anomaly detector.
    from mcp_proxy.observability.traffic_recorder import record_agent_request
    record_agent_request(request, payload.agent_id)

    return InternalAgent(
        agent_id=payload.agent_id,
        display_name=record.get("display_name") or payload.agent_id,
        capabilities=list(capabilities),
        created_at=str(record.get("created_at") or ""),
        is_active=bool(record.get("is_active", True)),
        cert_pem=record.get("cert_pem"),
        dpop_jkt=record.get("dpop_jkt"),
        # Audit 2026-04-30 lane 1 H2 — preserve the DB-stored reach.
        # Without this, the InternalAgent default ("both") shadows
        # an intra-only or cross-only setting whenever the egress
        # path runs through Bearer LOCAL_TOKEN, silently relaxing
        # reach. The mTLS path (client_cert.py:333) already does
        # this correctly; mirror it here for parity.
        reach=record.get("reach") or "both",
    )


