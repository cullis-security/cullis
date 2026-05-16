"""
FastAPI authentication dependencies for the MCP Proxy.

get_authenticated_agent: DPoP-bound JWT auth for ingress (external agents).
Uses Depends() pattern for FastAPI injection.
"""
import logging

from fastapi import HTTPException, Request, status

from mcp_proxy.models import TokenPayload

_log = logging.getLogger("mcp_proxy")

_DPOP_WWW_AUTH = 'DPoP realm="mcp-proxy", algs="ES256 PS256"'


async def get_authenticated_agent(request: Request) -> TokenPayload:
    """Authenticate an external agent.

    ADR-012 Phase 4: when ``local_auth_enabled`` is true and the request
    carries ``Authorization: Bearer <jwt>``, validate the JWT against the
    in-process ``LocalIssuer`` and surface a ``TokenPayload`` derived
    from local claims + DB lookup (capabilities, is_active). Otherwise
    fall through to the legacy DPoP-bound path below.
    """
    from mcp_proxy.auth.local_agent_dep import _maybe_local_token
    local = await _maybe_local_token(request)
    if local is not None:
        return local
    return await _get_authenticated_agent_dpop(request)


async def _get_authenticated_agent_dpop(request: Request) -> TokenPayload:
    """Authenticate an external agent via DPoP-bound JWT (RFC 9449).

    Requires:
      Authorization: DPoP <token>     (plain Bearer is rejected)
      DPoP: <proof-jwt>               (per-request proof of key possession)

    Steps:
      1. Extract Authorization: DPoP <token>
      2. Extract DPoP: <proof> header
      3. decode_token() — validate JWT via JWKS
      4. verify_dpop_proof() — validate proof (htm, htu, ath)
      5. Compare cnf.jkt from token with jkt from proof
      6. Return TokenPayload or raise 401
    """
    from mcp_proxy.main import get_jwks_client
    from mcp_proxy.auth.jwt_validator import decode_token
    from mcp_proxy.auth.dpop import verify_dpop_proof, _normalize_htu
    from mcp_proxy.config import get_settings

    # -- 1. Authorization header (must be "DPoP <token>")
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("dpop "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="DPoP token required — plain Bearer is not accepted",
            headers={"WWW-Authenticate": _DPOP_WWW_AUTH},
        )
    token = auth_header[5:]  # strip "DPoP "

    # -- 2. DPoP proof header (mandatory)
    dpop_header = request.headers.get("DPoP")
    if not dpop_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="DPoP proof header required",
            headers={"WWW-Authenticate": _DPOP_WWW_AUTH},
        )

    # -- 3. Decode and validate the access token via JWKS
    jwks_client = get_jwks_client()
    if jwks_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWKS client not initialized — proxy not ready",
        )
    payload = await decode_token(token, jwks_client)

    # -- 4. Token must be DPoP-bound (cnf.jkt present)
    if not payload.cnf or "jkt" not in payload.cnf:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not DPoP-bound (missing cnf.jkt)",
            headers={"WWW-Authenticate": _DPOP_WWW_AUTH},
        )

    # -- 5. Build canonical HTU for proof verification
    settings = get_settings()
    if settings.proxy_public_url:
        htu = settings.proxy_public_url.rstrip("/") + request.url.path
    else:
        htu = str(request.url)

    # -- 6. Verify DPoP proof (htm, htu, ath, jti, iat, nonce, signature)
    jkt = await verify_dpop_proof(
        dpop_header,
        htm=request.method,
        htu=htu,
        access_token=token,
    )

    # -- 7. Proof key must match the token binding
    if jkt != payload.cnf["jkt"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="DPoP proof key does not match token binding",
            headers={"WWW-Authenticate": _DPOP_WWW_AUTH},
        )

    # P1.2 — stamp the verified jkt into the per-request contextvar so
    # log_audit() picks it up downstream without threading the value
    # through every call site. Stamp only on the success path: a 401
    # before this point must not correlate the audit row to a
    # thumbprint the verifier just rejected.
    from mcp_proxy.auth.dpop_context import set_dpop_jkt
    set_dpop_jkt(jkt)

    # ADR-032 Layer 2 — graceful stamp of the per-request "on behalf of
    # user" contextvar when the Connector adds X-Cullis-Session-Token +
    # X-Cullis-On-Behalf-Of-User headers. See ``user_session`` module.
    from mcp_proxy.auth.user_session import maybe_stamp_user_session
    await maybe_stamp_user_session(request, caller_agent_id=payload.agent_id)

    _log.debug("Authenticated agent: %s (org=%s)", payload.agent_id, payload.org)
    return payload
