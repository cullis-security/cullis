"""ADR-004 §2.4 — proxy-side signing of broker client_assertion JWTs.

An agent enrolled via the proxy doesn't have its x509 key material locally
(it sits server-side, in Vault or in the proxy_config fallback). To obtain a
DPoP token from the broker via the reverse-proxy, it calls this endpoint
with its mTLS client cert (ADR-014), and the proxy returns a freshly-minted
client_assertion signed with the agent's certificate.

The SDK then posts that assertion to ``/v1/auth/token`` (reverse-proxied),
gets back a DPoP-bound access token, and from that point on it behaves
exactly like any SPIFFE/BYOCA agent — the broker never knows whether the
assertion was signed on-device or on the proxy.

This replaces the BrokerBridge impersonation path for enrolled agents.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from cullis_sdk.auth import build_client_assertion
from mcp_proxy.auth.client_cert import get_agent_from_client_cert
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.auth.sign_assertion")

router = APIRouter(tags=["auth"])


class SignAssertionResponse(BaseModel):
    """Response payload — the signed JWT plus the optional mastio
    counter-signature that the SDK must forward as
    ``X-Cullis-Mastio-Signature`` on ``/v1/auth/token`` (ADR-009 Phase 2).
    When the proxy hasn't loaded its mastio identity yet (legacy deploys
    pre-ADR-009), ``mastio_signature`` is ``None`` and the SDK skips the
    header — matching the ``mastio_pubkey IS NULL`` legacy path server-side.
    """

    client_assertion: str
    agent_id: str
    mastio_signature: str | None = None


@router.post(
    "/v1/auth/sign-assertion",
    response_model=SignAssertionResponse,
    summary="Sign a broker client_assertion on behalf of an enrolled agent",
)
async def sign_assertion(
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_client_cert),
) -> SignAssertionResponse:
    """Return a fresh x509 client_assertion JWT for the authenticated agent.

    The SDK posts this JWT to ``/v1/auth/token`` (via the reverse-proxy) to
    obtain a DPoP-bound access token from the broker. The key never leaves
    the proxy: only the short-lived signed assertion does (exp ≤ 5 min).
    """
    # Prefer the canonical app.state.agent_manager (present in both
    # standalone and federation mode). Fall back to the BrokerBridge's
    # own reference for older boot paths.
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None:
        bridge = getattr(request.app.state, "broker_bridge", None)
        mgr = getattr(bridge, "_agent_manager", None) if bridge else None
    if mgr is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent manager not initialized",
        )

    try:
        cert_pem, key_pem = await mgr.get_agent_credentials(agent.agent_id)
    except ValueError as exc:
        _log.warning(
            "sign-assertion: credentials unavailable for %s: %s",
            agent.agent_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="agent credentials not available on proxy",
        ) from exc

    assertion, _alg = build_client_assertion(agent.agent_id, cert_pem, key_pem)

    # ADR-009 Phase 2 — counter-sign the assertion with the mastio leaf
    # when the identity is available; otherwise leave None and the SDK will
    # omit the header (legacy path).
    mastio_signature: str | None = None
    if getattr(mgr, "mastio_loaded", False):
        try:
            mastio_signature = mgr.countersign(assertion.encode())
        except Exception as exc:
            _log.warning("mastio countersign failed for %s: %s", agent.agent_id, exc)

    return SignAssertionResponse(
        client_assertion=assertion,
        agent_id=agent.agent_id,
        mastio_signature=mastio_signature,
    )
