"""Proxy-native public-key lookup (ADR-006 Fase 1 / PR #3).

``GET /v1/federation/agents/{agent_id}/public-key`` returns the
certificate PEM for an agent. The proxy answers locally when it knows the
agent (``internal_agents`` — Mastio is authoritative per ADR-010) and
otherwise forwards to the Court's equivalent endpoint for federated
lookups.

Lookup order:
  1. ``internal_agents`` — the Mastio is authoritative for its own
     enrolled agents. Hit here → return PEM + scope=local.
  2. Forward to broker when the agent is not local AND the proxy is
     federated. Standalone mode returns 404 outright.

The ``cached_federated_agents`` table carries ``thumbprint`` but not the
full PEM (by design — the cache is meant to be small and invalidatable).
So "federated" responses go through the broker's live endpoint; there is
no stale cert to serve from a cache.

ADR-010 Phase 6a-4 dropped the legacy ``/v1/registry/agents/*`` mirror
of this endpoint together with the Court's equivalent. Only the
``/v1/federation/`` prefix remains.
"""
from __future__ import annotations

import logging
from typing import Literal

import httpx
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import text

from mcp_proxy.config import get_settings
from mcp_proxy.db import cert_thumbprint_from_pem, get_db

_log = logging.getLogger("mcp_proxy.registry.public_key")

federation_router = APIRouter(prefix="/v1/federation/agents", tags=["federation"])


class PublicKeyResponse(BaseModel):
    agent_id: str
    # Broker's equivalent endpoint (app/federation/read.py) returns
    # this exact field name; SDKs already consume `public_key_pem`.
    public_key_pem: str
    cert_thumbprint: str | None = None
    scope: Literal["local", "federated"]


@federation_router.get("/{agent_id}/public-key", response_model=PublicKeyResponse)
async def get_public_key(agent_id: str, request: Request) -> PublicKeyResponse:
    """Return the agent's public key PEM.

    Unauthenticated on purpose: public keys are public. This mirrors the
    broker's equivalent endpoint (``/v1/federation/agents/{id}/public-key``
    is also unauthenticated there).

    Federated proxies always forward to the Court. SPIFFE-authed agents
    rotate their leaf cert on every ``/v1/auth/login``; the Court updates
    ``agents.cert_pem`` on that path but the Mastio's ``internal_agents``
    row still carries the pre-SPIFFE bootstrap cert. Serving the stale
    local copy breaks E2E encryption: the peer encrypts to a public key
    whose private half the recipient no longer holds. The Court is the
    single source of truth for post-login cert material.

    Standalone proxies (no uplink) still answer locally — there's no
    Court to ask, and standalone agents don't rotate via SPIFFE anyway.
    """
    settings = get_settings()

    # Standalone: answer locally, no fallback.
    if settings.standalone:
        async with get_db() as conn:
            row = (await conn.execute(
                text(
                    """
                    SELECT cert_pem FROM internal_agents
                     WHERE agent_id = :aid AND is_active = 1
                    """
                ),
                {"aid": agent_id},
            )).first()
        if not row or not row[0]:
            raise HTTPException(status_code=404, detail="agent not found")
        cert_pem = row[0]
        try:
            cert = crypto_x509.load_pem_x509_certificate(cert_pem.encode())
            pubkey_pem = cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        except ValueError as exc:
            _log.error(
                "internal_agents.cert_pem for %s is not a valid cert: %s",
                agent_id, exc,
            )
            raise HTTPException(
                status_code=500,
                detail="stored cert for local agent is not a valid X.509 PEM",
            )
        return PublicKeyResponse(
            agent_id=agent_id,
            public_key_pem=pubkey_pem,
            cert_thumbprint=cert_thumbprint_from_pem(cert_pem),
            scope="local",
        )

    # Federated: hit the broker's live endpoint. We intentionally do NOT
    # serve from cached_federated_agents — the cache stores thumbprint
    # only, and we don't want to return a stale PEM.
    broker_url = getattr(request.app.state, "reverse_proxy_broker_url", None)
    client: httpx.AsyncClient | None = getattr(
        request.app.state, "reverse_proxy_client", None,
    )
    if not broker_url or client is None:
        raise HTTPException(
            status_code=503,
            detail="broker uplink not configured — cannot resolve federated agent",
        )

    # ADR-010 Phase 6a — Court serves this endpoint under /v1/federation/;
    # the legacy /v1/registry/ mirror has been hard-deleted in Phase 6a-4.
    target = f"{broker_url.rstrip('/')}/v1/federation/agents/{agent_id}/public-key"
    # Broker enforces org isolation + binding auth on this endpoint, so we
    # must propagate the caller's Authorization / DPoP headers. Hop-by-hop
    # headers are dropped for the same reason the reverse-proxy forwarder
    # drops them. Host is stripped separately so the broker's ``build_htu``
    # can reconstruct the URL the SDK originally signed — otherwise the
    # DPoP proof fails verification with 401 because the broker sees its
    # own hostname in ``request.url`` while the proof carries the proxy's.
    _HOP = frozenset([
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade", "content-length",
        "host",
    ])
    forward_headers = {
        k: v for k, v in request.headers.items() if k.lower() not in _HOP
    }
    # Same X-Forwarded-* propagation the generic reverse-proxy does in
    # mcp_proxy/reverse_proxy/forwarder.py — the broker's DPoP htu builder
    # reads these to rebuild the URL the SDK signed. Without them the
    # verification fails and the call 401s even though DPoP proof itself
    # is structurally valid.
    inbound_host = request.headers.get("host")
    if inbound_host and "x-forwarded-host" not in {h.lower() for h in forward_headers}:
        forward_headers["x-forwarded-host"] = inbound_host
    forward_headers.setdefault("x-forwarded-proto", request.url.scheme)
    client_host = request.client.host if request.client else None
    if client_host:
        existing = forward_headers.get("x-forwarded-for")
        forward_headers["x-forwarded-for"] = (
            f"{existing}, {client_host}" if existing else client_host
        )
    try:
        upstream = await client.get(target, headers=forward_headers)
    except httpx.ConnectError as exc:
        raise HTTPException(status_code=502, detail="broker unreachable") from exc
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="broker timeout") from exc

    if upstream.status_code == 404:
        raise HTTPException(status_code=404, detail="agent not found")
    if upstream.status_code >= 400:
        raise HTTPException(
            status_code=upstream.status_code,
            detail=upstream.text or "broker error",
        )

    body = upstream.json()
    pem = body.get("public_key_pem") or body.get("cert_pem") or body.get("public_key")
    if not pem:
        raise HTTPException(status_code=502, detail="broker returned empty public key")
    return PublicKeyResponse(
        agent_id=agent_id,
        public_key_pem=pem,
        cert_thumbprint=body.get("cert_thumbprint") or body.get("thumbprint"),
        scope="federated",
    )
