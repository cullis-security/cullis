"""ADR-010 Phase 6a — Court federation read API.

Sibling of ``app/federation/publish.py``: where ``publish.py`` accepts
Mastio-signed pushes, this module serves the **read** side of the
federation surface — other Mastios query the Court here to discover
cross-org agents and fetch their certs for E2E setup.

The shape (auth, org-isolation, response schema) was inherited from the
legacy ``/v1/registry/agents`` GETs that Phase 6a-4 deleted. These
endpoints are now the sole Court-side read path for federated agent
data.
"""
from __future__ import annotations

import logging

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.config import get_settings
from app.db.database import get_db
from app.registry.binding_store import get_approved_binding
from app.registry.models import (
    AgentListResponse, AgentPublicKeyResponse, AgentResponse,
)
from app.registry.org_store import get_org_by_id
from app.registry.store import get_agent_by_id, list_agents, search_agents
from app.spiffe import internal_id_to_spiffe

_log = logging.getLogger("agent_trust")

router = APIRouter(prefix="/v1/federation", tags=["federation"])


def _as_agent_response(agent, trust_domain: str) -> AgentResponse:
    return AgentResponse(
        agent_id=agent.agent_id,
        org_id=agent.org_id,
        display_name=agent.display_name,
        description=getattr(agent, "description", "") or "",
        capabilities=agent.capabilities,
        is_active=agent.is_active,
        registered_at=agent.registered_at,
        metadata=agent.extra,
        agent_uri=internal_id_to_spiffe(agent.agent_id, trust_domain),
    )


@router.get("/agents", response_model=AgentListResponse)
async def list_federated_agents(
    org_id: str | None = None,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """List registered agents. An agent sees only its own org unless
    ``org_id`` matches its own — cross-org listing is refused."""
    filter_org = current_agent.org if org_id is None else org_id
    if filter_org != current_agent.org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot view agents from other organizations",
        )

    agents = await list_agents(db, org_id=filter_org)
    trust_domain = get_settings().trust_domain
    return AgentListResponse(
        agents=[_as_agent_response(a, trust_domain) for a in agents],
        total=len(agents),
    )


@router.get("/agents/search", response_model=AgentListResponse)
async def search_federated_agents(
    capability: list[str] | None = Query(None, description="Filter by capabilities (AND)"),
    agent_id: str | None = Query(None, description="Direct lookup by agent_id"),
    agent_uri: str | None = Query(None, description="Direct lookup by SPIFFE URI"),
    org_id: str | None = Query(None, description="Filter by organization"),
    pattern: str | None = Query(None, description="Glob pattern on agent_id"),
    q: str | None = Query(None, description="Free-text search"),
    include_own_org: bool = Query(False, description="Include agents from your own org"),
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Cross-org discovery with flexible filters. At least one filter required."""
    if not any([capability, agent_id, agent_uri, org_id, pattern, q]):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one search parameter is required",
        )

    settings = get_settings()
    is_direct = bool(agent_id or agent_uri)
    exclude = None if (is_direct or include_own_org) else current_agent.org

    agents = await search_agents(
        db,
        capabilities=capability,
        agent_id=agent_id,
        agent_uri=agent_uri,
        org_id=org_id,
        pattern=pattern,
        q=q,
        exclude_org_id=exclude,
        trust_domain=settings.trust_domain,
    )

    # Audit 2026-04-30 lane 3 H4 — direct-lookup (``agent_id`` or
    # ``agent_uri``) bypasses the ``exclude_org_id`` filter, so any
    # authenticated agent can resolve any cross-org agent's full
    # record at the Court without an approved binding. Mirror the
    # gate that ``GET /agents/{id}`` and ``GET /agents/{id}/public-key``
    # already enforce: drop cross-org results whose owning org has no
    # approved binding with the caller. Filter silently — same shape
    # as "search found nothing".
    if is_direct and agents:
        gated: list = []
        for a in agents:
            if a.org_id == current_agent.org:
                gated.append(a)
                continue
            binding = await get_approved_binding(db, a.org_id, a.agent_id)
            if binding:
                gated.append(a)
        agents = gated

    return AgentListResponse(
        agents=[_as_agent_response(a, settings.trust_domain) for a in agents],
        total=len(agents),
    )


@router.get("/agents/{agent_id}/public-key", response_model=AgentPublicKeyResponse)
async def get_federated_agent_public_key(
    agent_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Return the PEM public key extracted from the agent's pinned cert.

    Same-org always allowed; cross-org requires an approved binding.
    """
    agent = await get_agent_by_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    if agent.org_id != current_agent.org:
        binding = await get_approved_binding(db, agent.org_id, agent_id)
        if not binding:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No approved binding with this agent",
            )

    if not agent.cert_pem:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not available — agent must login first",
        )

    cert = crypto_x509.load_pem_x509_certificate(agent.cert_pem.encode())
    public_key_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    # Issue #470 — return the full X.509 cert too. SDK consumers post-H7
    # need the cert (not just the SPKI) to bind the public key to the
    # agent identity. Legacy callers reading ``public_key_pem`` are
    # untouched.
    return AgentPublicKeyResponse(
        agent_id=agent_id,
        public_key_pem=public_key_pem,
        cert_pem=agent.cert_pem,
    )


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_federated_agent(
    agent_id: str,
    current_agent: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
):
    """Fetch an agent's full record. Same org-isolation as ``public-key``."""
    agent = await get_agent_by_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    if agent.org_id != current_agent.org:
        binding = await get_approved_binding(db, agent.org_id, agent_id)
        if not binding:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No approved binding with this agent",
            )

    trust_domain = get_settings().trust_domain
    return _as_agent_response(agent, trust_domain)


class MastioUrlResponse(BaseModel):
    """ADR-029 Phase G payload for cross-org Mastio URL discovery."""
    org_id: str
    mastio_url: str


@router.get(
    "/orgs/{org_id}/mastio-url",
    response_model=MastioUrlResponse,
    responses={404: {"description": "Org unknown or no URL published"}},
)
async def get_org_mastio_url(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """ADR-029 Phase G — discover where a peer org's Mastio answers PDP
    federation calls (``POST /v1/policy/tool-call``).

    Unauthenticated, on purpose: this URL is operational metadata that
    every federating Mastio needs to resolve before it can authenticate
    a call to that peer. The same shape as ``/.well-known/jwks.json`` or
    the A2A agent cards under ``/v1/a2a/agents/.../.well-known/agent.json``
    — public infrastructure discovery, no secret material exposed.

    Only orgs with status ``active`` AND a published ``mastio_url`` are
    visible. Unknown orgs, pending/rejected orgs, and orgs that have not
    set the URL collapse to a single 404 so the endpoint cannot be used
    to enumerate the registry beyond what is already public.
    """
    org = await get_org_by_id(db, org_id)
    if (
        not org
        or org.status != "active"
        or not org.mastio_url
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="org unknown or no mastio_url published",
        )
    return MastioUrlResponse(org_id=org.org_id, mastio_url=org.mastio_url)
