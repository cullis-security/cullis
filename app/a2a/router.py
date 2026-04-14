"""A2A protocol HTTP router — ADR-002 Phase 2a.

Two read-only endpoints:

  GET /v1/a2a/directory
       List all agents the caller may discover, with their AgentCard URLs.
       Filtered by capability/org if supplied.

  GET /v1/a2a/agents/{org_id}/{agent_id}/.well-known/agent.json
       Return the AgentCard for one specific agent.

Both are unauthenticated by design — A2A discovery is intentionally open
(an A2A peer fetches the AgentCard *before* it has credentials). The
listing respects Cullis' is_active flag so deactivated agents are not
exposed. Cross-org visibility rules (binding approval, etc.) land in
Phase 2b when authenticated A2A methods need them.

Phase 2b will add SendMessage / GetTask / CancelTask. Phase 2c adds
streaming + push notifications.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.a2a.agent_card import build_agent_card
from app.config import get_settings
from app.db.database import get_db
from app.registry.store import get_agent_by_id, list_agents

logger = logging.getLogger("agent_trust.a2a")

router = APIRouter(prefix="/a2a", tags=["a2a"])


def _public_base_url(request: Request) -> str:
    """Pick the broker's public URL: settings override > request scheme+host."""
    settings = get_settings()
    if settings.broker_public_url:
        return settings.broker_public_url.rstrip("/")
    return f"{request.url.scheme}://{request.url.netloc}"


def _agent_card_path(org_id: str, agent_name: str) -> str:
    return f"/v1/a2a/agents/{org_id}/{agent_name}/.well-known/agent.json"


def _split_agent_id(agent_id: str) -> tuple[str, str]:
    """Split internal `org::name` into (org, name); return (org, agent_id) if no separator."""
    if "::" in agent_id:
        org, name = agent_id.split("::", 1)
        return org, name
    return "", agent_id


@router.get("/directory")
async def directory(
    request: Request,
    capability: Optional[list[str]] = Query(None, description="Filter by capability (repeatable, AND semantics)"),
    org_id: Optional[str] = Query(None, description="Filter by org_id"),
    db: AsyncSession = Depends(get_db),
):
    """List Cullis agents discoverable via A2A.

    Matches Cullis' own agent listing semantics: active agents only, with
    AgentCard URLs the caller can fetch. Phase 2a does not enforce
    cross-org binding visibility (it would require auth — out of scope
    for discovery). Phase 3 adds the cross-org-federation sub-feature
    that filters cross-org listings against approved bindings.
    """
    base = _public_base_url(request)
    agents = await list_agents(db, org_id=org_id)
    out = []
    for agent in agents:
        if not agent.is_active:
            continue
        if capability:
            agent_caps = set(agent.capabilities)
            if not all(c in agent_caps for c in capability):
                continue
        org, name = _split_agent_id(agent.agent_id)
        out.append(
            {
                "agent_id": agent.agent_id,
                "org_id": agent.org_id,
                "display_name": agent.display_name,
                "capabilities": agent.capabilities,
                "agent_card_url": f"{base}{_agent_card_path(agent.org_id, name)}",
            }
        )
    return {"agents": out, "count": len(out)}


@router.get("/agents/{org_id}/{agent_name}/.well-known/agent.json")
async def agent_card(
    org_id: str,
    agent_name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Return the AgentCard for `{org_id}::{agent_name}`.

    404 when the agent does not exist or is deactivated. Cache headers
    let A2A clients avoid re-fetching on every call.
    """
    settings = get_settings()
    internal_id = f"{org_id}::{agent_name}"
    agent = await get_agent_by_id(db, internal_id)
    if agent is None or not agent.is_active:
        raise HTTPException(status_code=404, detail="agent_not_found")

    card = build_agent_card(
        agent,
        base_url=_public_base_url(request),
        trust_domain=settings.trust_domain,
    )
    # AgentCard pydantic models serialize via model_dump_json — wrap in
    # a JSONResponse with explicit cache headers so peers don't hammer us.
    return JSONResponse(
        content=json.loads(card.model_dump_json()),
        headers={
            "Cache-Control": "public, max-age=300",
            "Content-Type": "application/json",
        },
    )
