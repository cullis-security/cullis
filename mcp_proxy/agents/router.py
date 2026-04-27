"""Proxy-native agent discovery (ADR-006 Fase 1 / PR #3).

Before this module, ``/v1/agents/search`` was forwarded to the broker
(implicitly, via the ``/v1/registry/*`` reverse-proxy path). That round-
trip is dead weight in standalone mode — and even in federated mode, the
proxy already owns the canonical view of local agents + cached federated
agents, so it can answer without touching the broker.

Search semantics:
  - ``scope=local`` returns only ``internal_agents`` rows (always available).
  - ``scope=federated`` returns only cached_federated_agents rows.
  - No scope filter returns the union. On ``agent_id`` collision between
    the two tables, the local row wins — standalone trumps cached
    federation data, matching ADR-006 §2.4.
  - Optional ``?q=`` does a case-insensitive substring match on
    ``agent_id`` and ``display_name``.
  - Optional ``?capability=X`` filters to agents advertising the capability.
    Repeatable.
  - ``?active=1`` (default) skips disabled/revoked rows.

The endpoint is auth'd by client cert (ADR-014): the cert presented at
the TLS handshake identifies the caller, ``get_agent_from_client_cert``
resolves the canonical agent_id from the cert's SPIFFE SAN and pins
the leaf against ``internal_agents.cert_pem``. Unauthenticated callers
get 401 from nginx (no cert) or from the dependency (cert mismatch).
"""
from __future__ import annotations

import json
import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import text

from mcp_proxy.auth.client_cert import get_agent_from_client_cert
from mcp_proxy.db import cert_thumbprint_from_pem, get_db
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.agents.router")

router = APIRouter(prefix="/v1/agents", tags=["agents"])


class AgentSummary(BaseModel):
    agent_id: str
    display_name: str | None = None
    org_id: str | None = None
    capabilities: list[str]
    scope: Literal["local", "federated"]
    active: bool
    cert_thumbprint: str | None = None


class SearchResponse(BaseModel):
    agents: list[AgentSummary]
    count: int
    scope: Literal["local", "federated", "all"]


def _parse_capabilities(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if isinstance(parsed, list):
        return [str(x) for x in parsed]
    return []


def _matches_filters(
    caps: list[str],
    required_caps: list[str],
    haystack: str,
    q: str | None,
) -> bool:
    if required_caps and not all(c in caps for c in required_caps):
        return False
    if q and q.lower() not in haystack.lower():
        return False
    return True


async def _search_local(
    q: str | None, caps: list[str], active_only: bool,
) -> list[AgentSummary]:
    async with get_db() as conn:
        rows = await conn.execute(
            text(
                """
                SELECT agent_id, display_name, capabilities,
                       cert_pem, is_active
                  FROM internal_agents
                 WHERE :active_only = 0 OR is_active = 1
                """
            ),
            {"active_only": 1 if active_only else 0},
        )
        out: list[AgentSummary] = []
        for row in rows.mappings():
            caps_list = _parse_capabilities(row["capabilities"])
            haystack = f"{row['agent_id']} {row['display_name'] or ''}"
            if not _matches_filters(caps_list, caps, haystack, q):
                continue
            # ADR-010 Phase 6b: ``internal_agents`` doesn't persist org_id
            # or a thumbprint column — derive both on the fly so the
            # response shape matches what the dropped ``local_agents``
            # table used to serve.
            agent_id = row["agent_id"]
            org_id = agent_id.split("::", 1)[0] if "::" in agent_id else None
            out.append(AgentSummary(
                agent_id=agent_id,
                display_name=row["display_name"],
                org_id=org_id,
                capabilities=caps_list,
                scope="local",
                active=bool(row["is_active"]),
                cert_thumbprint=cert_thumbprint_from_pem(row["cert_pem"]),
            ))
        return out


async def _search_federated(
    q: str | None, caps: list[str], active_only: bool,
) -> list[AgentSummary]:
    async with get_db() as conn:
        rows = await conn.execute(
            text(
                """
                SELECT agent_id, display_name, org_id, capabilities,
                       thumbprint, revoked
                  FROM cached_federated_agents
                 WHERE :active_only = 0 OR revoked = 0
                """
            ),
            {"active_only": 1 if active_only else 0},
        )
        out: list[AgentSummary] = []
        for row in rows.mappings():
            caps_list = _parse_capabilities(row["capabilities"])
            haystack = f"{row['agent_id']} {row['display_name'] or ''}"
            if not _matches_filters(caps_list, caps, haystack, q):
                continue
            out.append(AgentSummary(
                agent_id=row["agent_id"],
                display_name=row["display_name"],
                org_id=row["org_id"],
                capabilities=caps_list,
                scope="federated",
                active=not bool(row["revoked"]),
                cert_thumbprint=row["thumbprint"],
            ))
        return out


@router.get("/search", response_model=SearchResponse)
async def search_agents(
    request: Request,
    q: str | None = Query(default=None, max_length=256),
    capability: list[str] = Query(default_factory=list),
    scope: Literal["local", "federated", "all"] = Query(default="all"),
    active: bool = Query(default=True),
    agent: InternalAgent = Depends(get_agent_from_client_cert),
) -> SearchResponse:
    """List agents matching the given filters.

    Returns an intentionally compact summary (no cert PEM). For the
    full certificate material, callers hit
    ``GET /v1/federation/agents/{agent_id}/public-key``.
    """
    local_rows: list[AgentSummary] = []
    federated_rows: list[AgentSummary] = []
    if scope in ("local", "all"):
        local_rows = await _search_local(q, capability, active)
    if scope in ("federated", "all"):
        federated_rows = await _search_federated(q, capability, active)

    # Local-priority merge on agent_id collision — matches ADR-006 §2.4.
    local_ids = {a.agent_id for a in local_rows}
    federated_rows = [a for a in federated_rows if a.agent_id not in local_ids]
    merged = local_rows + federated_rows

    return SearchResponse(agents=merged, count=len(merged), scope=scope)
