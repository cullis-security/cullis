"""Mastio dashboard — Tools + Network sub-router.

Sprint F-B-201 PR-5 of 10. Extracts the tool-registry viewer + reload
plus the cross-network agent discovery directory from
``mcp_proxy/dashboard/router.py``. Three routes total.

Mounted via ``router.include_router(tools_network_routes.router)``.

Routes (3):

  GET  /proxy/tools          tool registry list (read-only)
  GET  /proxy/network        cross-org agent discovery directory
  POST /proxy/tools/reload   reload YAML tool config (CSRF-gated)
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-tools-network"])


@router.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.tools.registry import tool_registry
    tools = tool_registry.list_tools()

    return templates.TemplateResponse("tools.html", _ctx(
        request, session,
        active="tools",
        tools=tools,
    ))


@router.get("/network", response_class=HTMLResponse)
async def network_page(request: Request):
    """Network directory — discover agents across the trust network via broker."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import list_agents, get_config

    q = (request.query_params.get("q") or "").strip() or None
    pattern = (request.query_params.get("pattern") or "").strip() or None
    org_filter = (request.query_params.get("org_id") or "").strip() or None
    capabilities_raw = (request.query_params.get("capabilities") or "").strip()
    capabilities = [c.strip() for c in capabilities_raw.split(",") if c.strip()] or None
    # ``include_own_org`` defaults on for the first page load — the list is
    # a directory, not a filter result, so showing your own org's agents
    # alongside peers is the expected default. Operators uncheck it when
    # they want to focus on cross-org visibility.
    has_query = any(k in request.query_params for k in (
        "q", "pattern", "org_id", "capabilities", "include_own_org", "querier",
    ))
    include_own_org = (
        request.query_params.get("include_own_org") == "on"
        if has_query
        else True
    )
    querier = (request.query_params.get("querier") or "").strip() or None

    internal_agents = await list_agents()
    own_org_id = await get_config("org_id") or ""
    broker_url = await get_config("broker_url") or ""

    bridge = getattr(request.app.state, "broker_bridge", None)

    # Default querier: first active internal agent.
    if not querier and internal_agents:
        querier = next(
            (a["agent_id"] for a in internal_agents if a.get("is_active", True)),
            internal_agents[0]["agent_id"],
        )

    agents: list[dict] = []
    error: str | None = None

    # Always populate the directory on every page load (no more ``submitted``
    # gate). Empty filters = full peer list under the selected querier;
    # typed filters narrow the same list. Errors are surfaced inline so the
    # missing-prereq path (no bridge / no internal agents) stays discoverable.
    if bridge is None:
        error = "Broker bridge not initialized — complete the Setup wizard first."
    elif not internal_agents:
        error = "Create an internal agent first — discovery queries go through an agent identity."
    elif not querier:
        error = "Select a querier agent."
    else:
        try:
            agents = await bridge.discover_agents(
                querier,
                capabilities=capabilities,
                q=q,
                org_id=org_filter,
                pattern=pattern,
            )
            if not include_own_org and own_org_id:
                agents = [a for a in agents if a.get("org_id") != own_org_id]
        except Exception as exc:
            _log.warning("Network directory query failed: %s", exc)
            error = f"Discovery failed: {exc}"

    own_org_count = sum(1 for a in agents if a.get("org_id") == own_org_id) if own_org_id else 0
    peer_count = len(agents) - own_org_count
    has_active_filters = bool(q or pattern or org_filter or capabilities)

    return templates.TemplateResponse("network.html", _ctx(
        request, session,
        active="network",
        internal_agents=internal_agents,
        querier=querier,
        q=q or "",
        pattern=pattern or "",
        org_filter=org_filter or "",
        capabilities=capabilities_raw,
        include_own_org=include_own_org,
        agents=agents,
        own_org_count=own_org_count,
        peer_count=peer_count,
        has_active_filters=has_active_filters,
        own_org_id=own_org_id,
        broker_url=broker_url,
        error=error,
    ))


@router.post("/tools/reload")
async def tools_reload(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.tools.registry import tool_registry
    from mcp_proxy.config import get_settings

    settings = get_settings()
    tool_registry.load_from_yaml(settings.tools_config_path)

    from mcp_proxy.db import log_audit
    await log_audit(
        agent_id="admin",
        action="tools.reload",
        status="success",
        detail=f"Loaded {len(tool_registry)} tool(s)",
    )

