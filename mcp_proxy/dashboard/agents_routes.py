"""Mastio dashboard — Agents sub-router.

Sprint F-B-201 PR-4 of 10. Extracts the agent registry surface
(``/proxy/agents`` + per-agent management endpoints) from
``mcp_proxy/dashboard/router.py``.

Mounted via ``router.include_router(agents_routes.router)``.

Routes (7):

  GET  /proxy/agents                            agent list + KPIs
  POST /proxy/agents/create                     enroll a new internal agent
  GET  /proxy/agents/{agent_id}                 developer-portal detail page
  GET  /proxy/agents/{agent_id}/env-download    download env.sample
  POST /proxy/agents/{agent_id}/reach           edit reach (intra/cross/both)
  POST /proxy/agents/{agent_id}/deactivate      flip is_active=False
  POST /proxy/agents/{agent_id}/delete          permanent delete + cascade

Mirrors Court PR-7 (#850) ``app/dashboard/agents_lifecycle_routes.py``
+ ``agents_credentials_routes.py`` pattern, here kept in a single
sub-router because the Mastio surface is simpler than Court's.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_AGENTS_DELETE,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-agents"])


async def _refresh_org_status_from_broker() -> str:
    """Synchronously ask the broker for the current org status and update
    the cached value in proxy_config.

    The cached value can drift behind reality in two situations:
      1. The broker admin approves the org while the proxy was not polling
         (no dashboard tab open).
      2. The bootstrap script (setup_proxy_org.py) writes status='pending'
         and never updates it after the broker admin approves.

    Returns the latest known status string ('pending', 'active', 'rejected',
    or '' if unknown / not configured). On any error, returns the cached
    value unchanged so the page render still works offline.
    """
    import httpx
    from mcp_proxy.db import get_config, set_config

    cached = await get_config("org_status") or ""

    org_id = await get_config("org_id")
    broker_url = await get_config("broker_url")
    org_secret = await get_config("org_secret")
    if not org_id or not broker_url or not org_secret:
        return cached

    try:
        from mcp_proxy.config import get_settings as _s, broker_tls_verify
        async with httpx.AsyncClient(
            verify=broker_tls_verify(_s()), timeout=3.0,
        ) as http:
            resp = await http.get(
                f"{broker_url}/v1/registry/orgs/me",
                headers={"X-Org-Id": org_id, "X-Org-Secret": org_secret},
            )
            if resp.is_success:
                fresh = (resp.json() or {}).get("status", "")
                if fresh and fresh != cached:
                    await set_config("org_status", fresh)
                return fresh or cached
    except Exception as exc:
        _log.debug("org_status refresh failed: %s", exc)

    return cached


@router.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import list_agents, get_config
    # Refresh the cached broker status BEFORE rendering, so the static
    # 'Approval Pending' banner in the template is never lying about a
    # state that the broker has already moved past.
    org_status = await _refresh_org_status_from_broker()
    agents = await list_agents()
    has_ca = bool(await get_config("org_ca_cert"))

    # Split by reach so the template can render two sections:
    # Federated (reach in {'cross','both'}) on top, Local (reach ==
    # 'intra') below. Peer-org agents live on /proxy/network now —
    # this page is exclusively "my agents".
    federated_agents = [a for a in agents if a.get("reach", "both") != "intra"]
    local_agents = [a for a in agents if a.get("reach", "both") == "intra"]

    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        federated_agents=federated_agents,
        local_agents=local_agents,
        org_status=org_status,
        has_ca=has_ca,
        new_agent_id=None,
    ))




@router.post("/agents/create")
async def agents_create(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import list_agents, log_audit, get_config
    from mcp_proxy.egress.agent_manager import AgentManager
    from mcp_proxy.config import get_settings

    form = await request.form()
    agent_name = str(form.get("agent_name", "")).strip().lower().replace(" ", "_")
    display_name = str(form.get("display_name", "")).strip()
    capabilities_raw = str(form.get("capabilities", "")).strip()

    if not agent_name or not display_name:
        agents = await list_agents()
        _org_status = await get_config("org_status") or ""
        _has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("agents.html", _ctx(
            request, session,
            active="agents",
            agents=agents,
            org_status=_org_status,
            has_ca=_has_ca,
            error="Agent name and display name are required.",
            new_agent_id=None,
        ))

    capabilities = [c.strip() for c in capabilities_raw.split(",") if c.strip()]

    # Determine org_id from config or settings
    org_id = await get_config("org_id") or get_settings().org_id

    # ADR-014 PR-C — agent creation requires a loaded Org CA so the
    # Mastio can mint the agent's TLS client cert (the credential).
    try:
        mgr = AgentManager(org_id=org_id)
        ca_loaded = await mgr.load_org_ca_from_config()

        if not ca_loaded:
            agents = await list_agents()
            _org_status = await get_config("org_status") or ""
            return templates.TemplateResponse("agents.html", _ctx(
                request, session,
                active="agents",
                agents=agents,
                org_status=_org_status,
                has_ca=False,
                error=(
                    "Org CA is not loaded — complete broker setup before "
                    "creating agents (the cert is the agent credential)."
                ),
                new_agent_id=None,
            ))

        agent_info, _key_pem = await mgr.create_agent(agent_name, display_name, capabilities)
        agent_id = agent_info["agent_id"]
    except Exception as exc:
        agents = await list_agents()
        _org_status = await get_config("org_status") or ""
        _has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("agents.html", _ctx(
            request, session,
            active="agents",
            agents=agents,
            org_status=_org_status,
            has_ca=_has_ca,
            error=f"Failed to create agent: {exc}",
            new_agent_id=None,
        ))

    await log_audit(
        agent_id=agent_id,
        action="agent.create",
        status="success",
        detail=f"display_name={display_name}, capabilities={capabilities}, mode=x509",
    )

    # ADR-010 Phase 6a-4 — the dashboard used to follow agent creation with
    # ``POST /v1/registry/agents`` + ``POST /v1/registry/bindings`` + auto-
    # approve via the legacy org_secret auth. That path is gone. Cross-org
    # exposure is now opt-in: the operator flips the federate toggle on
    # this agent row and manages bindings separately. Both happen through
    # the standard Mastio admin surface (see PATCH /v1/admin/agents/{id}/
    # federated and /v1/registry/bindings endpoints from the dashboard).

    agents = await list_agents()
    org_status = await get_config("org_status") or ""
    has_ca = bool(await get_config("org_ca_cert"))
    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        org_status=org_status,
        has_ca=has_ca,
        new_agent_id=agent_id,
    ))


@router.get("/agents/{agent_id:path}", response_class=HTMLResponse)
async def agent_detail_page(request: Request, agent_id: str):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_agent, get_config
    from mcp_proxy.config import get_settings

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Fetch recent audit entries for this agent
    from sqlalchemy import text

    from mcp_proxy.db import get_db
    async with get_db() as db:
        result = await db.execute(
            text("SELECT * FROM audit_log WHERE agent_id = :agent_id ORDER BY timestamp DESC LIMIT 20"),
            {"agent_id": agent_id},
        )
        audit_entries = [dict(row) for row in result.mappings().all()]

    # Extra context for integration snippets
    settings = get_settings()
    proxy_url = settings.proxy_public_url or f"http://localhost:{settings.port}"
    broker_url = await get_config("broker_url") or ""
    org_id = await get_config("org_id") or settings.org_id
    agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id

    return templates.TemplateResponse("agent_detail.html", _ctx(
        request, session,
        active="agents",
        agent=agent,
        audit_entries=audit_entries,
        proxy_url=proxy_url,
        broker_url=broker_url,
        org_id=org_id,
        agent_name=agent_name,
    ))


@router.get("/agents/{agent_id:path}/env-download")
async def agent_env_download(request: Request, agent_id: str):
    """Download .env file with agent configuration."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_agent, get_config
    from mcp_proxy.config import get_settings

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    settings = get_settings()
    proxy_url = settings.proxy_public_url or f"http://localhost:{settings.port}"
    broker_url = await get_config("broker_url") or ""
    org_id = await get_config("org_id") or settings.org_id

    agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id

    env_content = f"""# Cullis Agent Configuration — {agent_id}
# Generated from MCP Proxy dashboard
# ADR-014: the agent authenticates by presenting its TLS client cert
# at the handshake. Mount cert.pem + key.pem from the identity bundle.
CULLIS_PROXY_URL={proxy_url}
CULLIS_AGENT_ID={agent_id}
CULLIS_ORG_ID={org_id}
CULLIS_BROKER_URL={broker_url}
"""

    return Response(
        content=env_content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="{agent_name}.env"'
        },
    )


_VALID_REACH = {"intra", "cross", "both"}


@router.post("/agents/{agent_id:path}/reach")
async def agent_set_reach(request: Request, agent_id: str):
    """Set ``internal_agents.reach`` from the dashboard.

    Migration 0017 introduced three states:

    * ``intra``  — same-org chat only, NOT published to the Court
    * ``cross``  — other-org chat only, published to the Court
    * ``both``   — intra + cross, published

    The legacy ``federated`` boolean is kept in sync so the publisher
    (ADR-010 Phase 3) still finds the right rows to PUT / revoke; it is
    now derived from ``reach`` instead of being the primary knob.
    ``federation_revision`` is bumped on every mutation so the publisher
    picks up the change on its next tick.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    new_reach = (form.get("reach") or "").strip().lower()
    if new_reach not in _VALID_REACH:
        raise HTTPException(
            status_code=400,
            detail=f"reach must be one of {sorted(_VALID_REACH)}",
        )

    from mcp_proxy.db import get_agent, get_db, log_audit
    from sqlalchemy import text as _text

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    new_federated = new_reach != "intra"
    async with get_db() as conn:
        await conn.execute(
            _text(
                """
                UPDATE internal_agents
                   SET reach = :reach,
                       federated = :fed,
                       federation_revision = federation_revision + 1
                 WHERE agent_id = :aid
                """
            ),
            {"reach": new_reach, "fed": bool(new_federated), "aid": agent_id},
        )

    await log_audit(
        agent_id=agent_id,
        action="agent.reach_set",
        status="success",
        detail=f"source=dashboard reach={new_reach} federated={new_federated}",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)


@router.post("/agents/{agent_id:path}/deactivate")
async def agent_deactivate(request: Request, agent_id: str):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import deactivate_agent, log_audit

    found = await deactivate_agent(agent_id)
    if not found:
        raise HTTPException(status_code=404, detail="Agent not found")

    await log_audit(
        agent_id=agent_id,
        action="agent.deactivate",
        status="success",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)


@router.post("/agents/{agent_id:path}/delete")
async def agent_delete(request: Request, agent_id: str):
    """Permanently delete an agent and all associated data."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    intercept = await maybe_intercept_for_approval(
        session=session,
        action_type=ACTION_AGENTS_DELETE,
        payload={"agent_id": agent_id},
        request=request,
    )
    if intercept is not None:
        return intercept

    from sqlalchemy import text

    from mcp_proxy.db import get_agent, get_db, log_audit

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Delete from local DB
    async with get_db() as db:
        await db.execute(
            text("DELETE FROM internal_agents WHERE agent_id = :agent_id"),
            {"agent_id": agent_id},
        )
        # Also remove stored key from proxy_config if present
        await db.execute(
            text("DELETE FROM proxy_config WHERE key = :key"),
            {"key": f"agent_key:{agent_id}"},
        )

    # ADR-010 Phase 6a-4 — the ``DELETE /v1/registry/agents/{id}`` hop is
    # gone. ``db_deactivate_agent`` bumps ``federation_revision`` for
    # federated rows, and the publisher carries the revocation to the
    # Court via ``/v1/federation/publish-agent`` on its next tick.

    await log_audit(
        agent_id=agent_id,
        action="agent.delete",
        status="success",
        detail="Agent permanently deleted",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)

