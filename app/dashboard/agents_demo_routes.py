"""Court dashboard — Agents list + ADR-020 principal-type demo views.

Sprint 2 / F-B-202 PR-10 of 10 — final extraction, closes F-B-202.

Bundles the read-only views that surface registry rows + the
ADR-020 principal-type sections (Users / Workloads / Resources /
Federation). The latter ship with hardcoded ``_demo_cast`` data
because the matching admin REST endpoints (``/v1/admin/users``,
``/v1/admin/workloads``) are still being wired by the backend
session; once they are live, swap the ``_demo_cast.*`` calls for
httpx calls to those routes and delete ``app/dashboard/_demo_cast.py``.

Mounted via ``router.include_router(agents_demo_routes.router)``.

Routes (5):

  GET  /dashboard/agents        agent registry list (with binding + ws)
  GET  /dashboard/users         ADR-020 user principals (demo)
  GET  /dashboard/workloads     ADR-020 workload principals (demo)
  GET  /dashboard/resources     ADR-020 resource principals (demo)
  GET  /dashboard/federation    federation peers + Court status (demo)

All read-only; no CSRF / sealed gate.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.broker.ws_manager import ws_manager
from app.dashboard import _demo_cast
from app.dashboard._helpers import _ctx
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login
from app.db.database import get_db
from app.registry.binding_store import BindingRecord
from app.registry.store import AgentRecord

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-agents-demo"])


@router.get("/agents", response_class=HTMLResponse)
async def agents_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(AgentRecord).order_by(AgentRecord.org_id, AgentRecord.agent_id)
    agents = (await db.execute(q)).scalars().all()

    binding_statuses = {}
    binding_q = select(BindingRecord.agent_id, BindingRecord.status).order_by(BindingRecord.id.desc())
    for row in (await db.execute(binding_q)).all():
        if row[0] not in binding_statuses:
            binding_statuses[row[0]] = row[1]

    agent_list = []
    for agent in agents:
        extras = _demo_cast.agent_extras(agent.agent_id)
        agent_list.append({
            "agent_id": agent.agent_id,
            "org_id": agent.org_id,
            "display_name": agent.display_name,
            "is_active": agent.is_active,
            "capabilities": agent.capabilities,
            "binding_status": binding_statuses.get(agent.agent_id),
            "ws_connected": ws_manager.is_connected(agent.agent_id),
            "cert_thumbprint": agent.cert_thumbprint,
            "enrollment_method": extras.get("enrollment_method"),
            "automation_type": extras.get("automation_type"),
        })

    return templates.TemplateResponse("agents.html",
        _ctx(request, session, active="agents", agents=agent_list)
    )


@router.get("/users", response_class=HTMLResponse)
async def users_list(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return templates.TemplateResponse("users.html", _ctx(
        request, session, active="users",
        users=_demo_cast.users_cast(),
        endpoint_ready=False,
    ))


@router.get("/workloads", response_class=HTMLResponse)
async def workloads_list(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return templates.TemplateResponse("workloads.html", _ctx(
        request, session, active="workloads",
        workloads=_demo_cast.workloads_cast(),
        endpoint_ready=False,
    ))


@router.get("/resources", response_class=HTMLResponse)
async def resources_list(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return templates.TemplateResponse("resources.html", _ctx(
        request, session, active="resources",
        resources=_demo_cast.resources_cast(),
    ))


@router.get("/federation", response_class=HTMLResponse)
async def federation_view(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return templates.TemplateResponse("federation.html", _ctx(
        request, session, active="federation",
        peers=_demo_cast.peers_cast(),
        court_status="Online",
        court_endpoint="https://court.cullis.test",
        court_audit_status="Healthy",
        court_last_anchor="active",
        court_last_anchor_iso=None,
    ))
