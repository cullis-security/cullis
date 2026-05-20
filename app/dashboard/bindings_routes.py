"""Court dashboard — Bindings sub-router.

Sprint 2 / F-B-202 PR-8 of 10. Extracts the cross-org binding registry
surface (section 26 of router.py).

Mounted via ``router.include_router(bindings_routes.router)``.

Routes (4):

  GET  /dashboard/bindings                       list (org × agent grant table)
  POST /dashboard/bindings/{id}/approve          approve pending binding
  POST /dashboard/bindings/{id}/revoke           revoke + close sessions + drop ws
  POST /dashboard/bindings/{id}/scope            edit scope (subset of agent caps)

A binding is the per-org authorization to let an external agent call into
this org. Three knobs the network admin needs at a glance:
  * status: pending / approved / revoked (lifecycle)
  * scope:  subset of the agent's declared capabilities that this org
            actually concedes — can be tighter than what the agent offers
  * org_id ↔ agent_id pair: bindings are directional, so A↔B requires two
            separate rows; revoking one keeps the other live, which is
            how an operator pins one-way traffic

All state-changing routes verify CSRF. Revoke mirrors the API path side
effects (close active sessions + drop ws) so the dashboard and API stay
behaviour-equivalent.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.dashboard._helpers import _ctx
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login, verify_csrf
from app.db.audit import log_event
from app.db.database import get_db
from app.registry.binding_store import (
    approve_binding, get_binding, list_all_bindings, revoke_binding,
    update_binding_scope,
)

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-bindings"])


@router.get("/bindings", response_class=HTMLResponse)
async def bindings_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    status_filter: str | None = None,
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    bindings = await list_all_bindings(db, status_filter=status_filter)

    # Hydrate each row with the underlying agent's capabilities so the
    # scope editor can render a multi-select with the legal options.
    from app.registry.store import get_agent_by_id
    enriched = []
    for b in bindings:
        agent = await get_agent_by_id(db, b.agent_id)
        enriched.append({
            "id": b.id,
            "org_id": b.org_id,
            "agent_id": b.agent_id,
            "status": b.status,
            "scope": b.scope,
            "approved_by": b.approved_by,
            "approved_at": b.approved_at,
            "created_at": b.created_at,
            "agent_capabilities": list(agent.capabilities) if agent else [],
            "agent_org_id": agent.org_id if agent else None,
        })

    counts = {
        "pending":  sum(1 for b in bindings if b.status == "pending"),
        "approved": sum(1 for b in bindings if b.status == "approved"),
        "revoked":  sum(1 for b in bindings if b.status == "revoked"),
    }

    return templates.TemplateResponse(
        "bindings.html",
        _ctx(
            request, session, active="bindings",
            bindings=enriched,
            counts=counts,
            current_filter=status_filter or "",
        ),
    )


@router.post("/bindings/{binding_id}/approve", response_class=HTMLResponse)
async def bindings_approve(
    request: Request, binding_id: int, db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    binding = await get_binding(db, binding_id)
    if not binding:
        raise HTTPException(status_code=404, detail="Binding not found")

    approved = await approve_binding(
        db, binding_id, approved_by="dashboard-network-admin",
    )
    if approved is None:
        return RedirectResponse(url="/dashboard/bindings", status_code=303)

    await log_event(
        db, "binding.approved", "ok",
        agent_id=binding.agent_id, org_id=binding.org_id,
        details={"binding_id": binding_id, "source": "dashboard"},
    )
    return RedirectResponse(url="/dashboard/bindings", status_code=303)


@router.post("/bindings/{binding_id}/revoke", response_class=HTMLResponse)
async def bindings_revoke(
    request: Request, binding_id: int, db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    binding = await get_binding(db, binding_id)
    if not binding:
        raise HTTPException(status_code=404, detail="Binding not found")

    revoked = await revoke_binding(db, binding_id)
    if revoked is None:
        return RedirectResponse(url="/dashboard/bindings", status_code=303)

    # Mirror the API path side effects: close active sessions + drop ws.
    from app.broker.session import get_session_store
    from app.broker.persistence import save_session
    from app.broker.ws_manager import ws_manager

    store = get_session_store()
    closed = store.close_all_for_agent(revoked.agent_id)
    for s in closed:
        await save_session(db, s)
    if ws_manager.is_connected(revoked.agent_id):
        await ws_manager.disconnect(revoked.agent_id)

    await log_event(
        db, "binding.revoked", "ok",
        agent_id=revoked.agent_id, org_id=revoked.org_id,
        details={
            "binding_id": binding_id, "source": "dashboard",
            "sessions_closed": len(closed),
        },
    )
    return RedirectResponse(url="/dashboard/bindings", status_code=303)


@router.post("/bindings/{binding_id}/scope", response_class=HTMLResponse)
async def bindings_update_scope(
    request: Request, binding_id: int, db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    binding = await get_binding(db, binding_id)
    if not binding:
        raise HTTPException(status_code=404, detail="Binding not found")

    form = await request.form()
    raw_scope = form.getlist("scope")
    new_scope = [s.strip() for s in raw_scope if s.strip()]

    # Subset check against the agent's declared capabilities — same gate
    # the API enforces on POST /v1/registry/bindings.
    from app.registry.store import get_agent_by_id
    agent = await get_agent_by_id(db, binding.agent_id)
    if agent is None:
        raise HTTPException(
            status_code=404,
            detail=f"Agent {binding.agent_id} not found — cannot validate scope",
        )
    agent_caps = set(agent.capabilities)
    invalid = [s for s in new_scope if s not in agent_caps]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Scope {invalid} not in agent capabilities: "
                f"{sorted(agent_caps)}"
            ),
        )

    await update_binding_scope(db, binding_id, new_scope)
    await log_event(
        db, "binding.scope_updated", "ok",
        agent_id=binding.agent_id, org_id=binding.org_id,
        details={
            "binding_id": binding_id,
            "old_scope": binding.scope,
            "new_scope": new_scope,
            "source": "dashboard",
        },
    )
    return RedirectResponse(url="/dashboard/bindings", status_code=303)
