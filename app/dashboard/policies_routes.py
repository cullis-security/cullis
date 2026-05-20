"""Court dashboard — Policies sub-router.

Sprint 2 / F-B-202 PR-8 of 10. Extracts the session-policy CRUD surface
(section 25 of router.py).

Mounted via ``router.include_router(policies_routes.router)``.

Routes (4):

  GET  /dashboard/policies                    list session policies (table)
  GET  /dashboard/policies/create             create form
  POST /dashboard/policies/create             submit new policy
  POST /dashboard/policies/{policy_id}/deactivate
                                              flip is_active=False

State-changing routes verify CSRF. Org-tenants can only mutate policies
for their own org (admin-only is the default after the
network-admin-only refactor, ADR-001 — the per-org check stays as
defence-in-depth in case the role gate ever loosens).
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.dashboard._helpers import _ctx
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login, verify_csrf
from app.db.audit import log_event
from app.db.database import get_db
from app.policy.store import (
    PolicyRecord, create_policy, deactivate_policy, get_policy,
)
from app.registry.org_store import OrganizationRecord

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-policies"])


@router.get("/policies", response_class=HTMLResponse)
async def policies_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    result = await db.execute(
        select(PolicyRecord)
        .where(PolicyRecord.policy_type == "session")
        .order_by(PolicyRecord.org_id, PolicyRecord.policy_id)
    )
    records = result.scalars().all()

    policy_list = []
    for r in records:
        conds = r.rules.get("conditions", {})
        policy_list.append({
            "policy_id": r.policy_id,
            "org_id": r.org_id,
            "target_orgs": conds.get("target_org_id", []),
            "capabilities": conds.get("capabilities", []),
            "effect": r.rules.get("effect", "allow"),
            "is_active": r.is_active,
        })

    return templates.TemplateResponse("policies.html",
        _ctx(request, session, active="policies", policies=policy_list))


@router.get("/policies/create", response_class=HTMLResponse)
async def policy_create_form(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    orgs = (await db.execute(
        select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
    )).scalars().all()

    return templates.TemplateResponse("policy_create.html",
        _ctx(request, session, active="policies", form={}, orgs=orgs,
             error=None, success=None))


@router.post("/policies/create", response_class=HTMLResponse)
async def policy_create_submit(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/policies", status_code=303)

    form_data = await request.form()
    org_id       = form_data.get("org_id", "").strip()
    target_org   = form_data.get("target_org_id", "").strip()
    caps_raw     = form_data.get("capabilities", "").strip()
    effect       = form_data.get("effect", "allow").strip()

    form = {"org_id": org_id, "target_org_id": target_org, "capabilities": caps_raw, "effect": effect}

    orgs = (await db.execute(
        select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
    )).scalars().all()

    # Org user can only create policies for their own org
    if not session.is_admin and org_id != session.org_id:
        return templates.TemplateResponse("policy_create.html",
            _ctx(request, session, active="policies", form=form, orgs=orgs,
                 error="You can only create policies for your own organization.", success=None))

    if not org_id or not target_org:
        return templates.TemplateResponse("policy_create.html",
            _ctx(request, session, active="policies", form=form, orgs=orgs,
                 error="Organization and target organization are required.", success=None))

    if org_id == target_org:
        return templates.TemplateResponse("policy_create.html",
            _ctx(request, session, active="policies", form=form, orgs=orgs,
                 error="Organization and target must be different.", success=None))

    caps = [c.strip() for c in caps_raw.split(",") if c.strip()] if caps_raw else []

    policy_id = f"{org_id}::session-{target_org}-v1"
    conditions: dict = {"target_org_id": [target_org]}
    if caps:
        conditions["capabilities"] = caps

    existing = await get_policy(db, policy_id)
    if existing:
        return templates.TemplateResponse("policy_create.html",
            _ctx(request, session, active="policies", form=form, orgs=orgs,
                 error=f"Policy '{policy_id}' already exists.", success=None))

    await create_policy(db, policy_id, org_id, "session", {"effect": effect, "conditions": conditions})
    await log_event(db, "policy.created", "ok", org_id=org_id,
                    details={"policy_id": policy_id, "target_org": target_org, "source": "dashboard"})

    return templates.TemplateResponse("policy_create.html",
        _ctx(request, session, active="policies", form={}, orgs=orgs, error=None,
             success=f"Policy '{policy_id}' created. {org_id} → {target_org} [{effect}]"))


@router.post("/policies/{policy_id:path}/deactivate", response_class=HTMLResponse)
async def policy_deactivate(request: Request, policy_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/policies", status_code=303)

    record = await get_policy(db, policy_id)
    if record:
        if not session.is_admin and record.org_id != session.org_id:
            return RedirectResponse(url="/dashboard/policies", status_code=303)
        await deactivate_policy(db, policy_id)
        await log_event(db, "policy.deactivated", "ok", org_id=record.org_id,
                        details={"policy_id": policy_id, "source": "dashboard"})

    return RedirectResponse(url="/dashboard/policies", status_code=303)
