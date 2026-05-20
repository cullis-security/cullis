"""
Dashboard — network-admin console for the broker.

Single role: ``admin`` (network operator). All views are admin-only —
org-tenant login was removed in the network-admin-only refactor (see
ADR-001); tenants now administer their own org from the per-org proxy.

Authentication via signed cookie set at /dashboard/login. Login can be
either:
  - password (default; first-boot flow picks an admin password)
  - OIDC federation (optional, via ADMIN_OIDC_* settings)
"""
import asyncio
import io
import re
import json as _json
import pathlib
import zipfile
import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.dashboard.session import (
    get_session, set_session, clear_session, require_login, verify_csrf,
    add_reauth_scope, DashboardSession, REAUTH_TTL_SECONDS,
)
# F-B-202 PR-1: pure helpers extracted to a sibling module so the
# upcoming per-feature sub-routers can import them without dragging
# the 3000-LOC router.py with them.
from app.dashboard._helpers import (
    _safe_redirect,
    _ctx,
    _SEALED_DETAIL,
    _is_sealed,
    _require_sealed_reauth,
    _sealed_mutation_details,
    _ID_PATTERN,
    _validate_id,
    _validate_webhook_url,
    _build_audit_event_dict,
    _count_chip,
    _broker_url_from_request,
    _generate_agent_cert,
)
from app.dashboard._template_env import build_templates

from app.db.database import get_db
from app.db.audit import AuditLog, log_event
from app.registry.store import AgentRecord, register_agent, rotate_agent_cert
from app.registry.org_store import (
    OrganizationRecord, register_org, get_org_by_id,
    update_org_ca_cert, set_org_status, set_org_sealed,
)
from app.registry.binding_store import (
    BindingRecord, create_binding, approve_binding, revoke_binding,
    get_binding_by_org_agent, get_binding, list_all_bindings, update_binding_scope,
)
from app.policy.store import PolicyRecord, create_policy, get_policy, deactivate_policy
from app.broker.db_models import SessionRecord, SessionMessageRecord, RfqRecord, RfqResponseRecord
from app.broker.ws_manager import ws_manager
from app.auth.transaction_token import create_transaction_token, compute_payload_hash
from app.dashboard import _demo_cast

import logging
_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
# F-B-202 PR-1: build_templates threads every dashboard sub-router
# through one Jinja2 env factory so cross-cutting globals (today: none;
# future: license gates / feature flags) land in one place.
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# F-B-202 PR-2: include the auth_routes sub-router (login / logout /
# first-boot setup / OIDC). Routes inside auth_routes.py declare
# paths relative to /dashboard so the outer router's prefix is
# inherited via include_router (no double-prefix).
from app.dashboard import auth_routes as _auth_routes  # noqa: E402
router.include_router(_auth_routes.router)

# F-B-202 PR-3: include the admin_settings sub-router (change-password
# + policy-toggle). Same pattern as PR-2.
from app.dashboard import admin_settings_routes as _admin_settings_routes  # noqa: E402
router.include_router(_admin_settings_routes.router)

# F-B-202 PR-4: include badges (HTMX nav auto-refresh fragments) and
# SSE (real-time dashboard updates). Overview (``GET /dashboard``)
# stays inline in this file because FastAPI rejects sub-router routes
# with an empty path; extracting it would change the URL to
# ``/dashboard/`` and break linkage.
from app.dashboard import badges_routes as _badges_routes  # noqa: E402
from app.dashboard import sse_routes as _sse_routes  # noqa: E402
router.include_router(_badges_routes.router)
router.include_router(_sse_routes.router)

# F-B-202 PR-5: include the orgs sub-router (list + invites + approve
# / reject / suspend / delete / unlock-CA / upload-CA, 11 routes).
from app.dashboard import orgs_routes as _orgs_routes  # noqa: E402
router.include_router(_orgs_routes.router)

# F-B-202 PR-6: include org_onboard (generate-ca + form + submit) and
# org_seal (unseal-reauth + manual seal/unseal — audit F-B-2 gate).
from app.dashboard import org_onboard_routes as _org_onboard_routes  # noqa: E402
from app.dashboard import org_seal_routes as _org_seal_routes  # noqa: E402
router.include_router(_org_onboard_routes.router)
router.include_router(_org_seal_routes.router)

# F-B-202 PR-7: include agents_lifecycle (register / manage / delete)
# and agents_credentials (detail / upload-cert / credentials / bundle
# / rotate-cert). 12 routes total — biggest extract of Sprint 2.
from app.dashboard import agents_lifecycle_routes as _agents_lifecycle_routes  # noqa: E402
from app.dashboard import agents_credentials_routes as _agents_credentials_routes  # noqa: E402
router.include_router(_agents_lifecycle_routes.router)
router.include_router(_agents_credentials_routes.router)


# ─────────────────────────────────────────────────────────────────────────────
# Login / Logout
# ─────────────────────────────────────────────────────────────────────────────

# Auth routes (login / logout / first-boot setup / OIDC) extracted to
# ``app/dashboard/auth_routes.py`` since F-B-202 PR-2. The sub-router
# is wired via ``router.include_router(_auth_routes.router)`` near
# the router declaration at the top of this file.
#
# MIN_ADMIN_PASSWORD_LENGTH (was used by /setup) now lives in
# auth_routes.py. Future PR-3 admin_settings_routes will share or
# duplicate the constant when the change-password endpoint moves out
# of router.py.


# Admin Settings (change-password) routes moved to
# ``app/dashboard/admin_settings_routes.py`` since F-B-202 PR-3.
#
# Org-tenant self-service settings (CA upload, CA generate, OIDC role mapping)
# were removed in the network-admin-only refactor (ADR-001). Admin still
# manages per-org CA via /dashboard/orgs/{org_id}/upload-ca.




# ─────────────────────────────────────────────────────────────────────────────
# OIDC federation login
# ─────────────────────────────────────────────────────────────────────────────

# OIDC routes (/dashboard/oidc/start, /dashboard/oidc/callback) moved
# to auth_routes.py since F-B-202 PR-2.


# Helpers (_ctx, sealed-org guard, validators, ID pattern) live in
# ``app/dashboard/_helpers.py`` since F-B-202 PR-1. Endpoint-specific
# size limits below stay here for now; they migrate to per-feature
# sub-routers as the modularization sprint progresses.
_DISPLAY_NAME_MAX = 256
_CAPABILITY_MAX_LEN = 64
_CAPABILITY_MAX_COUNT = 50


# Policy enforcement toggle moved to admin_settings_routes.py since
# F-B-202 PR-3 (co-located with the rest of the admin-settings surface).


# ─────────────────────────────────────────────────────────────────────────────
# Overview
# ─────────────────────────────────────────────────────────────────────────────
#
# F-B-202 PR-4 footnote: this is the one route in the dashboard that
# can't move to a sub-router because FastAPI rejects sub-router routes
# with an empty path (the bare ``/dashboard`` landing page). It stays
# inline; the rest of PR-4 (badges + sse) is extracted.

@router.get("", response_class=HTMLResponse)
async def overview(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    # Note: the /setup-before-login invariant is enforced at /dashboard/login
    # now — any logged-in session implies user_set=true, so no redirect here.
    # Network-admin console: all stats are network-wide.

    orgs_total = (await db.execute(select(func.count(OrganizationRecord.org_id)))).scalar() or 0
    orgs_active = (await db.execute(
        select(func.count(OrganizationRecord.org_id)).where(OrganizationRecord.status == "active")
    )).scalar() or 0
    orgs_pending = (await db.execute(
        select(func.count(OrganizationRecord.org_id)).where(OrganizationRecord.status == "pending")
    )).scalar() or 0

    agents_total = (await db.execute(select(func.count(AgentRecord.agent_id)))).scalar() or 0
    agents_active = (await db.execute(
        select(func.count(AgentRecord.agent_id)).where(AgentRecord.is_active.is_(True))
    )).scalar() or 0

    sessions_active = (await db.execute(
        select(func.count(SessionRecord.session_id)).where(SessionRecord.status == "active")
    )).scalar() or 0

    audit_events = (await db.execute(select(func.count(AuditLog.id)))).scalar() or 0

    # Recent audit events (network-wide)
    recent_events = (await db.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(15)
    )).scalars().all()

    # Federation-health proxy metric: audit events in the last hour is a
    # cheap signal of network traffic that doesn't need a new metrics store.
    import datetime as _dt_stats
    _one_hour_ago = _dt_stats.datetime.now(_dt_stats.timezone.utc) - _dt_stats.timedelta(hours=1)
    events_last_hour = (await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= _one_hour_ago)
    )).scalar() or 0

    # Users count is hardcoded from the insurance demo cast until
    # /v1/admin/users lands (backend session). See _demo_cast.py.
    users_total = len(_demo_cast.users_cast())

    stats = {
        "orgs": orgs_total, "orgs_active": orgs_active, "orgs_pending": orgs_pending,
        "users": users_total,
        "agents": agents_total, "agents_active": agents_active,
        "sessions_active": sessions_active,
        "audit_events": audit_events,
        "events_last_hour": events_last_hour,
    }

    from app.config import is_policy_enforced
    return templates.TemplateResponse("overview.html",
        _ctx(request, session, active="overview", stats=stats, recent_events=recent_events,
             policy_enforced=is_policy_enforced())
    )


# Org list + invite endpoints moved to ``app/dashboard/orgs_routes.py``
# since F-B-202 PR-5.


# ─────────────────────────────────────────────────────────────────────────────
# Agents
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Users / Workloads / Resources / Federation (ADR-020 principal-type sections)
#
# Phase 1 of the SPA rework ships these views with hardcoded demo data
# from imp/insurance-demo-spec.md. The matching admin REST endpoints
# (/v1/admin/users, /v1/admin/workloads) are owned by the backend
# session and land separately. Once they are live, swap the
# ``_demo_cast.*`` calls below for httpx calls to those routes and
# delete app/dashboard/_demo_cast.py.
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Sessions
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/sessions", response_class=HTMLResponse)
async def sessions_list(
    request: Request,
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(SessionRecord).order_by(SessionRecord.created_at.desc())
    if status:
        q = q.where(SessionRecord.status == status)
    q = q.limit(100)

    result = await db.execute(q)
    sessions = result.scalars().all()

    # Count messages per session
    msg_counts = {}
    if sessions:
        session_ids = [s.session_id for s in sessions]
        count_q = (
            select(SessionMessageRecord.session_id, func.count(SessionMessageRecord.id))
            .where(SessionMessageRecord.session_id.in_(session_ids))
            .group_by(SessionMessageRecord.session_id)
        )
        for row in (await db.execute(count_q)).all():
            msg_counts[row[0]] = row[1]

    session_list = []
    for s in sessions:
        session_list.append({
            "session_id": s.session_id,
            "initiator_agent_id": s.initiator_agent_id,
            "initiator_org_id": s.initiator_org_id,
            "target_agent_id": s.target_agent_id,
            "target_org_id": s.target_org_id,
            "status": s.status,
            "message_count": msg_counts.get(s.session_id, 0),
            "created_at": s.created_at,
        })

    return templates.TemplateResponse("sessions.html",
        _ctx(request, session, active="sessions", sessions=session_list, status_filter=status)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────────────────────────────

_AUDIT_LIMIT = 200

# ``_build_audit_event_dict`` lives in ``app.dashboard._helpers`` since
# F-B-202 PR-1.


@router.get("/audit", response_class=HTMLResponse)
async def audit_log(
    request: Request,
    q: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    query = select(AuditLog).order_by(AuditLog.id.desc())

    if q:
        q = q[:100]  # Limit search term length to prevent expensive LIKE queries
        # Escape LIKE wildcards in user input to prevent pattern abuse
        _escaped = q.replace("%", r"\%").replace("_", r"\_")
        pattern = f"%{_escaped}%"
        query = query.where(or_(
            AuditLog.event_type.ilike(pattern),
            AuditLog.agent_id.ilike(pattern),
            AuditLog.org_id.ilike(pattern),
            AuditLog.result.ilike(pattern),
            AuditLog.details.ilike(pattern),
        ))

    query = query.limit(_AUDIT_LIMIT)
    result = await db.execute(query)
    events = result.scalars().all()

    event_list = [_build_audit_event_dict(e) for e in events]

    return templates.TemplateResponse("audit.html",
        _ctx(request, session, active="audit", events=event_list, query=q or "", limit=_AUDIT_LIMIT)
    )


@router.post("/audit/verify", response_class=HTMLResponse)
async def verify_audit_chain(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin-only: verify the cryptographic integrity of the audit log chain."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from app.db.audit import verify_chain
    is_valid, total, broken_id = await verify_chain(db)

    verify_result = {"valid": is_valid, "total": total, "broken_id": broken_id}

    # Re-render audit page with verification result
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(_AUDIT_LIMIT)
    result = await db.execute(query)
    events = result.scalars().all()
    event_list = [_build_audit_event_dict(e) for e in events]

    return templates.TemplateResponse("audit.html",
        _ctx(request, session, active="audit", events=event_list, query="",
             limit=_AUDIT_LIMIT, verify_result=verify_result)
    )


# ─────────────────────────────────────────────────────────────────────────────
# RFQ Detail & Approval
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rfqs", response_class=HTMLResponse)
async def rfq_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(RfqRecord).order_by(RfqRecord.created_at.desc()).limit(100)
    rfqs = (await db.execute(q)).scalars().all()

    return templates.TemplateResponse("rfqs.html",
        _ctx(request, session, active="rfq", rfqs=rfqs)
    )


@router.get("/rfq/{rfq_id}", response_class=HTMLResponse)
async def rfq_detail(request: Request, rfq_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    rfq = (await db.execute(
        select(RfqRecord).where(RfqRecord.rfq_id == rfq_id)
    )).scalar_one_or_none()
    if not rfq:
        raise HTTPException(status_code=404, detail="RFQ not found")

    responses = (await db.execute(
        select(RfqResponseRecord).where(RfqResponseRecord.rfq_id == rfq_id)
    )).scalars().all()

    return templates.TemplateResponse("rfq_detail.html",
        _ctx(request, session, active="rfq", rfq=rfq, responses=responses,
             success=None, error=None)
    )


@router.post("/rfq/{rfq_id}/approve", response_class=HTMLResponse)
async def rfq_approve(request: Request, rfq_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    rfq = (await db.execute(
        select(RfqRecord).where(RfqRecord.rfq_id == rfq_id)
    )).scalar_one_or_none()
    if not rfq:
        raise HTTPException(status_code=404, detail="RFQ not found")

    form = await request.form()
    response_id = form.get("response_id")
    responder_agent_id = form.get("responder_agent_id", "")

    if not response_id:
        raise HTTPException(status_code=400, detail="Missing response_id")

    quote = (await db.execute(
        select(RfqResponseRecord).where(
            RfqResponseRecord.id == int(response_id),
            RfqResponseRecord.rfq_id == rfq_id,
        )
    )).scalar_one_or_none()
    if not quote:
        raise HTTPException(status_code=404, detail="Quote not found")

    payload_hash = compute_payload_hash(quote.payload)
    token_id, token_record = await create_transaction_token(
        db,
        agent_id=rfq.initiator_agent_id,
        org_id=rfq.initiator_org_id,
        txn_type="CREATE_ORDER",
        resource_id=rfq_id,
        payload_hash=payload_hash,
        approved_by="admin",
        rfq_id=rfq_id,
        target_agent_id=responder_agent_id,
    )

    rfq.status = "approved"
    await db.commit()

    try:
        await ws_manager.send_to_agent(rfq.initiator_agent_id, {
            "type": "transaction_token",
            "token_id": token_id,
            "rfq_id": rfq_id,
            "txn_type": "CREATE_ORDER",
            "target_agent_id": responder_agent_id,
            "payload_hash": payload_hash,
        })
    except Exception:
        _log.warning("Could not deliver transaction token to agent %s via WS",
                      rfq.initiator_agent_id)

    await log_event(db, "rfq.approved", "ok",
                    agent_id=rfq.initiator_agent_id, org_id=rfq.initiator_org_id,
                    details={"rfq_id": rfq_id, "approved_quote_id": response_id,
                             "responder_agent_id": responder_agent_id, "token_id": token_id})

    responses = (await db.execute(
        select(RfqResponseRecord).where(RfqResponseRecord.rfq_id == rfq_id)
    )).scalars().all()
    await db.refresh(rfq)

    return templates.TemplateResponse("rfq_detail.html",
        _ctx(request, session, active="rfq", rfq=rfq, responses=responses,
             success=f"Quote approved. Transaction token issued to agent {rfq.initiator_agent_id}.",
             error=None)
    )


# Badge endpoints moved to ``app/dashboard/badges_routes.py`` and the
# SSE endpoint moved to ``app/dashboard/sse_routes.py`` (F-B-202 PR-4).


# ═════════════════════════════════════════════════════════════════════════════
# OPERATIONS — forms and actions
# ═════════════════════════════════════════════════════════════════════════════


# Org onboard routes (generate-ca + form + submit) moved to
# ``app/dashboard/org_onboard_routes.py`` since F-B-202 PR-6.


# Org approve / reject / suspend / delete / unlock-ca endpoints
# moved to ``app/dashboard/orgs_routes.py`` since F-B-202 PR-5.


# Audit F-B-2 — unseal-reauth challenge + manual seal/unseal routes
# moved to ``app/dashboard/org_seal_routes.py`` since F-B-202 PR-6.


# Upload-CA endpoints moved to ``app/dashboard/orgs_routes.py`` since
# F-B-202 PR-5.


# Agent register / manage / delete routes moved to
# ``app/dashboard/agents_lifecycle_routes.py`` since F-B-202 PR-7.
# Agent detail / upload-cert / credentials / bundle / rotate-cert
# routes moved to ``app/dashboard/agents_credentials_routes.py`` since
# F-B-202 PR-7.



# ─────────────────────────────────────────────────────────────────────────────
# Policies
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Bindings — registry of approved org ↔ agent grants (cross-org)
#
# A binding is the per-org authorization to let an external agent call into
# this org. Three knobs the network admin needs at a glance:
#   • status: pending / approved / revoked (lifecycle)
#   • scope:  subset of the agent's declared capabilities that this org
#             actually concedes — can be tighter than what the agent offers
#   • org_id ↔ agent_id pair: bindings are directional, so A↔B requires two
#             separate rows; revoking one keeps the other live, which is
#             how an operator pins one-way traffic
# ─────────────────────────────────────────────────────────────────────────────

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
