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

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse
from sqlalchemy import select, func
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
    get_binding_by_org_agent,
)
from app.broker.db_models import SessionRecord
from app.broker.ws_manager import ws_manager
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

# F-B-202 PR-8: include policies (session policy CRUD) and bindings
# (cross-org grant registry). 8 routes total.
from app.dashboard import policies_routes as _policies_routes  # noqa: E402
from app.dashboard import bindings_routes as _bindings_routes  # noqa: E402
router.include_router(_policies_routes.router)
router.include_router(_bindings_routes.router)

# F-B-202 PR-9: include sessions (session list), audit (log table +
# chain verify) and rfq (list + detail + approve). 6 routes total.
from app.dashboard import sessions_routes as _sessions_routes  # noqa: E402
from app.dashboard import audit_routes as _audit_routes  # noqa: E402
from app.dashboard import rfq_routes as _rfq_routes  # noqa: E402
router.include_router(_sessions_routes.router)
router.include_router(_audit_routes.router)
router.include_router(_rfq_routes.router)

# F-B-202 PR-10 (final): include agents_demo (agents list + ADR-020
# principal-type demo views: users/workloads/resources/federation).
# 5 routes — closes F-B-202.
from app.dashboard import agents_demo_routes as _agents_demo_routes  # noqa: E402
router.include_router(_agents_demo_routes.router)


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


# Agents list (/dashboard/agents) and ADR-020 principal-type demo views
# (/dashboard/users, /workloads, /resources, /federation) moved to
# ``app/dashboard/agents_demo_routes.py`` since F-B-202 PR-10.


# Sessions list (/dashboard/sessions) moved to
# ``app/dashboard/sessions_routes.py`` since F-B-202 PR-9.
#
# Audit log (/dashboard/audit + /dashboard/audit/verify) moved to
# ``app/dashboard/audit_routes.py`` since F-B-202 PR-9.
#
# RFQ list / detail / approve (/dashboard/rfqs, /dashboard/rfq/{id},
# /dashboard/rfq/{id}/approve) moved to
# ``app/dashboard/rfq_routes.py`` since F-B-202 PR-9.


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



# Policy routes (/dashboard/policies + create + deactivate) moved to
# ``app/dashboard/policies_routes.py`` since F-B-202 PR-8.
#
# Binding routes (/dashboard/bindings + approve / revoke / scope) moved
# to ``app/dashboard/bindings_routes.py`` since F-B-202 PR-8.
