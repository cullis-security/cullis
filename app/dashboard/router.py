"""
Dashboard — role-based HTML views of the broker state.

Two roles:
  - admin:  sees all orgs, agents, sessions, audit. Can onboard orgs, approve/reject.
  - org:    sees only own agents, own sessions, own audit. Can register agents.

Authentication via signed cookie set at /dashboard/login.
"""
import re
import pathlib
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.dashboard.session import (
    get_session, set_session, clear_session, require_login, verify_csrf,
    DashboardSession,
)

from app.db.database import get_db
from app.db.audit import AuditLog, log_event
from app.registry.store import AgentRecord, register_agent, rotate_agent_cert, compute_cert_thumbprint
from app.registry.org_store import (
    OrganizationRecord, register_org, get_org_by_id,
    update_org_ca_cert, update_org_webhook, set_org_status, list_pending_orgs,
)
from app.registry.binding_store import (
    BindingRecord, create_binding, approve_binding, revoke_binding, get_binding_by_org_agent,
)
from app.policy.store import PolicyRecord, create_policy, get_policy, list_policies, deactivate_policy
from app.broker.db_models import SessionRecord, SessionMessageRecord
from app.broker.ws_manager import ws_manager

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# ─────────────────────────────────────────────────────────────────────────────
# Login / Logout
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    session = get_session(request)
    if session.logged_in:
        return RedirectResponse(url="/dashboard", status_code=303)
    from app.config import get_settings as _gs
    _s = _gs()
    admin_oidc_enabled = bool(_s.admin_oidc_issuer_url and _s.admin_oidc_client_id)
    return templates.TemplateResponse("login.html", {
        "request": request, "error": None, "admin_oidc_enabled": admin_oidc_enabled,
    })


@router.post("/login")
async def login_submit(request: Request, db: AsyncSession = Depends(get_db)):
    from app.rate_limit.limiter import rate_limiter
    client_ip = request.client.host if request.client else "unknown"
    await rate_limiter.check(client_ip, "dashboard.login")

    form = await request.form()
    login_type = form.get("login_type", "")

    if login_type == "admin":
        import hmac as _hmac
        from app.config import get_settings
        secret = form.get("admin_secret", "")
        if not _hmac.compare_digest(secret, get_settings().admin_secret):
            return templates.TemplateResponse("login.html", {
                "request": request, "error": "Invalid admin secret.",
            })
        response = RedirectResponse(url="/dashboard", status_code=303)
        set_session(response, role="admin")
        return response

    elif login_type == "org":
        org_id = form.get("org_id", "").strip()
        org_secret = form.get("org_secret", "")
        if not org_id or not org_secret:
            return templates.TemplateResponse("login.html", {
                "request": request, "error": "Organization ID and secret are required.",
            })
        from app.registry.org_store import verify_org_credentials
        org = await get_org_by_id(db, org_id)
        if not verify_org_credentials(org, org_secret):
            return templates.TemplateResponse("login.html", {
                "request": request, "error": "Invalid organization credentials.",
            })
        response = RedirectResponse(url="/dashboard", status_code=303)
        set_session(response, role="org", org_id=org_id)
        return response

    return templates.TemplateResponse("login.html", {
        "request": request, "error": "Invalid login type.",
    })


@router.post("/logout")
async def logout(request: Request):
    session = get_session(request)
    if session.logged_in:
        if not await verify_csrf(request, session):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
    response = RedirectResponse(url="/dashboard/login", status_code=303)
    clear_session(response)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# OIDC federation login
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/oidc/start")
async def oidc_start(
    request: Request,
    role: str = Query(...),
    org_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Initiate OIDC authorization code flow with PKCE."""
    from app.config import get_settings
    from app.dashboard.oidc import create_oidc_state, build_authorization_url, OidcError
    from app.dashboard.session import set_oidc_state

    settings = get_settings()
    if not settings.broker_public_url:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "OIDC requires BROKER_PUBLIC_URL to be configured.",
            "admin_oidc_enabled": False,
        })

    redirect_uri = settings.broker_public_url.rstrip("/") + "/dashboard/oidc/callback"

    if role == "org":
        if not org_id:
            return templates.TemplateResponse("login.html", {
                "request": request, "error": "Organization ID is required for SSO login.",
                "admin_oidc_enabled": False,
            })
        org = await get_org_by_id(db, org_id)
        if not org or not org.oidc_enabled:
            return templates.TemplateResponse("login.html", {
                "request": request, "error": f"Organization '{org_id}' does not have SSO configured.",
                "admin_oidc_enabled": False,
            })
        if org.status != "active":
            return templates.TemplateResponse("login.html", {
                "request": request, "error": f"Organization is '{org.status}', not active.",
                "admin_oidc_enabled": False,
            })
        issuer_url = org.oidc_issuer_url
        client_id = org.oidc_client_id
    elif role == "admin":
        if not settings.admin_oidc_issuer_url or not settings.admin_oidc_client_id:
            return templates.TemplateResponse("login.html", {
                "request": request, "error": "Admin SSO is not configured.",
                "admin_oidc_enabled": False,
            })
        issuer_url = settings.admin_oidc_issuer_url
        client_id = settings.admin_oidc_client_id
    else:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid SSO role.",
            "admin_oidc_enabled": False,
        })

    flow_state = create_oidc_state(role, org_id)
    try:
        auth_url = await build_authorization_url(issuer_url, client_id, redirect_uri, flow_state)
    except OidcError as e:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": f"SSO error: {e}",
            "admin_oidc_enabled": bool(settings.admin_oidc_issuer_url),
        })

    response = RedirectResponse(url=auth_url, status_code=303)
    set_oidc_state(response, flow_state.to_dict())
    return response


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Handle OIDC provider redirect after user authentication."""
    import hmac as _hmac
    from app.config import get_settings
    from app.dashboard.oidc import OidcFlowState, exchange_code_for_identity, OidcError
    from app.dashboard.session import get_oidc_state, clear_oidc_state
    from app.rate_limit.limiter import rate_limiter

    settings = get_settings()
    admin_oidc_enabled = bool(settings.admin_oidc_issuer_url and settings.admin_oidc_client_id)

    client_ip = request.client.host if request.client else "unknown"
    await rate_limiter.check(client_ip, "dashboard.login")

    def _login_error(msg: str):
        return templates.TemplateResponse("login.html", {
            "request": request, "error": msg, "admin_oidc_enabled": admin_oidc_enabled,
        })

    if error:
        return _login_error(f"SSO provider error: {error_description or error}")

    if not code or not state:
        return _login_error("Missing authorization code or state from SSO provider.")

    flow_data = get_oidc_state(request)
    if not flow_data:
        return _login_error("SSO session expired or invalid. Please try again.")

    if not _hmac.compare_digest(state, flow_data.get("state", "")):
        return _login_error("SSO state mismatch — possible CSRF attack.")

    flow_state = OidcFlowState.from_dict(flow_data)
    redirect_uri = settings.broker_public_url.rstrip("/") + "/dashboard/oidc/callback"

    # Determine OIDC config
    if flow_state.role == "org":
        org = await get_org_by_id(db, flow_state.org_id)
        if not org or not org.oidc_enabled:
            return _login_error("Organization SSO configuration not found.")
        issuer_url = org.oidc_issuer_url
        client_id = org.oidc_client_id
        from app.registry.org_store import get_org_oidc_secret
        client_secret = await get_org_oidc_secret(org)
    elif flow_state.role == "admin":
        issuer_url = settings.admin_oidc_issuer_url
        client_id = settings.admin_oidc_client_id
        client_secret = settings.admin_oidc_client_secret or None
    else:
        return _login_error("Invalid SSO role.")

    try:
        identity = await exchange_code_for_identity(
            issuer_url, client_id, client_secret, redirect_uri, code, flow_state
        )
    except OidcError as e:
        _log.warning("OIDC callback failed: %s", e)
        return _login_error(f"SSO authentication failed: {e}")

    # Create session
    response = RedirectResponse(url="/dashboard", status_code=303)
    clear_oidc_state(response)

    if flow_state.role == "admin":
        set_session(response, role="admin")
    else:
        set_session(response, role="org", org_id=flow_state.org_id)

    await log_event(db, "dashboard.oidc_login", "ok",
                    org_id=flow_state.org_id,
                    details={
                        "role": flow_state.role,
                        "sub": identity.sub,
                        "email": identity.email,
                        "issuer": identity.issuer,
                    })

    return response


# ─────────────────────────────────────────────────────────────────────────────
# Helper — require login on every page
# ─────────────────────────────────────────────────────────────────────────────

def _ctx(request: Request, session: DashboardSession, **kwargs) -> dict:
    """Build template context with session info and CSRF token."""
    from app.config import get_settings
    _s = get_settings()
    _parsed = urlparse(_s.otel_exporter_otlp_endpoint or "http://localhost:4317")
    _jaeger_host = _parsed.hostname or "localhost"
    _jaeger_scheme = _parsed.scheme or "http"
    jaeger_url = f"{_jaeger_scheme}://{_jaeger_host}:16686"
    return {"request": request, "session": session, "csrf_token": session.csrf_token,
            "jaeger_url": jaeger_url, **kwargs}


# Alphanumeric, hyphens, underscores, colons, dots — max 128 chars
_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:@\-]{0,127}$")
_DISPLAY_NAME_MAX = 256
_CAPABILITY_MAX_LEN = 64
_CAPABILITY_MAX_COUNT = 50


def _validate_id(value: str, field_name: str) -> str | None:
    """Return an error message if the ID is invalid, else None."""
    if not value:
        return None  # emptiness checked elsewhere
    if not _ID_PATTERN.match(value):
        return f"{field_name} must be alphanumeric (hyphens, underscores, colons, dots allowed), max 128 characters."
    return None


def _validate_webhook_url(url: str) -> str | None:
    """Return an error message if the webhook URL is invalid, else None."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        return "Webhook URL must use https:// or http:// scheme."
    if not parsed.hostname:
        return "Webhook URL must have a valid hostname."
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Overview
# ─────────────────────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def overview(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    org_filter = session.org_id  # None for admin = all

    # Stats — scoped by role
    if session.is_admin:
        orgs_total = (await db.execute(select(func.count(OrganizationRecord.org_id)))).scalar() or 0
        orgs_active = (await db.execute(
            select(func.count(OrganizationRecord.org_id)).where(OrganizationRecord.status == "active")
        )).scalar() or 0
    else:
        orgs_total = 1
        orgs_active = 1

    agents_q = select(func.count(AgentRecord.agent_id))
    agents_active_q = select(func.count(AgentRecord.agent_id)).where(AgentRecord.is_active == True)
    if org_filter:
        agents_q = agents_q.where(AgentRecord.org_id == org_filter)
        agents_active_q = agents_active_q.where(AgentRecord.org_id == org_filter)
    agents_total = (await db.execute(agents_q)).scalar() or 0
    agents_active = (await db.execute(agents_active_q)).scalar() or 0

    sessions_q = select(func.count(SessionRecord.session_id)).where(SessionRecord.status == "active")
    if org_filter:
        sessions_q = sessions_q.where(or_(
            SessionRecord.initiator_org_id == org_filter,
            SessionRecord.target_org_id == org_filter,
        ))
    sessions_active = (await db.execute(sessions_q)).scalar() or 0

    audit_q = select(func.count(AuditLog.id))
    if org_filter:
        audit_q = audit_q.where(AuditLog.org_id == org_filter)
    audit_events = (await db.execute(audit_q)).scalar() or 0

    # Recent events
    recent_q = select(AuditLog).order_by(AuditLog.id.desc()).limit(15)
    if org_filter:
        recent_q = recent_q.where(AuditLog.org_id == org_filter)
    recent_events = (await db.execute(recent_q)).scalars().all()

    stats = {
        "orgs": orgs_total, "orgs_active": orgs_active,
        "agents": agents_total, "agents_active": agents_active,
        "sessions_active": sessions_active,
        "audit_events": audit_events,
    }

    return templates.TemplateResponse("overview.html",
        _ctx(request, session, active="overview", stats=stats, recent_events=recent_events)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Organizations
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/orgs", response_class=HTMLResponse)
async def orgs_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    result = await db.execute(select(OrganizationRecord).order_by(OrganizationRecord.org_id))
    orgs = result.scalars().all()

    agent_counts = {}
    count_q = select(AgentRecord.org_id, func.count(AgentRecord.agent_id)).group_by(AgentRecord.org_id)
    for row in (await db.execute(count_q)).all():
        agent_counts[row[0]] = row[1]

    org_list = []
    for org in orgs:
        org_list.append({
            "org_id": org.org_id,
            "display_name": org.display_name,
            "status": org.status,
            "webhook_url": org.webhook_url,
            "ca_certificate": org.ca_certificate,
            "oidc_enabled": org.oidc_enabled,
            "agent_count": agent_counts.get(org.org_id, 0),
        })

    return templates.TemplateResponse("orgs.html",
        _ctx(request, session, active="orgs", orgs=org_list)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Agents
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/agents", response_class=HTMLResponse)
async def agents_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(AgentRecord).order_by(AgentRecord.org_id, AgentRecord.agent_id)
    if not session.is_admin:
        q = q.where(AgentRecord.org_id == session.org_id)
    agents = (await db.execute(q)).scalars().all()

    binding_statuses = {}
    binding_q = select(BindingRecord.agent_id, BindingRecord.status).order_by(BindingRecord.id.desc())
    for row in (await db.execute(binding_q)).all():
        if row[0] not in binding_statuses:
            binding_statuses[row[0]] = row[1]

    agent_list = []
    for agent in agents:
        agent_list.append({
            "agent_id": agent.agent_id,
            "org_id": agent.org_id,
            "display_name": agent.display_name,
            "is_active": agent.is_active,
            "capabilities": agent.capabilities,
            "binding_status": binding_statuses.get(agent.agent_id),
            "ws_connected": ws_manager.is_connected(agent.agent_id),
            "cert_thumbprint": agent.cert_thumbprint,
        })

    return templates.TemplateResponse("agents.html",
        _ctx(request, session, active="agents", agents=agent_list)
    )


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
    if not session.is_admin:
        q = q.where(or_(
            SessionRecord.initiator_org_id == session.org_id,
            SessionRecord.target_org_id == session.org_id,
        ))
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
    if not session.is_admin:
        query = query.where(AuditLog.org_id == session.org_id)

    if q:
        q = q[:100]  # Limit search term length to prevent expensive LIKE queries
        pattern = f"%{q}%"
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

    # Use timestamp field (named 'timestamp' in the model)
    event_list = []
    for e in events:
        event_list.append({
            "event_type": e.event_type,
            "result": e.result,
            "agent_id": e.agent_id,
            "org_id": e.org_id,
            "details": e.details,
            "created_at": e.timestamp,
            "entry_hash": e.entry_hash,
        })

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
    event_list = [{
        "event_type": e.event_type, "result": e.result,
        "agent_id": e.agent_id, "org_id": e.org_id,
        "details": e.details, "created_at": e.timestamp,
        "entry_hash": e.entry_hash,
    } for e in events]

    return templates.TemplateResponse("audit.html",
        _ctx(request, session, active="audit", events=event_list, query="",
             limit=_AUDIT_LIMIT, verify_result=verify_result)
    )


# ─────────────────────────────────────────────────────────────────────────────
# HTMX badge fragments — auto-refreshed every 10s
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/badge/pending-orgs", response_class=HTMLResponse)
async def badge_pending_orgs(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    if not session.logged_in or not session.is_admin:
        return ""
    count = (await db.execute(
        select(func.count(OrganizationRecord.org_id))
        .where(OrganizationRecord.status == "pending")
    )).scalar() or 0
    if count > 0:
        return f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-yellow-500/20 text-yellow-400">{count}</span>'
    return ""


@router.get("/badge/pending-sessions", response_class=HTMLResponse)
async def badge_pending_sessions(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    if not session.logged_in:
        return ""
    count_q = select(func.count(SessionRecord.session_id)).where(SessionRecord.status == "pending")
    if not session.is_admin:
        count_q = count_q.where(or_(
            SessionRecord.initiator_org_id == session.org_id,
            SessionRecord.target_org_id == session.org_id,
        ))
    count = (await db.execute(count_q)).scalar() or 0
    if count > 0:
        return f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-yellow-500/20 text-yellow-400">{count}</span>'
    return ""


# ═════════════════════════════════════════════════════════════════════════════
# OPERATIONS — forms and actions
# ═════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# Onboard Organization
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/orgs/onboard", response_class=HTMLResponse)
async def org_onboard_form(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("org_onboard.html",
        _ctx(request, session, active="orgs", form={}, error=None, success=None)
    )


@router.post("/orgs/onboard", response_class=HTMLResponse)
async def org_onboard_submit(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form={}, error="Invalid CSRF token. Please try again.", success=None),
            status_code=403)
    form_data = await request.form()
    form = {
        "org_id": form_data.get("org_id", "").strip(),
        "display_name": form_data.get("display_name", "").strip(),
        "secret": form_data.get("secret", ""),
        "contact_email": form_data.get("contact_email", "").strip(),
        "webhook_url": form_data.get("webhook_url", "").strip() or None,
        "ca_certificate": form_data.get("ca_certificate", "").strip(),
    }
    action = form_data.get("action", "pending")

    # Validation
    if not form["org_id"] or not form["display_name"] or not form["secret"]:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form,
                 error="Organization ID, display name, and secret are required.", success=None))

    id_err = _validate_id(form["org_id"], "Organization ID")
    if id_err:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form, error=id_err, success=None))

    if len(form["display_name"]) > _DISPLAY_NAME_MAX:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form,
                 error=f"Display name must be at most {_DISPLAY_NAME_MAX} characters.", success=None))

    webhook_err = _validate_webhook_url(form["webhook_url"] or "")
    if webhook_err:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form, error=webhook_err, success=None))

    if not form["ca_certificate"] or "BEGIN CERTIFICATE" not in form["ca_certificate"]:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form,
                 error="A valid PEM CA certificate is required.", success=None))

    existing = await get_org_by_id(db, form["org_id"])
    if existing:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form,
                 error=f"Organization '{form['org_id']}' already exists.", success=None))

    # Create org
    await register_org(
        db, org_id=form["org_id"], display_name=form["display_name"],
        secret=form["secret"],
        metadata={"contact_email": form["contact_email"]},
        webhook_url=form["webhook_url"],
    )
    await update_org_ca_cert(db, form["org_id"], form["ca_certificate"])

    # Save optional OIDC configuration
    oidc_issuer = form_data.get("oidc_issuer_url", "").strip() or None
    oidc_cid = form_data.get("oidc_client_id", "").strip() or None
    oidc_csec = form_data.get("oidc_client_secret", "").strip() or None
    if oidc_issuer and oidc_cid:
        from app.registry.org_store import update_org_oidc
        await update_org_oidc(db, form["org_id"], oidc_issuer, oidc_cid, oidc_csec)

    if action == "approve":
        await set_org_status(db, form["org_id"], "active")
        await log_event(db, "onboarding.approved", "ok", org_id=form["org_id"],
                        details={"source": "dashboard"})
        msg = f"Organization '{form['org_id']}' registered and approved."
    else:
        await set_org_status(db, form["org_id"], "pending")
        await log_event(db, "onboarding.join_request", "ok", org_id=form["org_id"],
                        details={"source": "dashboard", "contact_email": form["contact_email"]})
        msg = f"Organization '{form['org_id']}' registered as pending."

    return templates.TemplateResponse("org_onboard.html",
        _ctx(request, session, active="orgs", form={}, error=None, success=msg))


# ─────────────────────────────────────────────────────────────────────────────
# Approve / Reject Organization
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/orgs/{org_id}/approve", response_class=HTMLResponse)
async def org_approve(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    org = await get_org_by_id(db, org_id)
    if org and org.status == "pending":
        await set_org_status(db, org_id, "active")
        await log_event(db, "onboarding.approved", "ok", org_id=org_id,
                        details={"source": "dashboard"})
    return RedirectResponse(url="/dashboard/orgs", status_code=303)


@router.post("/orgs/{org_id}/reject", response_class=HTMLResponse)
async def org_reject(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    org = await get_org_by_id(db, org_id)
    if org and org.status in ("pending", "active"):
        await set_org_status(db, org_id, "rejected")
        await log_event(db, "onboarding.rejected", "denied", org_id=org_id,
                        details={"source": "dashboard"})
    return RedirectResponse(url="/dashboard/orgs", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Register Agent
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/agents/register", response_class=HTMLResponse)
async def agent_register_form(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
    if not session.is_admin:
        q = q.where(OrganizationRecord.org_id == session.org_id)
    orgs = (await db.execute(q)).scalars().all()

    return templates.TemplateResponse("agent_register.html",
        _ctx(request, session, active="agents", form={}, orgs=orgs, error=None, success=None))


@router.post("/agents/register", response_class=HTMLResponse)
async def agent_register_submit(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        q = select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
        if not session.is_admin:
            q = q.where(OrganizationRecord.org_id == session.org_id)
        orgs = (await db.execute(q)).scalars().all()
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form={}, orgs=orgs,
                 error="Invalid CSRF token. Please try again.", success=None),
            status_code=403)
    form_data = await request.form()
    org_id      = form_data.get("org_id", "").strip()
    agent_name  = form_data.get("agent_name", "").strip()
    display_name = form_data.get("display_name", "").strip()
    capabilities_raw = form_data.get("capabilities", "").strip()

    # Build full agent_id from org + name
    agent_id = f"{org_id}::{agent_name}" if org_id and agent_name else ""
    if not display_name:
        display_name = agent_name.replace("-", " ").replace("_", " ").title()

    form = {
        "org_id": org_id,
        "agent_name": agent_name,
        "display_name": display_name,
        "capabilities": capabilities_raw,
    }

    result = await db.execute(
        select(OrganizationRecord)
        .where(OrganizationRecord.status == "active")
        .order_by(OrganizationRecord.org_id)
    )
    orgs = result.scalars().all()

    # Org user can only register agents for their own org
    if not session.is_admin and org_id != session.org_id:
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form=form, orgs=orgs,
                 error="You can only register agents for your own organization.", success=None))

    if not org_id or not agent_name:
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form=form, orgs=orgs,
                 error="Organization and agent name are required.", success=None))

    for val, lbl in [(org_id, "Organization ID"), (agent_name, "Agent name")]:
        id_err = _validate_id(val, lbl)
        if id_err:
            return templates.TemplateResponse("agent_register.html",
                _ctx(request, session, active="agents", form=form, orgs=orgs, error=id_err, success=None))

    existing = await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )
    if existing.scalar_one_or_none():
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form=form, orgs=orgs,
                 error=f"Agent '{agent_id}' already exists.", success=None))

    caps = [c.strip() for c in capabilities_raw.split(",") if c.strip()] if capabilities_raw else []
    if len(caps) > _CAPABILITY_MAX_COUNT:
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form=form, orgs=orgs,
                 error=f"Maximum {_CAPABILITY_MAX_COUNT} capabilities allowed.", success=None))
    for cap in caps:
        if len(cap) > _CAPABILITY_MAX_LEN or not re.match(r"^[a-zA-Z0-9._:\-]+$", cap):
            return templates.TemplateResponse("agent_register.html",
                _ctx(request, session, active="agents", form=form, orgs=orgs,
                     error=f"Invalid capability '{cap}'. Use alphanumeric, dots, colons, hyphens (max {_CAPABILITY_MAX_LEN} chars).",
                     success=None))

    await register_agent(
        db, agent_id=agent_id, org_id=org_id,
        display_name=display_name, capabilities=caps,
        metadata={},
    )
    await log_event(db, "registry.agent_registered", "ok",
                    agent_id=agent_id, org_id=org_id,
                    details={"source": "dashboard", "capabilities": caps})

    # Auto-create and auto-approve binding
    existing_binding = await get_binding_by_org_agent(db, org_id, agent_id)
    if not existing_binding:
        binding = await create_binding(db, org_id, agent_id, scope=caps)
        await approve_binding(db, binding.id, approved_by="dashboard-admin")

    return templates.TemplateResponse("agent_register.html",
        _ctx(request, session, active="agents", form={}, orgs=orgs, error=None,
             success=f"Agent '{agent_id}' registered. Binding approved."))


# ─────────────────────────────────────────────────────────────────────────────
# Delete Agent
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/agents/{agent_id:path}/delete", response_class=HTMLResponse)
async def agent_delete(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    agent = await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))
    record = agent.scalar_one_or_none()
    if record:
        # Revoke binding if exists
        binding = await get_binding_by_org_agent(db, record.org_id, agent_id)
        if binding and binding.status != "revoked":
            await revoke_binding(db, binding.id)

        # Delete the agent
        await db.delete(record)
        await db.commit()
        await log_event(db, "registry.agent_deleted", "ok",
                        agent_id=agent_id, org_id=record.org_id,
                        details={"source": "dashboard"})

    return RedirectResponse(url="/dashboard/agents", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Rotate Certificate
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/agents/{agent_id:path}/rotate-cert", response_class=HTMLResponse)
async def cert_rotate_form(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    agent = (await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))).scalar_one_or_none()
    if not agent:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    if not session.is_admin and agent.org_id != session.org_id:
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    return templates.TemplateResponse("cert_rotate.html",
        _ctx(request, session, active="agents", agent=agent, error=None, success=None))


@router.post("/agents/{agent_id:path}/rotate-cert", response_class=HTMLResponse)
async def cert_rotate_submit(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    agent = (await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))).scalar_one_or_none()
    if not agent:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    if not session.is_admin and agent.org_id != session.org_id:
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    form_data = await request.form()
    cert_pem = form_data.get("certificate", "").strip()

    if not cert_pem:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error="Certificate PEM is required.", success=None))

    # Validate the certificate
    from cryptography import x509 as crypto_x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.x509.oid import NameOID

    try:
        cert = crypto_x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error="Invalid PEM certificate.", success=None))

    # Verify CN matches agent_id
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs or cn_attrs[0].value != agent_id:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error=f"Certificate CN does not match agent '{agent_id}'.",
                 success=None))

    # Verify signed by org CA
    org = await get_org_by_id(db, agent.org_id)
    if not org or not org.ca_certificate:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error="Organization CA not configured.", success=None))

    try:
        org_ca = crypto_x509.load_pem_x509_certificate(org.ca_certificate.encode())
        org_ca.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error="Certificate is not signed by the organization CA.", success=None))
    except Exception:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error="Certificate verification failed. Please check the certificate is valid and signed by the organization CA.", success=None))

    old_thumbprint = agent.cert_thumbprint
    new_thumbprint = await rotate_agent_cert(db, agent_id, cert_pem)

    await log_event(db, "agent.cert_rotated", "ok",
                    agent_id=agent_id, org_id=agent.org_id,
                    details={"old_thumbprint": old_thumbprint, "new_thumbprint": new_thumbprint,
                             "source": "dashboard"})

    return templates.TemplateResponse("cert_rotate.html",
        _ctx(request, session, active="agents", agent=agent, error=None,
             success=f"Certificate rotated. New thumbprint: {new_thumbprint[:16]}…"))


# ─────────────────────────────────────────────────────────────────────────────
# Policies
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/policies", response_class=HTMLResponse)
async def policies_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    if session.is_admin:
        result = await db.execute(
            select(PolicyRecord)
            .where(PolicyRecord.policy_type == "session")
            .order_by(PolicyRecord.org_id, PolicyRecord.policy_id)
        )
    else:
        result = await db.execute(
            select(PolicyRecord)
            .where(PolicyRecord.policy_type == "session", PolicyRecord.org_id == session.org_id)
            .order_by(PolicyRecord.policy_id)
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
