"""Court dashboard — authentication routes.

Sprint 2 / F-B-202 PR-2 of 10. Extracts login / logout / first-boot
password setup / OIDC federation routes from the 3125-LOC
``app/dashboard/router.py`` god-object into a per-feature sub-router.

Mounted as a child of the main dashboard router via
``router.include_router(auth_routes.router)`` in ``router.py``, which
preserves the ``/dashboard/...`` prefix and keeps every URL byte-for-
byte identical to the pre-split version.

Routes (7):

  GET  /dashboard/login           login form (or redirect to /setup on
                                  first boot when no admin password is
                                  set yet)
  POST /dashboard/login           password login submit
  POST /dashboard/logout          session clear

  GET  /dashboard/setup           first-boot admin password page
  POST /dashboard/setup           first-boot admin password submit
                                  (consume_bootstrap_token_and_set_password)

  GET  /dashboard/oidc/start      kick off OIDC authorization code flow
  GET  /dashboard/oidc/callback   handle OIDC provider redirect

The constant ``MIN_ADMIN_PASSWORD_LENGTH`` lives here because both
``/setup`` GET and ``/setup`` POST consume it; it would be re-imported
by every consumer of the helper module if it moved there, while it's
naturally co-located with the only two routes that read it.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dashboard.session import (
    DashboardSession, clear_session, get_session, set_session, verify_csrf,
)
from app.dashboard._template_env import build_templates
from app.db.audit import log_event
from app.db.database import get_db

import pathlib

_log = logging.getLogger("agent_trust")

# Mirror the parent router's template path so renders see the same
# templates dir. We construct a fresh Jinja2Templates via the factory
# (mirrors mcp_proxy/dashboard sub-router pattern, memory
# `feedback_dashboard_template_envs_per_router`) — each sub-router owns
# its env so cross-cutting globals registered by build_templates apply
# uniformly without import-time coupling.
_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-auth"])

# F-B-202 PR-2 note: NIST SP 800-63B compliant length-only rule. Both
# the pre-auth /setup form and the future /admin/settings change-pw
# form read this constant. Kept here for now; if PR-3 (admin_settings)
# wants its own copy or a different value, factor through _helpers.
MIN_ADMIN_PASSWORD_LENGTH = 12


# ── Login / Logout ────────────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # First-boot: no admin password set yet → go straight to /setup.
    # No login form is shown until the operator has picked a password.
    from app.kms.admin_secret import is_admin_password_user_set
    if not await is_admin_password_user_set():
        return RedirectResponse(url="/dashboard/setup", status_code=303)

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

    from app.kms.admin_secret import is_admin_password_user_set
    # Guard: if the admin password hasn't been set yet, you can't sign in —
    # the operator has to pick a password via /dashboard/setup first.
    if not await is_admin_password_user_set():
        return RedirectResponse(url="/dashboard/setup", status_code=303)

    from app.config import get_settings as _gs
    admin_oidc_enabled = bool(_gs().admin_oidc_issuer_url and _gs().admin_oidc_client_id)

    form = await request.form()
    password = form.get("password", "")
    # user_id is accepted for backward-compat but ignored — only the network
    # admin can log in. An explicit "admin" user_id is optional.
    user_id = form.get("user_id", "admin").strip().lower() or "admin"

    if not password:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Password is required.",
            "admin_oidc_enabled": admin_oidc_enabled,
        })

    if user_id not in ("", "admin"):
        # Org-tenant login was removed — tenants manage their org on the proxy.
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "The broker dashboard is network-admin only. "
                     "Org tenants should log in on their per-org proxy.",
            "admin_oidc_enabled": admin_oidc_enabled,
        })

    from app.kms.admin_secret import (
        get_admin_secret_hash, verify_admin_password,
    )
    stored_hash = await get_admin_secret_hash()
    # Only the stored bcrypt hash is trusted. The .env ADMIN_SECRET
    # is not accepted as a dashboard credential (shake-out P0-06).
    if verify_admin_password(password, stored_hash):
        response = RedirectResponse(url="/dashboard", status_code=303)
        set_session(response, role="admin")
        return response
    return templates.TemplateResponse("login.html", {
        "request": request, "error": "Invalid credentials.",
        "admin_oidc_enabled": admin_oidc_enabled,
    })


@router.post("/logout")
async def logout(request: Request):
    session = get_session(request)
    # Audit F-B-9: enforce CSRF for every request that carries a valid
    # session cookie, not only ``logged_in`` ones. ``csrf_token`` is
    # empty on ``_NO_SESSION`` (missing / invalid / expired cookie) so
    # a logout without a cookie still gets the friendly 303; but any
    # cookie the server issued must come back accompanied by the form
    # CSRF token it is bound to.
    if session.csrf_token and not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    response = RedirectResponse(url="/dashboard/login", status_code=303)
    clear_session(response)
    return response


# ── First-boot admin password setup (shake-out P0-06) ────────────
#
# Flow (setup-first-no-login, matches mcp_proxy /register pattern):
#   1. Fresh deploy: no hash, no user_set flag.
#   2. Any hit to /dashboard/login → redirects to /dashboard/setup.
#      The setup page is served without authentication.
#   3. Admin submits password + confirm on /dashboard/setup. The password is
#      bcrypt-hashed, stored in the KMS backend, and user_set is flipped true.
#   4. Admin is redirected to /dashboard/login and signs in with the new
#      password.  From this moment on .env ADMIN_SECRET is no longer a
#      dashboard credential — only the stored hash is trusted.  (ADMIN_SECRET
#      remains valid for the `x-admin-secret` HTTP API header used by
#      onboarding/policy/org admin routes — see those routers.)
#
# MIN_ADMIN_PASSWORD_LENGTH is intentionally lax: length only, no complexity
# rules, per NIST SP 800-63B guidance and the P0-06 product directive.


@router.get("/setup", response_class=HTMLResponse)
async def admin_setup_page(request: Request):
    # The setup page is public when user_set=false — this is the first
    # landing spot on a fresh deploy, no session required.  Once the
    # password has been picked, the page redirects callers to /login.
    from app.kms.admin_secret import is_admin_password_user_set
    if await is_admin_password_user_set():
        return RedirectResponse(url="/dashboard/login", status_code=303)

    return templates.TemplateResponse("admin_setup.html", {
        "request": request,
        "min_length": MIN_ADMIN_PASSWORD_LENGTH,
        "error": None,
    })


@router.post("/setup", response_class=HTMLResponse)
async def admin_setup_submit(request: Request, db: AsyncSession = Depends(get_db)):
    from app.kms.admin_secret import (
        consume_bootstrap_token_and_set_password,
        is_admin_password_user_set,
    )
    # State guard: the setup form is one-shot.  Once a password has been
    # chosen, further POSTs bounce to /login — prevents replay/overwrite.
    # Audit F-D-3: this is a soft UX hint; the atomic consume below is
    # the actual race-safe gate.
    if await is_admin_password_user_set():
        return RedirectResponse(url="/dashboard/login", status_code=303)

    form = await request.form()
    password = str(form.get("password", ""))
    confirm = str(form.get("password_confirm", ""))
    bootstrap_token = str(form.get("bootstrap_token", "")).strip()

    def _err(msg: str, status: int = 400):
        return templates.TemplateResponse("admin_setup.html", {
            "request": request,
            "min_length": MIN_ADMIN_PASSWORD_LENGTH, "error": msg,
        }, status_code=status)

    if not password or not confirm:
        return _err("Both fields are required.")
    if not bootstrap_token:
        # Audit F-B-4: /dashboard/setup is reachable pre-auth on a fresh
        # deploy. Require the one-shot bootstrap token printed on broker
        # startup so only the legitimate operator (with access to the
        # broker logs or the ``certs/.admin_bootstrap_token`` file) can
        # succeed.
        return _err(
            "Bootstrap token is required. Check the broker startup logs "
            "or ``certs/.admin_bootstrap_token`` on the broker host, "
            "then paste the value below."
        )
    if len(password) < MIN_ADMIN_PASSWORD_LENGTH:
        return _err(
            f"Password must be at least {MIN_ADMIN_PASSWORD_LENGTH} characters."
        )
    if password != confirm:
        return _err("The two passwords do not match.")

    import bcrypt
    new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()

    # Audit F-B-4 + F-D-3: atomic consume-or-fail. Only one concurrent
    # POST wins — loser and wrong-token alike see 403 with the same
    # error body (no timing/shape oracle on which case happened).
    try:
        consumed = await consume_bootstrap_token_and_set_password(
            bootstrap_token, new_hash,
        )
    except Exception as exc:
        _log.error("Failed to persist admin password during setup: %s", exc)
        return _err(
            "Failed to save the new password. Check the broker logs "
            "for details (KMS backend may be unreachable).",
            status=500,
        )

    if not consumed:
        return _err(
            "Invalid or expired bootstrap token. Retrieve the current "
            "value from the broker startup logs and retry.",
            status=403,
        )

    await log_event(db, "admin.first_boot_password_set", "ok",
                    details={"source": "dashboard", "actor": "admin"})

    # Admin now signs in with the password they just chose.
    return RedirectResponse(url="/dashboard/login", status_code=303)


# ── OIDC federation login ─────────────────────────────────────────


@router.get("/oidc/start")
async def oidc_start(
    request: Request,
    role: str = Query(default="admin"),
    org_id: str | None = Query(default=None),  # deprecated; ignored
    db: AsyncSession = Depends(get_db),
):
    """Initiate network-admin OIDC authorization code flow with PKCE.

    The ``role`` query param is retained for backward-compat but only
    ``admin`` is supported — per-org SSO was removed from the broker.
    """
    from app.config import get_settings
    from app.dashboard.oidc import create_oidc_state, build_authorization_url, OidcError
    from app.dashboard.session import set_oidc_state

    settings = get_settings()
    admin_oidc_enabled = bool(settings.admin_oidc_issuer_url and settings.admin_oidc_client_id)

    if not settings.broker_public_url:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "OIDC requires BROKER_PUBLIC_URL to be configured.",
            "admin_oidc_enabled": admin_oidc_enabled,
        })

    if role != "admin":
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "The broker dashboard is network-admin only. "
                     "Org tenants should log in on their per-org proxy.",
            "admin_oidc_enabled": admin_oidc_enabled,
        })

    if not settings.admin_oidc_issuer_url or not settings.admin_oidc_client_id:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Admin SSO is not configured.",
            "admin_oidc_enabled": False,
        })

    redirect_uri = settings.broker_public_url.rstrip("/") + "/dashboard/oidc/callback"
    issuer_url = settings.admin_oidc_issuer_url
    client_id = settings.admin_oidc_client_id

    flow_state = create_oidc_state("admin", None)
    try:
        auth_url = await build_authorization_url(
            issuer_url, client_id, redirect_uri, flow_state,
        )
    except OidcError as e:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": f"SSO error: {e}",
            "admin_oidc_enabled": admin_oidc_enabled,
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

    # Only the admin OIDC flow is supported. Any legacy "org" state is rejected.
    if flow_state.role != "admin":
        return _login_error(
            "Org-tenant SSO is not available on the broker dashboard. "
            "Tenants log in on the per-org proxy."
        )

    issuer_url = settings.admin_oidc_issuer_url
    client_id = settings.admin_oidc_client_id
    client_secret = settings.admin_oidc_client_secret or None

    try:
        identity = await exchange_code_for_identity(
            issuer_url, client_id, client_secret, redirect_uri, code, flow_state
        )
    except OidcError as e:
        _log.warning("OIDC callback failed: %s", e)
        return _login_error(f"SSO authentication failed: {e}")

    # Create admin session
    response = RedirectResponse(url="/dashboard", status_code=303)
    clear_oidc_state(response)
    set_session(response, role="admin")

    await log_event(db, "dashboard.oidc_login", "ok",
                    details={
                        "role": "admin",
                        "sub": identity.sub,
                        "email": identity.email,
                        "issuer": identity.issuer,
                    })

    return response
