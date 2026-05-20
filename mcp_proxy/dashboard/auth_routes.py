"""Mastio dashboard — Auth sub-router.

Sprint F-B-201 PR-2 of 10. Extracts the login / logout / register
surface from ``mcp_proxy/dashboard/router.py`` (sections "Auth" and
"Register").

Mounted via ``router.include_router(auth_routes.router)``.

Routes (5):

  GET  /proxy/login        login form (or redirect to register if no pwd set)
  POST /proxy/login        verify password + lockout/rate-limit gate + audit
  POST /proxy/logout       clear session (CSRF-gated when cookie present)
  GET  /proxy/register     one-shot admin password form
  POST /proxy/register     create admin password + redirect to login

Mirrors the Court sibling ``app/dashboard/auth_routes.py`` (F-B-202 PR-2).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._helpers import (
    _load_display_name,
    _login_client_ip,
    _post_login_redirect,
)
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import (
    MIN_PASSWORD_LENGTH,
    clear_session,
    get_session,
    is_admin_password_set,
    set_admin_password,
    set_session,
    verify_admin_password,
    verify_csrf,
)

_log = logging.getLogger("mcp_proxy.dashboard")

import pathlib
_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-auth"])


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # Pristine proxy: send the user to set an admin password first.
    if not await is_admin_password_set():
        return RedirectResponse(url="/proxy/register", status_code=303)

    # Already authenticated? Skip the form.
    session = get_session(request)
    if session.logged_in:
        return RedirectResponse(url=await _post_login_redirect(), status_code=303)

    from mcp_proxy.dashboard.oidc import is_oidc_configured
    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    oidc_enabled = await is_oidc_configured()
    password_enabled = await is_local_password_login_enabled()
    display_name = await _load_display_name()

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
        "oidc_enabled": oidc_enabled,
        "password_enabled": password_enabled,
        "display_name": display_name,
    })


@router.post("/login")
async def login_submit(request: Request):
    # State guard: if no password is set, you can't sign in — go register first.
    if not await is_admin_password_set():
        return RedirectResponse(url="/proxy/register", status_code=303)

    # SSO-only hardening toggle: refuse before touching bcrypt so a
    # timing side-channel can't probe the stored secret. The env
    # break-glass (``MCP_PROXY_FORCE_LOCAL_PASSWORD=1``) is honoured
    # inside ``is_local_password_login_enabled`` itself.
    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    if not await is_local_password_login_enabled():
        from mcp_proxy.db import log_audit
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="denied",
            detail="password sign-in disabled",
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Password sign-in is disabled. Use the SSO button instead.",
            "password_enabled": False,
        }, status_code=403)

    # H9 audit fix — per-IP lockout + rate-limit before bcrypt.
    from mcp_proxy.auth.rate_limit import get_agent_rate_limiter
    from mcp_proxy.dashboard.login_lockout import (
        LOGIN_RATE_PER_MINUTE,
        get_login_lockout_store,
    )
    from mcp_proxy.db import log_audit

    client_ip = _login_client_ip(request)
    lockout_store = get_login_lockout_store()

    locked_until = await lockout_store.is_locked(client_ip)
    if locked_until is not None:
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="denied",
            detail=f"ip-locked-until {int(locked_until)} ip={client_ip}",
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": (
                "Too many failed attempts from this address. Try again later "
                "or reset the admin password from the local CLI."
            ),
        }, status_code=429)

    if not await get_agent_rate_limiter().check(
        f"ip:{client_ip}:dashboard.login", LOGIN_RATE_PER_MINUTE,
    ):
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="denied",
            detail=f"rate-limited ip={client_ip}",
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Too many login attempts. Slow down and try again in a minute.",
        }, status_code=429)

    form = await request.form()
    password = str(form.get("password", ""))

    if not password:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Password is required.",
        }, status_code=400)

    if not await verify_admin_password(password):
        # Audit the failure but keep the message vague (don't leak whether the
        # account exists, the username is wrong, etc.).
        fail_count, locked_until = await lockout_store.record_failure(client_ip)
        detail = f"invalid password ip={client_ip} consecutive_fails={fail_count}"
        if locked_until is not None:
            detail += f" locked-until={int(locked_until)}"
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="error",
            detail=detail,
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid password.",
        }, status_code=401)

    await lockout_store.record_success(client_ip)
    await log_audit(
        agent_id="admin",
        action="auth.login",
        status="success",
        detail=f"ip={client_ip}",
    )

    response = RedirectResponse(url=await _post_login_redirect(), status_code=303)
    set_session(response, role="admin")
    return response


@router.post("/logout")
async def logout(request: Request):
    session = get_session(request)
    # Audit F-B-9: raise on CSRF failure instead of calling
    # ``verify_csrf`` purely for side effects. Previously a cross-site
    # POST without the form token logged the victim out anyway — a
    # force-logout via any attacker-controlled page the victim loaded
    # while holding a valid Mastio admin session. Enforce on any
    # non-empty ``csrf_token`` (valid cookie) and keep the bare
    # no-cookie path idempotent with a friendly 303.
    if session.csrf_token and not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    response = RedirectResponse(url="/proxy/login", status_code=303)
    clear_session(response)
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    # Already registered? Send them to login.
    if await is_admin_password_set():
        return RedirectResponse(url="/proxy/login", status_code=303)

    return templates.TemplateResponse("register.html", {
        "request": request,
        "error": None,
        "min_length": MIN_PASSWORD_LENGTH,
    })


@router.post("/register")
async def register_submit(request: Request):
    # Cannot re-register: someone already set the password.
    if await is_admin_password_set():
        return RedirectResponse(url="/proxy/login", status_code=303)

    form = await request.form()
    password = str(form.get("password", ""))
    confirm = str(form.get("confirm_password", ""))

    if not password or not confirm:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Both fields are required.",
            "min_length": MIN_PASSWORD_LENGTH,
        }, status_code=400)

    if len(password) < MIN_PASSWORD_LENGTH:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.",
            "min_length": MIN_PASSWORD_LENGTH,
        }, status_code=400)

    if password != confirm:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "The two passwords do not match.",
            "min_length": MIN_PASSWORD_LENGTH,
        }, status_code=400)

    try:
        await set_admin_password(password)
    except ValueError as exc:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": str(exc),
            "min_length": MIN_PASSWORD_LENGTH,
        }, status_code=400)

    from mcp_proxy.db import log_audit
    await log_audit(
        agent_id="admin",
        action="auth.register",
        status="success",
        details={
            "event": "admin_password_registered",
            "client_ip": _login_client_ip(request),
            "user_agent": (request.headers.get("user-agent") or "")[:200],
        },
    )

    # Force a clean sign-in for the very first session.
    return RedirectResponse(url="/proxy/login", status_code=303)
