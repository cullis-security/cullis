"""Local-mode login + session router — ADR-025 Phase 2.

Mounted by ``cullis_connector.web.build_app`` when
``AUTH_MODE=local`` (default for Frontdesk SMB deployments without a
corporate IdP).

Endpoints:

    GET  /login                       server-side fallback form
    GET  /change-password             server-side fallback form
    POST /api/auth/login              JSON {user_name,password} → cookie
    POST /api/auth/logout             clears cookie
    POST /api/auth/change-password    JSON {old_password,new_password}
    GET  /api/auth/whoami-local       returns cookie payload echo
    GET  /api/auth/runtime-info       no-auth hint for the SPA bootstrap

Cookie shape (``cullis_local_session``): see
``cullis_connector.identity.local_session``. The cookie is HttpOnly +
SameSite=Strict and Secure unless ``CULLIS_CONNECTOR_DEV=1``.

Phase-4 stubs (lockout / audit) are wired here as no-op helpers so
this PR does not depend on the parallel lockout PR landing first. A
follow-up patch swaps the stubs for the real implementations once
both have merged.
"""
from __future__ import annotations

import logging
import os
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from pydantic import BaseModel, Field

from cullis_connector.ambassador.shared.wire import bootstrap_cookie_secret
from cullis_connector.identity.local_session import (
    LOCAL_SESSION_COOKIE_NAME,
    LOCAL_SESSION_TTL_SEC,
    LocalSessionPayload,
    build_payload,
    issue_local_cookie,
    parse_local_cookie,
)
from cullis_connector.identity.users import (
    MIN_PASSWORD_LENGTH,
    get_user_by_name,
    mark_password_changed,
    set_password_hash,
    verify_password,
)
from cullis_connector.identity.users_db import get_users_session

_log = logging.getLogger("cullis_connector.auth.local_router")


_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


router = APIRouter(tags=["auth", "local"])


# ── Phase 4 stubs ────────────────────────────────────────────────────────
#
# Wired to the real lockout + audit modules in a follow-up PR after
# Phase 4 (cullis_connector/identity/lockout.py + audit.py) lands. For
# Phase 2 these are intentional no-ops that emit a single warning so
# the call-sites stay shaped correctly and follow-up only edits the
# helper bodies.


def _check_lockout(ip: str, user_name: str) -> bool:
    """Return ``True`` if the (ip, user_name) pair is currently locked.

    Phase-2 stub — never locked. Wired to lockout/audit in follow-up PR
    after Phase 4 lands.
    """
    return False


def _record_login_attempt(
    ip: str, user_name: str, success: bool,
) -> None:
    """Record a login attempt for lockout + audit accounting.

    Phase-2 stub — no-op. Wired to lockout/audit in follow-up PR after
    Phase 4 lands.
    """
    # Single debug line only — never log the password and never log a
    # full audit event from the stub (so the follow-up PR's audit
    # writer is the only place rows are emitted).
    _log.debug(
        "login attempt (stub) ip=%s user_name=%s success=%s",
        ip, user_name, success,
    )


# ── Request / response models ────────────────────────────────────────────


class LoginRequest(BaseModel):
    user_name: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=4096)


class LoginResponse(BaseModel):
    ok: bool
    must_change_password: bool
    principal_name: str
    exp: int


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1, max_length=4096)
    new_password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=4096)


class ChangePasswordResponse(BaseModel):
    ok: bool
    must_change_password: bool
    principal_name: str
    exp: int


class WhoamiLocalResponse(BaseModel):
    user_name: str
    principal_name: str
    must_change_password: bool
    exp: int


class RuntimeInfoResponse(BaseModel):
    auth_mode: str
    login_url: str
    require_change_password_url: str


# ── Helpers ──────────────────────────────────────────────────────────────


def _is_secure_cookie() -> bool:
    """Return True unless we're explicitly in dev mode.

    The Frontdesk container's reverse proxy terminates TLS, so the
    Connector's own cookie must carry ``Secure`` so the browser refuses
    to attach it to HTTP requests. ``CULLIS_CONNECTOR_DEV=1`` flips it
    off so the dashboard works on plain ``http://127.0.0.1:7777``
    during local development.
    """
    return os.environ.get("CULLIS_CONNECTOR_DEV", "") != "1"


def _config_dir(request: Request) -> Path:
    config = getattr(request.app.state, "connector_config", None)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="connector_config not bound on app.state",
        )
    return config.config_dir


def _cookie_secret(request: Request) -> bytes:
    """Return the cached cookie secret, bootstrapping it on first call.

    Stashed on ``app.state`` so the bootstrap (file IO + chmod) only
    runs once per process even though ``parse_local_cookie`` /
    ``issue_local_cookie`` need the secret on every request.
    """
    cached = getattr(request.app.state, "local_cookie_secret", None)
    if cached is not None:
        return cached
    secret = bootstrap_cookie_secret(_config_dir(request))
    request.app.state.local_cookie_secret = secret
    return secret


def _set_cookie(
    response: Response, cookie_value: str, *, max_age: int = LOCAL_SESSION_TTL_SEC,
) -> None:
    response.set_cookie(
        LOCAL_SESSION_COOKIE_NAME,
        cookie_value,
        max_age=max_age,
        httponly=True,
        samesite="strict",
        secure=_is_secure_cookie(),
        path="/",
    )


def _clear_cookie(response: Response) -> None:
    # Delete by setting Max-Age=0 with the same flags so the browser
    # actually overwrites the prior cookie. ``delete_cookie`` does not
    # always emit Max-Age which some browsers ignore.
    response.set_cookie(
        LOCAL_SESSION_COOKIE_NAME,
        value="",
        max_age=0,
        httponly=True,
        samesite="strict",
        secure=_is_secure_cookie(),
        path="/",
    )


async def _require_local_session(request: Request) -> LocalSessionPayload:
    """FastAPI dep — return a valid session payload or raise 401.

    Also re-checks the user is still enabled in users.db on every
    request (defence in depth — an admin who disables a user mid-flight
    must invalidate the existing cookie). Cheap: a single indexed
    lookup on the username PK.
    """
    raw = request.cookies.get(LOCAL_SESSION_COOKIE_NAME, "")
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login required",
        )
    secret = _cookie_secret(request)
    payload = parse_local_cookie(raw, secret)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login required",
        )
    config_dir = _config_dir(request)
    async with get_users_session(config_dir) as session:
        user = await get_user_by_name(session, payload.user_name)
    if user is None or user.disabled:
        # Account vanished or was disabled since the cookie was issued
        # — treat as logged out. Generic 401 to avoid leaking which
        # state caused the failure.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="login required",
        )
    return payload


def _client_ip(request: Request) -> str:
    """Best-effort caller IP. Used only for the Phase-4 lockout stub."""
    if request.client is not None:
        return request.client.host or ""
    return ""


# ── Server-side fallback HTML ────────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    """Plain HTML form for non-SPA clients + ops debug."""
    return _templates.TemplateResponse(
        request,
        "login.html",
        {
            "connector_status": "offline",
            "connector_status_label": "Sign in",
            "error": None,
        },
    )


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request) -> Response:
    """Plain HTML form for non-SPA first-login change flow."""
    return _templates.TemplateResponse(
        request,
        "change_password.html",
        {
            "connector_status": "waiting",
            "connector_status_label": "Change password",
            "error": None,
        },
    )


# ── JSON API ─────────────────────────────────────────────────────────────


@router.post("/api/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> JSONResponse:
    """Verify credentials and issue a session cookie.

    Generic 401 on every failure (missing user, wrong password,
    disabled account) so a brute-forcer cannot enumerate valid
    user_names off the response code or message.
    """
    ip = _client_ip(request)
    if _check_lockout(ip, body.user_name):
        # Phase-4 stub — never returns True today. Real implementation
        # surfaces 429 with a Retry-After header.
        _record_login_attempt(ip, body.user_name, success=False)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts",
        )

    config_dir = _config_dir(request)
    async with get_users_session(config_dir) as session:
        user = await get_user_by_name(session, body.user_name)
        if user is None or user.disabled:
            _record_login_attempt(ip, body.user_name, success=False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
            )
        ok = await verify_password(session, body.user_name, body.password)
    if not ok:
        _record_login_attempt(ip, body.user_name, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )

    payload = build_payload(
        user_name=user.user_name,
        must_change_password=user.must_change_password,
    )
    secret = _cookie_secret(request)
    cookie_value = issue_local_cookie(payload, secret)
    body_out = LoginResponse(
        ok=True,
        must_change_password=payload.must_change_password,
        principal_name=payload.principal_name,
        exp=payload.exp,
    )
    response = JSONResponse(body_out.model_dump())
    _set_cookie(response, cookie_value)
    _record_login_attempt(ip, body.user_name, success=True)
    # Never log the password — only the username + result.
    _log.info(
        "local login ok user_name=%s must_change=%s",
        user.user_name, payload.must_change_password,
    )
    return response


@router.post("/api/auth/logout")
async def logout(request: Request) -> JSONResponse:
    """Invalidate the cookie. No-op when called without one."""
    response = JSONResponse({"ok": True})
    _clear_cookie(response)
    return response


@router.post("/api/auth/change-password", response_model=ChangePasswordResponse)
async def change_password(
    body: ChangePasswordRequest, request: Request,
) -> JSONResponse:
    """Verify old password + persist new + reissue cookie.

    Uses ``_require_local_session`` semantics inline so we can reissue
    the cookie on the same response. Wrong old password returns 401
    (not 403) to avoid distinguishing "logged in but wrong old pw"
    from "session expired".
    """
    payload = await _require_local_session(request)
    config_dir = _config_dir(request)
    async with get_users_session(config_dir) as session:
        ok = await verify_password(
            session, payload.user_name, body.old_password,
        )
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
            )
        try:
            updated = await set_password_hash(
                session, payload.user_name, body.new_password,
                must_change=False,
            )
        except ValueError as exc:
            # ``set_password_hash`` re-validates length/whitespace.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )
        if not updated:
            # User vanished between cookie parse and update — generic
            # 401 so attackers cannot probe state via this endpoint.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="login required",
            )
        # Belt + braces: explicitly clear must_change in case
        # ``set_password_hash`` semantics drift in future. Currently
        # already cleared via ``must_change=False``.
        await mark_password_changed(session, payload.user_name)

    new_payload = build_payload(
        user_name=payload.user_name,
        must_change_password=False,
        principal_name=payload.principal_name,
    )
    secret = _cookie_secret(request)
    cookie_value = issue_local_cookie(new_payload, secret)
    body_out = ChangePasswordResponse(
        ok=True,
        must_change_password=False,
        principal_name=new_payload.principal_name,
        exp=new_payload.exp,
    )
    response = JSONResponse(body_out.model_dump())
    _set_cookie(response, cookie_value)
    _log.info(
        "local password changed user_name=%s", payload.user_name,
    )
    return response


@router.get("/api/auth/whoami-local", response_model=WhoamiLocalResponse)
async def whoami_local(request: Request) -> WhoamiLocalResponse:
    """Echo the cookie payload — drives the SPA's "are you logged in" probe."""
    payload = await _require_local_session(request)
    return WhoamiLocalResponse(
        user_name=payload.user_name,
        principal_name=payload.principal_name,
        must_change_password=payload.must_change_password,
        exp=payload.exp,
    )


@router.get("/api/auth/runtime-info", response_model=RuntimeInfoResponse)
async def runtime_info() -> RuntimeInfoResponse:
    """Public hint for the SPA bootstrap: which login flow to render.

    Intentionally no-auth so the SPA can fetch this before it has any
    cookie. Returns only public-safe metadata (URL paths, mode name).
    """
    # Hardcoded "local" because this router is only mounted in
    # local mode by ``build_app``. Callers in shared/oidc mode get
    # 404 from FastAPI (no router mounted) — the SPA detects this and
    # falls back to the SSO bootstrap path.
    return RuntimeInfoResponse(
        auth_mode="local",
        login_url="/login",
        require_change_password_url="/change-password",
    )


__all__ = [
    "_require_local_session",
    "router",
]
