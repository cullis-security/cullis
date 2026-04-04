"""
Dashboard session management — signed cookie-based authentication.

Two roles:
  - admin: full access to all orgs, agents, sessions, audit. Can approve/reject orgs.
  - org:   scoped to a single organization. Can manage own agents and bindings.

The session is stored in a signed cookie (HMAC-SHA256). No server-side session
store needed — the cookie contains the role and org_id, verified on every request.

CSRF protection: a per-session token is embedded in the cookie and must be
present as a hidden form field on every state-changing POST request.
"""
import hashlib
import hmac
import json
import os
import time
import logging
from dataclasses import dataclass

from fastapi import Request, Response
from starlette.responses import RedirectResponse

_log = logging.getLogger("agent_trust")

_COOKIE_NAME = "atn_session"
_COOKIE_MAX_AGE = 8 * 3600  # 8 hours


@dataclass
class DashboardSession:
    role: str           # "admin" | "org"
    org_id: str | None  # None for admin, org_id for org users
    csrf_token: str = ""
    logged_in: bool = True

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


_NO_SESSION = DashboardSession(role="none", org_id=None, csrf_token="", logged_in=False)


def _get_secret() -> str:
    from app.config import get_settings
    return get_settings().admin_secret


def _sign(payload: str) -> str:
    secret = _get_secret()
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify(cookie_value: str) -> str | None:
    """Verify signature and return payload string, or None if invalid."""
    if "." not in cookie_value:
        return None
    payload, sig = cookie_value.rsplit(".", 1)
    secret = _get_secret()
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return payload


def get_session(request: Request) -> DashboardSession:
    """Extract and verify the dashboard session from the request cookie."""
    cookie = request.cookies.get(_COOKIE_NAME)
    if not cookie:
        return _NO_SESSION

    payload_str = _verify(cookie)
    if not payload_str:
        return _NO_SESSION

    try:
        data = json.loads(payload_str)
    except (json.JSONDecodeError, TypeError):
        return _NO_SESSION

    # Check expiry
    if data.get("exp", 0) < time.time():
        return _NO_SESSION

    return DashboardSession(
        role=data.get("role", "none"),
        org_id=data.get("org_id"),
        csrf_token=data.get("csrf_token", ""),
        logged_in=True,
    )


def set_session(response: Response, role: str, org_id: str | None = None) -> str:
    """Set a signed session cookie on the response. Returns the CSRF token."""
    csrf_token = os.urandom(16).hex()
    payload = json.dumps({
        "role": role,
        "org_id": org_id,
        "csrf_token": csrf_token,
        "exp": int(time.time()) + _COOKIE_MAX_AGE,
    })
    signed = _sign(payload)
    from app.config import get_settings
    is_https = "https" in get_settings().broker_public_url.lower() if get_settings().broker_public_url else False
    response.set_cookie(
        _COOKIE_NAME, signed,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=is_https,
    )
    return csrf_token


def clear_session(response: Response) -> None:
    """Delete the session cookie."""
    from app.config import get_settings
    is_https = "https" in get_settings().broker_public_url.lower() if get_settings().broker_public_url else False
    response.delete_cookie(_COOKIE_NAME, samesite="lax", secure=is_https)


def require_login(request: Request) -> DashboardSession | RedirectResponse:
    """
    Helper: returns the session if logged in, or a redirect to /dashboard/login.
    Use in route handlers:
        session = require_login(request)
        if isinstance(session, RedirectResponse):
            return session
    """
    session = get_session(request)
    if not session.logged_in:
        return RedirectResponse(url="/dashboard/login", status_code=303)
    return session


async def verify_csrf(request: Request, session: DashboardSession) -> bool:
    """Verify the CSRF token from the form matches the one in the session cookie."""
    form = await request.form()
    token = form.get("csrf_token", "")
    if not session.csrf_token or not token:
        return False
    return hmac.compare_digest(str(token), session.csrf_token)
