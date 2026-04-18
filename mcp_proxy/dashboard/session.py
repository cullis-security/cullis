"""
Dashboard session management — HMAC-SHA256 signed cookies + bcrypt admin password.

Single role for the MCP Proxy dashboard: admin.
The session is stored in a signed cookie (HMAC-SHA256). No server-side
session store needed — the cookie contains the role and CSRF token,
verified on every request.

The admin password is hashed with bcrypt and stored in proxy_config under
the key 'admin_password_hash'. The very first visit to /proxy/register
sets it; from then on /proxy/login verifies it before issuing a session.

CSRF protection: a per-session token is embedded in the cookie and must
be present as a hidden form field on every state-changing POST request.
Login and register are pre-session and therefore CSRF-exempt.
"""
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass

import bcrypt
from fastapi import Request, Response
from starlette.responses import RedirectResponse

_log = logging.getLogger("mcp_proxy.dashboard")

_COOKIE_NAME = "mcp_proxy_session"
_COOKIE_MAX_AGE = 8 * 3600  # 8 hours


@dataclass
class ProxyDashboardSession:
    """Dashboard session payload."""
    role: str  # "admin" only for now
    csrf_token: str = ""
    logged_in: bool = True


_NO_SESSION = ProxyDashboardSession(role="none", csrf_token="", logged_in=False)

_auto_key: str = ""


def _get_secret() -> str:
    """Return the dashboard signing key from settings, or auto-generate one."""
    global _auto_key
    from mcp_proxy.config import get_settings
    key = get_settings().dashboard_signing_key
    if key:
        return key
    if not _auto_key:
        _auto_key = os.urandom(32).hex()
    return _auto_key


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


def get_session(request: Request) -> ProxyDashboardSession:
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

    if data.get("exp", 0) < time.time():
        return _NO_SESSION

    return ProxyDashboardSession(
        role=data.get("role", "none"),
        csrf_token=data.get("csrf_token", ""),
        logged_in=True,
    )


def set_session(response: Response, role: str = "admin") -> str:
    """Set a signed session cookie on the response. Returns the CSRF token."""
    csrf_token = os.urandom(16).hex()
    payload = json.dumps({
        "role": role,
        "csrf_token": csrf_token,
        "exp": int(time.time()) + _COOKIE_MAX_AGE,
    })
    signed = _sign(payload)
    from mcp_proxy.config import get_settings as _proxy_settings
    _pub_url = _proxy_settings().proxy_public_url
    _use_secure = _pub_url.startswith("https") if _pub_url else False
    response.set_cookie(
        _COOKIE_NAME, signed,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=_use_secure,
    )
    return csrf_token


def clear_session(response: Response) -> None:
    """Delete the session cookie."""
    from mcp_proxy.config import get_settings as _proxy_settings
    _pub_url = _proxy_settings().proxy_public_url
    _use_secure = _pub_url.startswith("https") if _pub_url else False
    response.delete_cookie(_COOKIE_NAME, samesite="lax", secure=_use_secure)


def require_login(request: Request) -> ProxyDashboardSession | RedirectResponse:
    """Return the session if logged in, or a redirect to /proxy/login."""
    session = get_session(request)
    if not session.logged_in:
        return RedirectResponse(url="/proxy/login", status_code=303)
    return session


async def verify_csrf(request: Request, session: ProxyDashboardSession) -> bool:
    """Verify the CSRF token from the form matches the one in the session cookie."""
    form = await request.form()
    token = form.get("csrf_token", "")
    if not session.csrf_token or not token:
        return False
    return hmac.compare_digest(str(token), session.csrf_token)


# ─────────────────────────────────────────────────────────────────────────────
# OIDC flow state cookie — short-lived, signed, single-purpose
#
# NOTE: set_oidc_state / get_oidc_state / clear_oidc_state duplicate the
# equivalent helpers in app/dashboard/session.py (only the cookie name
# differs: atn_session → mcp_proxy_session). Will be extracted to
# cullis_core/ shared lib in a follow-up refactor.
# ─────────────────────────────────────────────────────────────────────────────

_OIDC_STATE_COOKIE = "mcp_proxy_oidc_state"
_OIDC_STATE_MAX_AGE = 600  # 10 minutes


def set_oidc_state(response: Response, flow_state: dict) -> None:
    """Store the OIDC flow state (state+nonce+code_verifier) in a signed cookie."""
    payload_data = dict(flow_state)
    payload_data["exp"] = int(time.time()) + _OIDC_STATE_MAX_AGE
    payload = json.dumps(payload_data)
    signed = _sign(payload)
    from mcp_proxy.config import get_settings as _proxy_settings
    _pub_url = _proxy_settings().proxy_public_url
    _use_secure = _pub_url.startswith("https") if _pub_url else False
    response.set_cookie(
        _OIDC_STATE_COOKIE, signed,
        max_age=_OIDC_STATE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=_use_secure,
    )


def get_oidc_state(request: Request) -> dict | None:
    """Read and verify the OIDC state cookie. Returns None if missing / invalid / expired."""
    cookie = request.cookies.get(_OIDC_STATE_COOKIE)
    if not cookie:
        return None
    payload_str = _verify(cookie)
    if not payload_str:
        return None
    try:
        data = json.loads(payload_str)
    except (json.JSONDecodeError, TypeError):
        return None
    if data.get("exp", 0) < time.time():
        return None
    return data


def clear_oidc_state(response: Response) -> None:
    """Delete the OIDC state cookie."""
    from mcp_proxy.config import get_settings as _proxy_settings
    _pub_url = _proxy_settings().proxy_public_url
    _use_secure = _pub_url.startswith("https") if _pub_url else False
    response.delete_cookie(
        _OIDC_STATE_COOKIE, samesite="lax", secure=_use_secure,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Admin password (bcrypt, stored in proxy_config.admin_password_hash)
# ─────────────────────────────────────────────────────────────────────────────

ADMIN_PASSWORD_KEY = "admin_password_hash"
MIN_PASSWORD_LENGTH = 8

# Key under which the admin toggles local-password sign-in on/off from
# Settings. Absent row → enabled (retro-compat for pre-existing proxies).
LOCAL_PASSWORD_ENABLED_KEY = "local_password_enabled"


async def is_admin_password_set() -> bool:
    """Return True if an admin password has been set on this proxy instance."""
    from mcp_proxy.db import get_config
    return bool(await get_config(ADMIN_PASSWORD_KEY))


async def set_admin_password(plaintext: str) -> None:
    """Hash the password with bcrypt and persist it.

    Caller is responsible for length / confirm validation. This function
    only enforces the absolute minimum to avoid storing junk.
    """
    if not plaintext or len(plaintext) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    from mcp_proxy.db import set_config
    hashed = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12))
    await set_config(ADMIN_PASSWORD_KEY, hashed.decode())


async def verify_admin_password(plaintext: str) -> bool:
    """Constant-time bcrypt verify against the stored hash. False if no hash set."""
    if not plaintext:
        return False

    from mcp_proxy.db import get_config
    stored = await get_config(ADMIN_PASSWORD_KEY)
    if not stored:
        return False

    try:
        return bcrypt.checkpw(plaintext.encode(), stored.encode())
    except (ValueError, TypeError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Local admin password sign-in path — toggle (enterprise SSO-only hardening)
#
# With SSO (OIDC) wired, the bcrypt admin password is a dual-auth path:
# anyone who learns it bypasses MFA the IdP enforces. Operators harden
# this by flipping the toggle off once OIDC is proven working, collapsing
# daily sign-in to SSO only. Local password stays as a break-glass: the
# env var ``MCP_PROXY_FORCE_LOCAL_PASSWORD`` forces it back on at boot
# even if the DB flag says disabled, so an IdP outage can't strand the
# admin out of their own dashboard. Pattern mirrors Grafana's
# ``auth.disable_login_form`` and Argo CD's ``admin.enabled=false``.
# ─────────────────────────────────────────────────────────────────────────────


async def is_local_password_login_enabled() -> bool:
    """Return True when /proxy/login is allowed to accept a password.

    Order of precedence:
      1. env var ``MCP_PROXY_FORCE_LOCAL_PASSWORD=1`` → always True (break-glass)
      2. stored flag ``proxy_config.local_password_enabled``
         - absent (new install / pre-toggle proxy) → True (retro-compat)
         - "1" → True, "0" → False

    The toggle is consulted on every request; no caching — the admin
    must be able to flip it off and see the form vanish immediately.
    """
    from mcp_proxy.config import get_settings
    if get_settings().force_local_password:
        return True

    from mcp_proxy.db import get_config
    stored = await get_config(LOCAL_PASSWORD_ENABLED_KEY)
    if stored is None:
        return True
    return stored == "1"


async def set_local_password_login_enabled(enabled: bool) -> None:
    """Persist the toggle. Caller is responsible for refusing to disable
    when no alternative sign-in path (OIDC) is configured — this function
    does not second-guess the caller to keep the CLI recovery path simple."""
    from mcp_proxy.db import set_config
    await set_config(LOCAL_PASSWORD_ENABLED_KEY, "1" if enabled else "0")
