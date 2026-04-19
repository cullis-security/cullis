"""
Dashboard session management — signed cookie-based authentication.

Single role: ``admin`` (network operator). The org-tenant role was removed —
tenants now log in on the per-org proxy (see ADR-001). Only the network
admin has a session on the broker dashboard.

The session is stored in a signed cookie (HMAC-SHA256). No server-side session
store needed — the cookie contains the role (always ``admin``), verified on
every request.

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

_COOKIE_NAME = "cullis_session"
_COOKIE_MAX_AGE = 8 * 3600  # 8 hours


@dataclass
class DashboardSession:
    role: str           # "admin" — org role removed in the network-admin-only refactor
    org_id: str | None  # always None for admin; kept for template compatibility
    csrf_token: str = ""
    logged_in: bool = True
    # Audit F-B-2 — per-org re-auth scope. Maps org_id → unix-epoch-seconds
    # expiry. When the admin completes a re-auth challenge for a specific
    # org, we stamp this map with ``now + REAUTH_TTL_SECONDS`` and re-issue
    # the session cookie. Mutations on a sealed org consult this map via
    # ``has_reauth_scope()``.
    reauth_orgs: dict[str, int] | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def has_reauth_scope(self, org_id: str) -> bool:
        """True iff the session holds an unexpired re-auth token for org_id."""
        if not self.reauth_orgs:
            return False
        exp = self.reauth_orgs.get(org_id, 0)
        return exp > int(time.time())


_NO_SESSION = DashboardSession(
    role="none", org_id=None, csrf_token="", logged_in=False, reauth_orgs=None,
)

# Audit F-B-2 — re-auth gate TTL. After completing a password re-challenge
# scoped to an org, the admin has this many seconds to issue mutations on
# the sealed org before having to re-authenticate. Kept short on purpose:
# this is a "break-glass" window, not a working mode.
REAUTH_TTL_SECONDS = 5 * 60  # 5 minutes

# Maximum number of concurrent per-org re-auth tokens we carry in the
# cookie. Bounded to keep the cookie size predictable (each entry is ~40
# bytes before signing). Oldest entries are evicted in FIFO order.
REAUTH_MAX_ENTRIES = 16


_auto_key: str = ""


def _load_or_create_signing_key_file(path: str) -> str:
    """Load a persisted signing key from ``path``, creating it (0600) if missing.

    Audit F-B-10 — the previous ``os.urandom`` fallback was in-memory-only, so
    every worker / replica had its own key and sessions broke on worker hop.
    Persisting the auto-generated key to disk makes it deterministic across
    workers (same filesystem → same key) and survives restarts without
    logging users out. File perms are 0600 so only the process UID can read
    it; the directory is created with 0700.
    """
    import pathlib
    p = pathlib.Path(path)
    if p.exists():
        # Existing key wins — reused across restarts + workers.
        return p.read_text().strip()
    # Create parent with tight perms if it doesn't exist yet.
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = os.urandom(32).hex()
    # Write atomically via temp file + rename so two workers starting at
    # the same time don't race on a half-written file.
    tmp = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(key)
    os.chmod(tmp, 0o600)
    try:
        os.rename(tmp, p)
    except OSError:
        # Another worker beat us to it — reread its key.
        try:
            tmp.unlink()
        except OSError:
            pass
        if p.exists():
            return p.read_text().strip()
        raise
    return key


def _get_secret() -> str:
    """Return a dedicated dashboard signing key, separate from admin_secret.

    Order of precedence (audit F-B-10):
      1. ``DASHBOARD_SIGNING_KEY`` env → wins. Recommended for prod.
      2. Persisted file at ``dashboard_signing_key_path`` → dev fallback,
         shared across workers and restarts. Auto-created on first call.
      3. Legacy in-memory ``os.urandom`` — only when file cannot be
         written (e.g. read-only FS in a sandbox test). Logs a warning.
    """
    global _auto_key
    from app.config import get_settings
    settings = get_settings()
    if settings.dashboard_signing_key:
        return settings.dashboard_signing_key
    # File-backed auto key — consulted even after an in-memory fallback
    # fired once, so a later write recovers determinism.
    key_path = settings.dashboard_signing_key_path
    if key_path:
        try:
            key = _load_or_create_signing_key_file(key_path)
            if key:
                _auto_key = key
                return key
        except OSError as exc:
            _log.warning(
                "Could not persist dashboard signing key to %s (%s) — "
                "falling back to per-process key. Sessions will not "
                "survive restart or span multiple workers. Fix by "
                "setting DASHBOARD_SIGNING_KEY or making the path "
                "writable (audit F-B-10).",
                key_path, exc,
            )
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

    # Only admin sessions are valid on the broker dashboard. Legacy org cookies
    # (pre network-admin-only refactor) are treated as logged-out.
    role = data.get("role", "none")
    if role != "admin":
        return _NO_SESSION

    raw_reauth = data.get("reauth_orgs") or {}
    # Defensively coerce to dict[str, int] and drop expired entries at
    # read time — keeps the cookie small and avoids trusting future work
    # to do the cleanup.
    now = int(time.time())
    reauth_orgs: dict[str, int] = {}
    if isinstance(raw_reauth, dict):
        for k, v in raw_reauth.items():
            try:
                exp = int(v)
            except (TypeError, ValueError):
                continue
            if isinstance(k, str) and exp > now:
                reauth_orgs[k] = exp

    return DashboardSession(
        role=role,
        org_id=None,
        csrf_token=data.get("csrf_token", ""),
        logged_in=True,
        reauth_orgs=reauth_orgs or None,
    )


def set_session(response: Response, role: str = "admin", org_id: str | None = None) -> str:
    """Set a signed session cookie on the response. Returns the CSRF token.

    Only ``role="admin"`` is valid on the broker dashboard. Any other role
    is rejected so a legacy code path cannot silently mint an org session.
    """
    if role != "admin":
        raise ValueError(
            f"Invalid dashboard role {role!r}: the broker dashboard is network-admin only."
        )
    # org_id is accepted only for backward compatibility; it is never used.
    csrf_token = os.urandom(16).hex()
    payload = json.dumps({
        "role": role,
        "org_id": None,
        "csrf_token": csrf_token,
        "exp": int(time.time()) + _COOKIE_MAX_AGE,
        "reauth_orgs": {},
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


def add_reauth_scope(
    response: Response, session: DashboardSession, org_id: str,
    ttl_seconds: int = REAUTH_TTL_SECONDS,
) -> None:
    """Stamp a per-org re-auth token into the session cookie.

    Audit F-B-2 — called after the admin has proven password ownership
    for a scoped mutation on a sealed org. Re-issues the session cookie
    preserving the existing CSRF token so in-flight form submissions
    keep working. Evicts the oldest entries if we hit
    ``REAUTH_MAX_ENTRIES`` to bound the cookie size.
    """
    if not session.is_admin:
        raise ValueError("add_reauth_scope called on a non-admin session")
    existing = dict(session.reauth_orgs or {})
    now = int(time.time())
    # Drop already-expired entries before we add a new one.
    existing = {k: v for k, v in existing.items() if v > now}
    existing[org_id] = now + ttl_seconds
    # Bound cookie size — oldest-expiry-first eviction.
    if len(existing) > REAUTH_MAX_ENTRIES:
        sorted_items = sorted(existing.items(), key=lambda kv: kv[1], reverse=True)
        existing = dict(sorted_items[:REAUTH_MAX_ENTRIES])

    payload = json.dumps({
        "role": session.role,
        "org_id": None,
        "csrf_token": session.csrf_token,
        "exp": now + _COOKIE_MAX_AGE,
        "reauth_orgs": existing,
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


# ── OIDC flow state cookie ──────────────────────────────────────────────────
_OIDC_STATE_COOKIE = "cullis_oidc_state"
_OIDC_STATE_MAX_AGE = 600  # 10 minutes


def set_oidc_state(response: Response, flow_state: dict) -> None:
    """Store the OIDC flow state in a short-lived signed cookie."""
    flow_state["exp"] = int(time.time()) + _OIDC_STATE_MAX_AGE
    payload = json.dumps(flow_state)
    signed = _sign(payload)
    from app.config import get_settings
    is_https = "https" in get_settings().broker_public_url.lower() if get_settings().broker_public_url else False
    response.set_cookie(
        _OIDC_STATE_COOKIE, signed,
        max_age=_OIDC_STATE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=is_https,
    )


def get_oidc_state(request: Request) -> dict | None:
    """Read and verify the OIDC state cookie. Returns None if missing/invalid/expired."""
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
    from app.config import get_settings
    is_https = "https" in get_settings().broker_public_url.lower() if get_settings().broker_public_url else False
    response.delete_cookie(_OIDC_STATE_COOKIE, samesite="lax", secure=is_https)


async def verify_csrf(request: Request, session: DashboardSession) -> bool:
    """Verify the CSRF token from the form matches the one in the session cookie."""
    form = await request.form()
    token = form.get("csrf_token", "")
    if not session.csrf_token or not token:
        return False
    return hmac.compare_digest(str(token), session.csrf_token)
