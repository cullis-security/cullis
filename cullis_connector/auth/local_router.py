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
import time

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from pydantic import BaseModel, Field

from cullis_connector.ambassador.shared.wire import bootstrap_cookie_secret
from cullis_connector.identity.oidc_session import OidcSession, save_session
from cullis_connector.identity.cert_session_map import (
    delete_binding,
    derive_session_id,
    record_binding,
)
from cullis_connector.identity.audit import (
    log_lockout_trigger,
    log_login_attempt,
    log_password_change,
)
from cullis_connector.identity.csr_flow import (
    LocalProvisioningError,
    LocalUserProvisioner,
)
from cullis_connector.identity.local_session import (
    LOCAL_SESSION_COOKIE_NAME,
    LOCAL_SESSION_TTL_SEC,
    LocalSessionPayload,
    build_payload,
    issue_local_cookie,
    parse_local_cookie,
)
from cullis_connector.identity.lockout import (
    is_locked,
    record_failure,
    record_success,
)
from cullis_connector.identity.users import (
    MIN_PASSWORD_LENGTH,
    count_users,
    create_user,
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


# ── Phase 4 wire-up (ADR-025 Phase 5, F4 R3) ─────────────────────────────
#
# Replaces the Phase-2 stubs that no-op'd lockout + audit accounting.
# Both helpers live in ``cullis_connector.identity`` and share state
# with the rest of the local-auth stack (admin disable, audit query,
# Frontdesk dashboard).
#
# The helpers below intentionally collapse every failure path to a log
# breadcrumb rather than re-raising. A login flow that 500s because the
# audit DB hiccupped is worse than a login flow that succeeds but
# leaves a faint trace — the audit log is observability, not a gate.


def _now_epoch() -> float:
    """Wall-clock epoch seconds. Wrapped so tests can monkey-patch."""
    return time.time()


async def _check_lockout(ip: str) -> float | None:
    """Return the unlock-time epoch when ``ip`` is locked, else ``None``.

    Wraps :func:`cullis_connector.identity.lockout.is_locked` so the
    call site stays terse and the stub-shape (`async` with a single ip
    arg) is unchanged from the Phase-2 placeholder.
    """
    try:
        return await is_locked(ip)
    except Exception as exc:  # noqa: BLE001 — fail-open on lockout I/O
        _log.warning("lockout probe failed for ip=%s: %s", ip, exc)
        return None


async def _record_login_attempt(
    config_dir: Path,
    *,
    ip: str,
    user_name: str | None,
    success: bool,
    reason: str = "",
) -> None:
    """Audit one login attempt + update the lockout counter.

    On success: ``log_login_attempt(status='ok')`` + ``record_success``
    so the IP's failure run resets. On failure: ``log_login_attempt(
    status='fail')`` + ``record_failure``; when the lockout threshold
    trips we also emit ``log_lockout_trigger`` so a reviewer can
    correlate the 429 wave back to the offending IP.
    """
    status_str = "ok" if success else "fail"
    try:
        await log_login_attempt(
            config_dir,
            ip=ip,
            user_name=user_name,
            status=status_str,
            reason=reason,
        )
    except Exception as exc:  # noqa: BLE001 — audit best-effort
        _log.warning(
            "audit write failed user_name=%s ip=%s success=%s: %s",
            user_name, ip, success, exc,
        )

    try:
        if success:
            await record_success(ip)
        else:
            _count, unlock_at = await record_failure(ip, user_name)
            if unlock_at is not None:
                try:
                    await log_lockout_trigger(
                        config_dir,
                        ip=ip,
                        locked_until=unlock_at,
                        user_name=user_name,
                    )
                except Exception as exc:  # noqa: BLE001 — audit best-effort
                    _log.warning(
                        "lockout audit write failed ip=%s: %s", ip, exc,
                    )
    except Exception as exc:  # noqa: BLE001 — lockout state I/O failure
        _log.warning(
            "lockout counter update failed ip=%s success=%s: %s",
            ip, success, exc,
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
    # ADR-025 Phase 3 — post-login Mastio CSR result.
    #
    #   "ok"       — cert minted + bound to session, /v1/* ready to go
    #   "deferred" — Mastio refused / unreachable; password verification
    #                still succeeded so the cookie is issued, but
    #                /v1/* will return 502 until /api/auth/reprovision
    #                eventually succeeds. The SPA reads
    #                ``X-Cullis-Provisioning-Failed: true`` to surface
    #                a banner.
    #   "skipped"  — local provisioner not wired on this app (e.g. the
    #                connector identity isn't on disk yet, or
    #                local-mode boot bailed out). Login still works,
    #                /v1/* is gated upstream.
    provisioning: str = "skipped"
    # ADR-025 Phase 5 / F4 R3 — Mastio attribution call result for the
    # user_sessions row that lets downstream audit pick up
    # ``on_behalf_of_user_id``. Same three states as ``provisioning``;
    # the two calls are independent because the cert + the session row
    # serve different layers (transport vs audit), and one can succeed
    # while the other fails (e.g. cert cache hit + Mastio attribution
    # endpoint hiccup).
    attribution: str = "skipped"


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
    # ADR-025 Phase 5 / F4 R3 — flips to True when ``users.db`` is empty
    # on a Connector desktop install so the SPA renders the owner-setup
    # form instead of the login form. Probe is intentionally on the
    # public ``/api/auth/runtime-info`` endpoint so the bootstrap can
    # decide before it has any cookie.
    setup_required: bool = False
    setup_url: str = "/api/auth/first-run-setup"
    # P3 MAJOR-1-rest — IT-support email surfaced behind the
    # "Forgot password?" affordance on the SPA login form. Empty
    # string when ``CULLIS_FRONTDESK_SUPPORT_EMAIL`` is unset; the
    # SPA then renders a CLI-hint fallback instead of a mailto link.
    # No-auth is fine: this is the same kind of public hint as
    # ``login_url`` (any visitor of the login page already sees the
    # configured email rendered into a mailto by the server-side
    # template).
    support_email: str = ""


class FirstRunSetupRequest(BaseModel):
    """Body for ``POST /api/auth/first-run-setup``.

    Same validation envelope as ``LoginRequest`` so the SPA can reuse
    its existing field-error renderer. ``display_name`` is optional.
    """

    user_name: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=4096)
    display_name: str = Field(default="", max_length=255)


class ReprovisionResponse(BaseModel):
    """Manual retry result for ``POST /api/auth/reprovision``.

    Returns ``ok=True`` when a cert is now bound, ``ok=False`` with a
    short ``detail`` when Mastio refused (the SPA shows the banner
    again). Idempotent — a hit on a still-valid cache entry returns
    ``ok=True`` with ``cached=True``.
    """

    ok: bool
    cached: bool = False
    principal_id: str = ""
    detail: str = ""


# ── Helpers ──────────────────────────────────────────────────────────────


def _sanitize_header_value(value: str, *, max_len: int = 256) -> str:
    """Strip CR/LF/control bytes + truncate so the value is a legal HTTP header.

    RFC 7230 §3.2.6 forbids CR/LF inside a header value; uvicorn rejects
    such a value with ``RuntimeError: Invalid HTTP header value``. The
    deferred-provisioning detail we echo back to the SPA comes from
    ``str(exc)`` on an underlying httpx error, and httpx multi-line
    error formatting (e.g. ``"... 400 Bad Request ...\\nFor more
    information check: https://..."``) leaks the LF straight through.
    """
    sanitized = "".join(
        " " if (ord(c) < 0x20 or ord(c) == 0x7F) else c
        for c in value
    )
    # Latin-1 is uvicorn's wire encoding for headers. Replace any
    # non-latin1 codepoint with '?' rather than blowing up.
    sanitized = sanitized.encode("latin-1", errors="replace").decode("latin-1")
    return sanitized[:max_len].strip()


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


def _mint_ambassador_bearer_cookie(
    response: Response, config_dir: Path,
) -> None:
    """Seed the ``cullis_session`` cookie with the Connector LOCAL_TOKEN.

    Twin of ``_set_cookie`` for the Ambassador's bearer surface. In shared
    mode the Ambassador's ``POST /api/session/init`` minted this cookie;
    ADR-025 deprecated that endpoint but didn't replace the cookie-mint
    behaviour, leaving ``/v1/chat/completions`` 401 on every SPA call
    after a local-auth login. Best-effort: if the local token can't be
    read (pre-enrollment, identity dir missing), we log and continue —
    the rest of the login flow still succeeds, just the chat surface
    will refuse until the next successful login after enrollment.
    """
    try:
        from cullis_connector.ambassador.auth import (
            LOCAL_SESSION_COOKIE as _AMBASSADOR_COOKIE_NAME,
            ensure_local_token,
        )
        bearer = ensure_local_token(config_dir)
    except Exception as exc:  # noqa: BLE001 — best effort, login still wins
        _log.warning(
            "could not mint Ambassador bearer cookie: %s", exc,
        )
        return
    response.set_cookie(
        _AMBASSADOR_COOKIE_NAME,
        bearer,
        max_age=LOCAL_SESSION_TTL_SEC,
        httponly=True,
        samesite="strict",
        secure=_is_secure_cookie(),
        path="/",
    )


def _clear_ambassador_bearer_cookie(response: Response) -> None:
    """Mirror of :func:`_clear_cookie` for the Ambassador bearer cookie."""
    try:
        from cullis_connector.ambassador.auth import (
            LOCAL_SESSION_COOKIE as _AMBASSADOR_COOKIE_NAME,
        )
    except Exception:  # noqa: BLE001 — best effort
        return
    response.set_cookie(
        _AMBASSADOR_COOKIE_NAME,
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


def _local_provisioner(request: Request) -> LocalUserProvisioner | None:
    """Return the bound :class:`LocalUserProvisioner` or ``None`` when not wired.

    The Connector boot path (``web.build_app``) seeds
    ``app.state.local_provisioner`` only when local-mode is active AND
    the agent identity is on disk. Pre-enrollment dashboards or non-
    local-mode deploys leave it ``None`` so the login router can still
    hand out cookies (the password check is independent of CSR).
    """
    return getattr(request.app.state, "local_provisioner", None)


async def _bind_login_cert(
    request: Request,
    payload: LocalSessionPayload,
) -> tuple[str, str | None]:
    """Provision + persist a cert for ``payload``. Return ``(status, detail)``.

    ``status`` is one of:

      - ``"ok"``       cert minted (or cache-hit) + persistence row written
      - ``"deferred"`` Mastio refused; cookie still issued, banner state
                       returned to the SPA via header + body
      - ``"skipped"``  no provisioner wired on this app

    The function is forgiving by design: every failure mode collapses
    to ``deferred`` rather than raising, so the login flow never
    crashes mid-flight just because the Mastio is unreachable. The
    original exception detail is bubbled up so an operator can
    correlate against the Mastio audit log.
    """
    provisioner = _local_provisioner(request)
    if provisioner is None:
        return "skipped", None
    try:
        cred = await provisioner.provision_for_user(payload.user_name)
    except LocalProvisioningError as exc:
        return "deferred", str(exc)
    except Exception as exc:  # noqa: BLE001 — defensive; never crash login
        _log.warning(
            "unexpected provisioning failure user_name=%s: %s",
            payload.user_name, exc,
        )
        return "deferred", str(exc)

    # Persist the binding so a Connector restart can re-resolve the
    # cookie → principal_id without re-asking the user.
    try:
        thumbprint = _cert_thumbprint(cred.cert_pem)
    except Exception as exc:  # noqa: BLE001 — best effort breadcrumb
        _log.warning(
            "could not compute cert thumbprint for %s: %s",
            cred.principal_id, exc,
        )
        thumbprint = ""
    session_id = derive_session_id(
        iat=payload.iat, user_name=payload.user_name,
    )
    try:
        await record_binding(
            _config_dir(request),
            session_id=session_id,
            user_name=payload.user_name,
            principal_id=cred.principal_id,
            cert_thumbprint=thumbprint,
            cert_not_after=cred.cert_not_after.isoformat(),
        )
    except Exception as exc:  # noqa: BLE001 — DB hiccup still leaves
        # the cert in the in-process cache so /v1/* works for the
        # current process; rebind on next login.
        _log.warning(
            "could not persist cert binding for %s: %s",
            cred.principal_id, exc,
        )
    return "ok", None


async def _bind_mastio_user_session(
    request: Request,
    *,
    user_name: str,
    display_name: str | None,
    device_thumbprint: str,
) -> tuple[str, str | None]:
    """Call the Mastio attribution endpoint and persist the returned session.

    ADR-025 Phase 5 / F4 R3. Returns ``(status, detail)`` where status
    is one of:

      - ``"ok"``       — session minted + persisted under
                         ``<config_dir>/oidc_session.json`` so the
                         downstream MCP envelope layer (R2) picks up
                         ``X-Cullis-Session-Token`` automatically.
      - ``"deferred"`` — Mastio refused / unreachable. The user login
                         is still considered successful; subsequent
                         MCP traffic falls back to agent-only audit
                         attribution until the next login retry.
      - ``"skipped"``  — no Mastio CSR transport on this app (pre-
                         enrollment dashboard, dev mode).

    All exceptions collapse to ``deferred`` so a Mastio outage cannot
    take down the dashboard login.
    """
    transport = getattr(request.app.state, "local_csr_transport", None)
    if transport is None or not device_thumbprint:
        return "skipped", None

    try:
        user_id, session_token, expires_at = await transport.attribute_local_login(
            local_subject=user_name,
            display_name=display_name,
            device_cert_thumbprint=device_thumbprint,
        )
    except Exception as exc:  # noqa: BLE001 — degrade, don't crash login
        _log.warning(
            "Mastio local-login attribution failed user_name=%s: %s",
            user_name, exc,
        )
        return "deferred", str(exc)

    try:
        save_session(
            _config_dir(request),
            OidcSession(
                user_id=user_id,
                session_token=session_token,
                sso_subject=f"local:{user_name}",
                idp_issuer="local",
                display_name=display_name,
                expires_at=expires_at,
                device_thumbprint=device_thumbprint,
                source="local",
            ),
        )
    except Exception as exc:  # noqa: BLE001 — persistence best-effort
        _log.warning(
            "Mastio attribution session persist failed user_name=%s: %s",
            user_name, exc,
        )
        # The session is still valid in-memory on the Mastio; we just
        # won't auto-attach on Connector restart. Treat as ok for the
        # current process so the user isn't bounced.
        return "ok", None

    return "ok", None


def _cert_thumbprint(cert_pem: str) -> str:
    """SHA-256 hex of the cert DER. Lazily import cryptography so a
    test that monkey-patches the provisioner does not pull
    ``cryptography`` into module import.
    """
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


# ── Server-side fallback HTML ────────────────────────────────────────────


# Cap on ``?user_name=`` echoed into the mailto subject — mirrors
# ``LoginRequest`` so an attacker-controlled query cannot bloat the
# rendered href. Jinja autoescape handles HTML; ``urlencode`` handles
# CR/LF mailto-header-injection.
_FORGOT_USER_NAME_MAX_LEN = 64


def _support_email(env: dict[str, str] | None = None) -> str:
    """``CULLIS_FRONTDESK_SUPPORT_EMAIL`` or empty string when unset."""
    src = env if env is not None else os.environ
    return (src.get("CULLIS_FRONTDESK_SUPPORT_EMAIL", "") or "").strip()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    """Plain HTML form for non-SPA clients + ops debug."""
    raw = request.query_params.get("user_name", "")
    user_name_hint = raw.strip()[:_FORGOT_USER_NAME_MAX_LEN]
    return _templates.TemplateResponse(
        request,
        "login.html",
        {
            "connector_status": "offline",
            "connector_status_label": "Sign in",
            "error": None,
            "support_email": _support_email(),
            "user_name_hint": user_name_hint,
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
    config_dir = _config_dir(request)
    locked_until = await _check_lockout(ip)
    if locked_until is not None:
        # 429 with Retry-After lets a well-behaved client back off
        # without re-probing the password endpoint on a tight loop.
        retry_after = max(1, int(locked_until - _now_epoch()))
        await _record_login_attempt(
            config_dir,
            ip=ip,
            user_name=body.user_name,
            success=False,
            reason="locked",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts",
            headers={"Retry-After": str(retry_after)},
        )

    async with get_users_session(config_dir) as session:
        user = await get_user_by_name(session, body.user_name)
        if user is None or user.disabled:
            await _record_login_attempt(
                config_dir,
                ip=ip,
                user_name=body.user_name,
                success=False,
                reason="unknown_or_disabled",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
            )
        ok = await verify_password(session, body.user_name, body.password)
    if not ok:
        await _record_login_attempt(
            config_dir,
            ip=ip,
            user_name=body.user_name,
            success=False,
            reason="bad_password",
        )
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

    # ADR-025 Phase 3 — post-login UserPrincipal CSR. Best-effort: a
    # Mastio outage degrades to ``provisioning="deferred"`` rather
    # than rejecting the login (the password was correct). The SPA
    # surfaces a banner from the response header so the user knows
    # ``/v1/*`` will 502 until reprovisioning succeeds.
    if user.must_change_password:
        # Skip the CSR roundtrip when the user is being bounced to
        # /change-password — we'll mint after the password change so
        # the cert is bound to the post-change session, not a session
        # that's about to be replaced.
        provisioning = "skipped"
        provisioning_detail: str | None = None
        attribution_status: str = "skipped"
    else:
        provisioning, provisioning_detail = await _bind_login_cert(
            request, payload,
        )
        # ADR-025 Phase 5 / F4 R3 — alongside the CSR, ask Mastio to
        # mint a ``user_sessions`` row attributing future MCP calls
        # from this Connector to the user_name we just authenticated.
        # Best-effort: a Mastio outage degrades to "deferred" and the
        # cert middleware can still serve ``/v1/*`` (the audit row
        # just won't carry ``on_behalf_of_user_id`` until next login).
        device_thumbprint = ""
        try:
            from cullis_connector.identity.store import load_identity
            bundle = load_identity(_config_dir(request))
            if bundle.cert_pem:
                device_thumbprint = _cert_thumbprint(bundle.cert_pem)
        except Exception as exc:  # noqa: BLE001 — pre-enrollment ok
            _log.debug(
                "F4 R3: no device cert thumbprint resolvable yet: %s", exc,
            )
        attribution_status, _attribution_detail = await _bind_mastio_user_session(
            request,
            user_name=payload.user_name,
            display_name=user.display_name,
            device_thumbprint=device_thumbprint,
        )

    body_out = LoginResponse(
        ok=True,
        must_change_password=payload.must_change_password,
        principal_name=payload.principal_name,
        exp=payload.exp,
        provisioning=provisioning,
        attribution=attribution_status,
    )
    response = JSONResponse(body_out.model_dump())
    if provisioning == "deferred":
        # Header is the SPA's signal to render the banner — the body
        # already carries the same info but headers survive any caller
        # that strips JSON fields it does not recognise.
        response.headers["X-Cullis-Provisioning-Failed"] = "true"
        if provisioning_detail:
            response.headers["X-Cullis-Provisioning-Detail"] = (
                _sanitize_header_value(provisioning_detail)
            )
    _set_cookie(response, cookie_value)
    # Mint the Ambassador bearer cookie alongside the local-auth session
    # cookie. Pre-fix the SPA could log in (`cullis_local_session` set
    # by the line above) but every call to `/v1/chat/completions` or
    # `/v1/models` returned 401, because Ambassador's `require_bearer`
    # only accepts `Authorization: Bearer <local-token>` or the cookie
    # `cullis_session=<local-token>` — neither of which the local-auth
    # login flow ever issued. In shared mode (legacy) `POST
    # /api/session/init` minted that cookie; ADR-025 deprecated that
    # endpoint without replacing the cookie-mint behaviour, so the chat
    # surface broke silently. The bearer is identical on disk
    # (`local.token`) regardless of auth mode, so we read it through
    # `ensure_local_token` and seed the cookie here. The per-user
    # identity for the audit row is still resolved by `cert_middleware`
    # off `cullis_local_session`; this cookie is only "you reached the
    # right Connector box".
    _mint_ambassador_bearer_cookie(response, config_dir)
    await _record_login_attempt(
        config_dir,
        ip=ip,
        user_name=body.user_name,
        success=True,
        reason=provisioning,
    )
    # Never log the password — only the username + result.
    _log.info(
        "local login ok user_name=%s must_change=%s provisioning=%s",
        user.user_name, payload.must_change_password, provisioning,
    )
    return response


@router.post("/api/auth/logout")
async def logout(request: Request) -> JSONResponse:
    """Invalidate the cookie + drop the persisted cert binding.

    No-op when called without a cookie. We deliberately keep the cert
    in the in-process cache (it expires on TTL) so a follow-up login
    by the same user inside the cache window can fast-path. The
    persisted binding row is dropped here so a forensic dump of
    users.db cannot link a cookie that was logged out to its cert.
    """
    raw = request.cookies.get(LOCAL_SESSION_COOKIE_NAME, "")
    if raw:
        secret = _cookie_secret(request)
        payload = parse_local_cookie(raw, secret)
        if payload is not None:
            session_id = derive_session_id(
                iat=payload.iat, user_name=payload.user_name,
            )
            try:
                async with get_users_session(_config_dir(request)) as session:
                    await delete_binding(session, session_id)
            except Exception as exc:  # noqa: BLE001 — best effort
                _log.warning(
                    "could not delete cert binding for %s: %s",
                    payload.user_name, exc,
                )
    response = JSONResponse({"ok": True})
    _clear_cookie(response)
    _clear_ambassador_bearer_cookie(response)
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

    # F4 R3 — emit a pw.change audit row. Never carries the password
    # value (only the user_name); a Connector compromise that gains
    # SQL write still cannot rewrite it because the audit table has
    # a RAISE FAIL trigger on UPDATE/DELETE.
    try:
        await log_password_change(config_dir, user_name=payload.user_name)
    except Exception as exc:  # noqa: BLE001 — audit best-effort
        _log.warning(
            "pw.change audit write failed user_name=%s: %s",
            payload.user_name, exc,
        )

    new_payload = build_payload(
        user_name=payload.user_name,
        must_change_password=False,
        principal_name=payload.principal_name,
    )
    secret = _cookie_secret(request)
    cookie_value = issue_local_cookie(new_payload, secret)

    # ADR-025 Phase 3 — first-login flow ends here; mint the cert now
    # that the post-change session exists. Same deferred-on-failure
    # semantics as ``/api/auth/login`` so a Mastio outage doesn't
    # invalidate a successful password rotation.
    provisioning, provisioning_detail = await _bind_login_cert(
        request, new_payload,
    )

    body_out = ChangePasswordResponse(
        ok=True,
        must_change_password=False,
        principal_name=new_payload.principal_name,
        exp=new_payload.exp,
    )
    response = JSONResponse(body_out.model_dump())
    if provisioning == "deferred":
        response.headers["X-Cullis-Provisioning-Failed"] = "true"
        if provisioning_detail:
            response.headers["X-Cullis-Provisioning-Detail"] = (
                _sanitize_header_value(provisioning_detail)
            )
    _set_cookie(response, cookie_value)
    _mint_ambassador_bearer_cookie(response, _config_dir(request))
    _log.info(
        "local password changed user_name=%s provisioning=%s",
        payload.user_name, provisioning,
    )
    return response


@router.post("/api/auth/reprovision", response_model=ReprovisionResponse)
async def reprovision(request: Request) -> JSONResponse:
    """Manual retry for a deferred CSR call.

    Idempotent — calls into :class:`UserProvisioner.get_or_provision`
    so a still-valid cache hit returns ``ok=True`` without touching
    Mastio. The SPA renders a "retry now" button when it sees
    ``provisioning="deferred"`` on login; that button hits this
    endpoint.

    Returns 502 when the underlying provisioner errors out so the
    SPA's banner stays visible until Mastio recovers. The cookie is
    not touched (still valid; only the cert binding was missing).
    """
    payload = await _require_local_session(request)
    provisioner = _local_provisioner(request)
    if provisioner is None:
        body = ReprovisionResponse(
            ok=False,
            detail="local provisioner not configured on this Connector",
        )
        return JSONResponse(body.model_dump(), status_code=503)

    # Cache check first so an immediate retry after a successful login
    # does not double-call Mastio. ``get`` is async-safe and lazy-
    # expires entries past their ``not_after``.
    coords = provisioner.coordinates_for(payload.user_name)
    cached = await provisioner.cache.get(coords.principal_id)
    if cached is not None:
        body = ReprovisionResponse(
            ok=True,
            cached=True,
            principal_id=cached.principal_id,
        )
        return JSONResponse(body.model_dump())

    status_str, detail = await _bind_login_cert(request, payload)
    if status_str == "ok":
        body = ReprovisionResponse(
            ok=True,
            cached=False,
            principal_id=coords.principal_id,
        )
        return JSONResponse(body.model_dump())
    body = ReprovisionResponse(
        ok=False,
        cached=False,
        principal_id=coords.principal_id,
        detail=detail or "provisioning failed",
    )
    headers: dict[str, str] = {"X-Cullis-Provisioning-Failed": "true"}
    if detail:
        headers["X-Cullis-Provisioning-Detail"] = _sanitize_header_value(detail)
    return JSONResponse(
        body.model_dump(),
        status_code=502,
        headers=headers,
    )


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
async def runtime_info(request: Request) -> RuntimeInfoResponse:
    """Public hint for the SPA bootstrap: which login flow to render.

    Intentionally no-auth so the SPA can fetch this before it has any
    cookie. Returns only public-safe metadata (URL paths, mode name,
    setup state).

    ``setup_required`` is a public boolean — knowing whether a fresh
    Connector install has zero users does not leak anything an attacker
    couldn't infer from observing 401-on-every-login. Treating the DB
    probe as a hard failure would force the SPA to render an unusable
    page, so a probe error falls back to ``False`` and the SPA shows
    the regular login (a missing user surfaces as the usual 401).
    """
    # Hardcoded "local" because this router is only mounted in
    # local mode by ``build_app``. Callers in shared/oidc mode get
    # 404 from FastAPI (no router mounted) — the SPA detects this and
    # falls back to the SSO bootstrap path.
    setup_required = False
    try:
        config_dir = _config_dir(request)
        async with get_users_session(config_dir) as session:
            setup_required = await count_users(session) == 0
    except Exception as exc:  # noqa: BLE001 — probe must not 500
        _log.warning("runtime-info: users.db probe failed: %s", exc)
    return RuntimeInfoResponse(
        auth_mode="local",
        login_url="/login",
        require_change_password_url="/change-password",
        setup_required=setup_required,
        support_email=_support_email(),
    )


@router.post("/api/auth/first-run-setup", response_model=LoginResponse)
async def first_run_setup(
    body: FirstRunSetupRequest, request: Request,
) -> JSONResponse:
    """ADR-025 Phase 5 / F4 R3 — create the owner user on a fresh install.

    Only succeeds when ``users.db`` is empty. The new account is
    created with ``must_change_password=False`` because the operator
    just picked the password interactively — forcing them through a
    second change form on the next request would be hostile UX. The
    response shape mirrors :class:`LoginResponse` so the SPA can reuse
    its post-login handler.

    Refuses with 409 once any user exists. That keeps the endpoint
    safe to leave mounted in production: a leaked URL cannot be used
    to mint an admin on a long-running Connector.

    No lockout / audit on the setup path itself — there is no prior
    state to brute-force against, and the audit table is created on
    the first login attempt downstream.
    """
    config_dir = _config_dir(request)
    async with get_users_session(config_dir) as session:
        if await count_users(session) != 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="setup already completed",
            )
        try:
            user = await create_user(
                session,
                name=body.user_name,
                password=body.password,
                must_change=False,
                display_name=body.display_name,
            )
        except ValueError as exc:
            # password/username rule failure — surface verbatim so the
            # SPA can render a useful field error.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )

    payload = build_payload(
        user_name=user.user_name,
        must_change_password=False,
    )
    secret = _cookie_secret(request)
    cookie_value = issue_local_cookie(payload, secret)

    body_out = LoginResponse(
        ok=True,
        must_change_password=False,
        principal_name=payload.principal_name,
        exp=payload.exp,
        # Setup deliberately does NOT mint a CSR or attribute the
        # session on Mastio: the Connector may not yet have its agent
        # cert when the wizard runs, and even when it does, deferring
        # provisioning to the next user-initiated request keeps the
        # blast radius of a Mastio outage contained to the next
        # request rather than the setup itself.
        provisioning="skipped",
    )
    response = JSONResponse(body_out.model_dump(), status_code=201)
    _set_cookie(response, cookie_value)
    _mint_ambassador_bearer_cookie(response, _config_dir(request))
    _log.info(
        "first-run setup completed user_name=%s", user.user_name,
    )
    return response


__all__ = [
    "_require_local_session",
    "router",
]
