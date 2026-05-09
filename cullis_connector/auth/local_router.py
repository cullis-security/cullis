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
from cullis_connector.identity.cert_session_map import (
    delete_binding,
    derive_session_id,
    record_binding,
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
    else:
        provisioning, provisioning_detail = await _bind_login_cert(
            request, payload,
        )

    body_out = LoginResponse(
        ok=True,
        must_change_password=payload.must_change_password,
        principal_name=payload.principal_name,
        exp=payload.exp,
        provisioning=provisioning,
    )
    response = JSONResponse(body_out.model_dump())
    if provisioning == "deferred":
        # Header is the SPA's signal to render the banner — the body
        # already carries the same info but headers survive any caller
        # that strips JSON fields it does not recognise.
        response.headers["X-Cullis-Provisioning-Failed"] = "true"
        if provisioning_detail:
            # Truncate to keep the header well under 2KB; the full
            # detail is in the audit log + Mastio side.
            response.headers["X-Cullis-Provisioning-Detail"] = (
                provisioning_detail[:256]
            )
    _set_cookie(response, cookie_value)
    _record_login_attempt(ip, body.user_name, success=True)
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
                provisioning_detail[:256]
            )
    _set_cookie(response, cookie_value)
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
        headers["X-Cullis-Provisioning-Detail"] = detail[:256]
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
