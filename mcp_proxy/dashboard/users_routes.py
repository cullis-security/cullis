"""Mastio dashboard, Users sub-router.

Sprint F-B-201 PR-11 of 13. Extracts the multi-user admin surface
(list + create + per-user lifecycle: reset-password,
provision-to-frontdesk, delete, reset-tofu-pin) from the
``mcp_proxy/dashboard/router.py`` god-object. Seven routes total.

Mounted via ``router.include_router(users_routes.router)``.

Routes (7):

  GET  /proxy/users                                       merged user list
  POST /proxy/users/create                                create user (two paths)
  GET  /proxy/users/{principal_id}                        per-user detail page
  POST /proxy/users/{principal_id}/reset-password         force reset on Frontdesk
  POST /proxy/users/{principal_id}/provision-to-frontdesk promote registry-only to Frontdesk
  POST /proxy/users/{principal_id}/delete                 lifecycle delete (approval-hook)
  POST /proxy/users/{principal_id}/reset-tofu-pin         clear TOFU-pinned pubkey

Mastio is the identity authority (principal registry, audit attribution,
cert authority). The Frontdesk Ambassador owns the credential data plane
(``users.db``, bcrypt, password lifecycle). This module forwards
create/reset/delete to the Frontdesk over the loopback admin API and
keeps a Mastio attribution row in ``local_user_principals`` so the
dashboard renders both halves of the picture. ADR-020 multi-user
quadrant unchanged.
"""
from __future__ import annotations

import logging
import pathlib

import httpx

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_USERS_DELETE,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-users"])


# Users, control plane (Mastio) over the credential data plane (Frontdesk)
#
# The Mastio is the identity authority: it holds the principal registry,
# audit attribution, and the cert authority. It does NOT hold passwords.
# When the admin creates / resets / deletes a user from this dashboard,
# we forward the call to the Frontdesk Ambassador admin API (which owns
# users.db, bcrypt, lifecycle). The plaintext password is generated on
# the Mastio just-in-time, sent to the Frontdesk once over the loopback,
# surfaced to the admin once, and never persisted on this side.

# Single source of truth for "is the Frontdesk wiring configured?". Used
# by both the page template (to hide Create/Reset/Delete) and the POST
# handlers (to short-circuit with a clear error rather than crashing).
def _frontdesk_admin_target() -> tuple[str, str] | None:
    from mcp_proxy.config import get_settings
    s = get_settings()
    url = (s.frontdesk_ambassador_url or "").strip().rstrip("/")
    secret = (s.frontdesk_admin_secret or "").strip()
    if not url or not secret:
        return None
    return url, secret


def _frontdesk_verify_arg():
    """Return the ``verify=`` argument for the httpx call to the
    Frontdesk Ambassador.

    ``MCP_PROXY_FRONTDESK_CA_BUNDLE`` (path) wins when set; otherwise
    ``MCP_PROXY_FRONTDESK_VERIFY_TLS`` (bool, default ``true``)
    controls the standard-trust path. ``false`` means "skip
    verification", fine for the libvirt dogfood and any deployment
    that fronts the Ambassador with a self-signed sidecar; production
    deployments behind a real CA leave the default.
    """
    from mcp_proxy.config import get_settings
    s = get_settings()
    bundle = (s.frontdesk_ca_bundle or "").strip()
    if bundle:
        return bundle
    return bool(s.frontdesk_verify_tls)


async def _fetch_frontdesk_users() -> dict[str, dict] | None:
    """Pull the canale's user list. Keyed by ``user_name`` for join.

    Returns ``None`` if the Frontdesk is not configured or unreachable,
    callers should fall back to the Mastio-local view in that case
    rather than rendering an empty page.
    """
    target = _frontdesk_admin_target()
    if target is None:
        return None
    url, secret = target
    try:
        async with httpx.AsyncClient(
            timeout=5.0, verify=_frontdesk_verify_arg(),
        ) as client:
            r = await client.get(
                f"{url}/admin/users",
                headers={"X-Admin-Secret": secret},
            )
        if r.status_code != 200:
            _log.warning(
                "frontdesk admin list failed: status=%s",
                r.status_code,
            )
            return None
        body = r.json()
    except Exception as exc:  # noqa: BLE001, wire-level failure
        _log.warning("frontdesk admin list error: %s", exc)
        return None
    return {u["user_name"]: u for u in body.get("users", [])}


async def _frontdesk_admin_call(
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
) -> tuple[int, dict | None, str | None]:
    """Thin httpx wrapper. Returns ``(status, json_or_none, error_str)``.

    ``error_str`` is None on transport success regardless of HTTP status;
    callers inspect ``status`` for app-level outcomes. A ``None`` body
    + non-None error means the call did not complete (DNS, connect,
    timeout), surface a generic message, do not stringify the
    exception into the browser.
    """
    target = _frontdesk_admin_target()
    if target is None:
        return 0, None, "frontdesk_not_configured"
    url, secret = target
    try:
        async with httpx.AsyncClient(
            timeout=10.0, verify=_frontdesk_verify_arg(),
        ) as client:
            r = await client.request(
                method,
                f"{url}{path}",
                headers={
                    "X-Admin-Secret": secret,
                    "Content-Type": "application/json",
                },
                json=json_body,
            )
    except Exception as exc:  # noqa: BLE001
        _log.warning("frontdesk admin call %s %s failed: %s", method, path, exc)
        return 0, None, "transport_error"
    body: dict | None = None
    try:
        body = r.json() if r.content else None
    except Exception:
        body = None
    return r.status_code, body, None


async def _build_user_view() -> tuple[list[dict], bool]:
    """Merge Mastio principal registry + Frontdesk users.db.

    Mastio rows (``local_user_principals``) carry cert + last_active +
    surface. Frontdesk rows carry the credential state (has_password,
    must_change_password, disabled). One physical user shows up in both
    when they have signed in at least once; pre-seeded users live only
    on the Frontdesk side until first CSR. The merged view favours the
    Mastio row for principal_id / cert / surface and fills credential
    state from the Frontdesk.
    """
    try:
        from mcp_proxy.db import list_user_principals
        mastio_rows = await list_user_principals()
    except Exception as exc:  # noqa: BLE001
        _log.warning("users_page: list_user_principals failed: %s", exc)
        mastio_rows = []

    fd_users = await _fetch_frontdesk_users()
    fd_enabled = fd_users is not None
    fd_users = fd_users or {}

    # Derive org_id once so we can synthesize a principal_id for
    # Frontdesk-only rows. Read from the Mastio config; falls back to
    # an empty string if not yet configured (early first-boot path).
    from mcp_proxy.db import get_config
    try:
        org_id = await get_config("org_id") or ""
    except Exception:
        org_id = ""

    merged: list[dict] = []
    seen_user_names: set[str] = set()

    for row in mastio_rows:
        user_name = row.get("user_name") or ""
        seen_user_names.add(user_name)
        fd = fd_users.get(user_name, {})
        merged.append({
            "principal_id": row.get("principal_id"),
            "user_name": user_name,
            "display_name": fd.get("display_name") or row.get("display_name") or "",
            "reach": row.get("reach"),
            "surface": row.get("surface"),
            "cert_thumbprint": row.get("cert_thumbprint"),
            "pubkey_thumbprint": row.get("pubkey_thumbprint"),
            "created_at": row.get("created_at"),
            "last_active_at": row.get("last_active_at"),
            "in_frontdesk": user_name in fd_users,
            "has_password": bool(fd) if fd_enabled else False,
            "must_change_password": bool(fd.get("must_change_password")),
            "disabled": bool(fd.get("disabled")),
            "password_changed_at": fd.get("password_changed_at"),
        })

    # Frontdesk-only rows (no Mastio cert yet). Synthesize a placeholder
    # principal_id so the detail link works; once the user signs in and
    # the CSR endpoint fires, the real Mastio row supersedes this entry.
    for user_name, fd in fd_users.items():
        if user_name in seen_user_names:
            continue
        principal_id = f"{org_id}::user::{user_name}" if org_id else f"::user::{user_name}"
        merged.append({
            "principal_id": principal_id,
            "user_name": user_name,
            "display_name": fd.get("display_name", ""),
            "reach": "intra",
            "surface": "frontdesk",
            "cert_thumbprint": None,
            "pubkey_thumbprint": None,
            "created_at": fd.get("created_at"),
            "last_active_at": None,
            "in_frontdesk": True,
            "has_password": True,
            "must_change_password": bool(fd.get("must_change_password")),
            "disabled": bool(fd.get("disabled")),
            "password_changed_at": fd.get("password_changed_at"),
        })

    # Newest first.
    merged.sort(
        key=lambda u: u.get("created_at") or "",
        reverse=True,
    )
    return merged, fd_enabled


def _split_principal_id(principal_id: str) -> tuple[str, str]:
    """Pull ``(org_id, user_name)`` out of ``<org>::user::<name>``.

    Tolerates a missing org prefix (synthetic ids from frontdesk-only
    rows) and returns empty strings rather than raising so the caller
    can decide whether to 404.
    """
    if "::user::" in principal_id:
        head, name = principal_id.split("::user::", 1)
        return head, name
    return "", ""


@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    """Merged identity view: Mastio registry x Frontdesk Ambassador."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    users, fd_enabled = await _build_user_view()

    # Banners survive one render via query string (POST-redirect-GET).
    # ADR-034 follow-up, removed ``new_user_temp_password``: the
    # admin types the initial password themselves now, no server-
    # generated cleartext to surface.
    action_message = request.query_params.get("ok")
    error = request.query_params.get("error")

    return templates.TemplateResponse("users.html", _ctx(
        request, session,
        active="users",
        users=users,
        frontdesk_enabled=fd_enabled,
        action_message=action_message,
        error=error,
    ))


@router.post("/users/create")
async def users_create(request: Request):
    """Create a user. Two paths depending on the deployment topology:

    1. **Frontdesk Ambassador configured** (``MCP_PROXY_FRONTDESK_AMBASSADOR_URL``
       set): the Mastio mints a one-time temp password, forwards it to the
       Frontdesk together with the user metadata, surfaces it to the admin
       on the redirect, and forgets it. The Frontdesk's ``users.db`` holds
       the bcrypt hash; the Mastio never logs the value anywhere.

    2. **Registry-only fallback** (no Frontdesk, no SSO): writes a row in
       ``local_user_principals`` without any credential. Used when the
       deployment authenticates clients via ADR-027 ``culk_*`` API tokens,
       the admin pre-creates the user principal here, then mints a
       Bearer token from the user detail page's API Tokens tab. No
       password, no IdP, no temp credential to distribute. Workable for
       VPS demos where the customer points LibreChat / Cursor / Cherry
       Studio at the Mastio with token auth.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse("/proxy/users?error=csrf", status_code=303)

    form = await request.form()
    user_name = (form.get("user_name") or "").strip()
    display_name = (form.get("display_name") or "").strip()
    if not user_name:
        return RedirectResponse(
            "/proxy/users?error=user_name+is+required",
            status_code=303,
        )

    # Registry-only fallback path, no Frontdesk to delegate to.
    if _frontdesk_admin_target() is None:
        from urllib.parse import quote
        from mcp_proxy.db import get_config, get_db, log_audit
        from sqlalchemy import text
        try:
            # Prefer app.state.agent_manager.org_id (set at lifespan
            # start, source of truth), fall back to proxy_config table
            # for legacy deployments that pre-date the agent_manager
            # singleton.
            mgr = getattr(request.app.state, "agent_manager", None)
            org_id = getattr(mgr, "org_id", None) if mgr is not None else None
            if not org_id:
                org_id = await get_config("org_id") or ""
            if not org_id:
                return RedirectResponse(
                    "/proxy/users?error=Mastio+org_id+not+initialised",
                    status_code=303,
                )
            principal_id = f"{org_id}::user::{user_name}"
            async with get_db() as conn:
                result = await conn.execute(
                    text(
                        "SELECT 1 FROM local_user_principals "
                        "WHERE principal_id = :pid"
                    ),
                    {"pid": principal_id},
                )
                if result.first() is not None:
                    return RedirectResponse(
                        f"/proxy/users?error=User+{user_name}+already+exists",
                        status_code=303,
                    )
                await conn.execute(
                    text(
                        """
                        INSERT INTO local_user_principals
                        (principal_id, user_name, display_name, reach,
                         surface, created_at)
                        VALUES (:pid, :uname, :dname, 'intra', 'registry',
                                datetime('now'))
                        """
                    ),
                    {
                        "pid": principal_id,
                        "uname": user_name,
                        "dname": display_name,
                    },
                )
            await log_audit(
                agent_id=(
                    getattr(session, "principal_id", None)
                    or getattr(session, "username", None)
                    or "dashboard-admin"
                ),
                action="user.create",
                status="success",
                details={
                    "event": "user.create",
                    "source": "registry-only",
                    "principal_id": principal_id,
                    "user_name": user_name,
                    "display_name": display_name,
                },
            )
            return RedirectResponse(
                f"/proxy/users/{quote(principal_id, safe='')}"
                "?ok=Registry+row+created+-+mint+an+API+token+to+grant+access",
                status_code=303,
            )
        except Exception as exc:  # noqa: BLE001
            _log.exception("users_create registry-only failed: %s", exc)
            return RedirectResponse(
                "/proxy/users?error=Failed+to+create+registry+row",
                status_code=303,
            )

    # ADR-034 dogfood follow-up, the admin now picks the initial
    # password themselves (was: auto-generated 20-char temp). Rationale:
    # the previous flow stored the cleartext in a process-local ticket
    # store so the redirect could render it once on the detail page;
    # multi-worker uvicorn (F0.1 ship 2026-05-18) made that store
    # unreliable because POST and GET land on different workers and
    # the in-memory dict is per-process. Admin-input password
    # eliminates the shared state altogether: the password lives only
    # in the POST body (HTTPS) and the Frontdesk's bcrypt hash; the
    # admin already knows it (they typed it) and communicates it
    # out-of-band. ``must_change_password=True`` still forces the user
    # to rotate at first sign-in.
    admin_password = (form.get("password") or "").strip()
    admin_password_confirm = (form.get("password_confirm") or "").strip()
    if not admin_password:
        return RedirectResponse(
            "/proxy/users?error=Initial+password+is+required",
            status_code=303,
        )
    if admin_password != admin_password_confirm:
        return RedirectResponse(
            "/proxy/users?error=Password+confirmation+does+not+match",
            status_code=303,
        )
    # The Frontdesk admin API enforces ``min_length=8`` via Pydantic
    # (``cullis_connector/admin/users_router.py:54``); raise the floor
    # to 12 chars here so the admin gets immediate feedback before the
    # round-trip rather than a generic 400 back from the Ambassador.
    if len(admin_password) < 12:
        return RedirectResponse(
            "/proxy/users?error=Password+must+be+at+least+12+characters",
            status_code=303,
        )

    status_code, body, transport_err = await _frontdesk_admin_call(
        "POST",
        "/admin/users",
        json_body={
            "user_name": user_name,
            "password": admin_password,
            "must_change_password": True,
            "display_name": display_name,
        },
    )
    if transport_err:
        return RedirectResponse(
            "/proxy/users?error=Frontdesk+unreachable",
            status_code=303,
        )
    if status_code == 409:
        return RedirectResponse(
            f"/proxy/users?error=User+{user_name}+already+exists",
            status_code=303,
        )
    if status_code >= 400:
        # Surface a generic message; the Frontdesk's own log carries the
        # detailed error, the Mastio worker log carries the status code.
        detail = (body or {}).get("detail") if isinstance(body, dict) else None
        _log.warning(
            "users_create: frontdesk rejected status=%s detail=%s",
            status_code, detail,
        )
        return RedirectResponse(
            "/proxy/users?error=Frontdesk+rejected+the+request",
            status_code=303,
        )

    # Pre-seed the Mastio row so the principal is visible immediately,
    # not just after the first CSR. The Frontdesk-only fallback in
    # ``_build_user_view`` already handles this, but writing a Mastio
    # row earlier keeps the cert thumbprint slot stable across reloads.
    # Use the same admin path the existing ``/v1/admin/users`` endpoint
    # would.
    org_id = ""
    try:
        from mcp_proxy.db import get_config, get_db
        from sqlalchemy import text
        org_id = await get_config("org_id") or ""
        if org_id:
            principal_id = f"{org_id}::user::{user_name}"
            async with get_db() as conn:
                await conn.execute(
                    text(
                        """
                        INSERT OR IGNORE INTO local_user_principals
                        (principal_id, user_name, display_name, reach, surface, created_at)
                        VALUES (:pid, :uname, :dname, 'intra', 'frontdesk', datetime('now'))
                        """
                    ),
                    {"pid": principal_id, "uname": user_name, "dname": display_name},
                )
    except Exception as exc:  # noqa: BLE001, pre-seed is best-effort
        _log.warning("users_create: mastio pre-seed failed: %s", exc)

    # Redirect to the per-user detail page rather than the list so
    # the admin lands on a page that confirms the user state and lets
    # them mint API tokens / inspect audit immediately. No banner
    # carries the password anymore, admin already knows it
    # (it was typed in the form they just submitted) and the redirect
    # URL stays free of any cleartext credential.
    from urllib.parse import quote
    target_pid = f"{org_id}::user::{user_name}" if org_id else f"::user::{user_name}"
    return RedirectResponse(
        f"/proxy/users/{quote(target_pid, safe='')}"
        f"?ok=User+{quote(user_name)}+created+-+communicate+the+initial+password+out-of-band",
        status_code=303,
    )


@router.get("/users/{principal_id:path}", response_class=HTMLResponse)
async def user_detail_page(principal_id: str, request: Request):
    """Per-user detail: Mastio attribution + Frontdesk credential state + audit."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    users, fd_enabled = await _build_user_view()
    user = next(
        (u for u in users if u.get("principal_id") == principal_id),
        None,
    )
    if user is None:
        return RedirectResponse(
            "/proxy/users?error=user+not+found",
            status_code=303,
        )

    # Audit rows attributed to this principal id.
    audit_entries: list[dict] = []
    try:
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            result = await conn.execute(
                text(
                    "SELECT timestamp, action, tool_name, status, detail "
                    "  FROM audit_log "
                    " WHERE agent_id = :pid "
                    " ORDER BY timestamp DESC LIMIT 20"
                ),
                {"pid": principal_id},
            )
            audit_entries = [dict(r) for r in result.mappings().all()]
    except Exception as exc:  # noqa: BLE001
        _log.warning("user_detail_page: audit query failed: %s", exc)

    from mcp_proxy.db import get_config
    try:
        org_id = await get_config("org_id") or ""
        trust_domain = await get_config("trust_domain") or "cullis.local"
    except Exception:
        org_id, trust_domain = "", "cullis.local"

    # ADR-034 follow-up, passwords are admin-input now, not
    # server-generated. The Wave B G2 ticket store + ``?new_pw_ticket``
    # / ``?reset_pw_ticket`` redirect params are removed: the admin
    # already knows the password (they typed it in the form), so
    # there is nothing to surface back on this page. Any stale URL
    # with the legacy params is silently ignored, the bookmark
    # rendered nothing useful anyway because the ticket store would
    # have popped on first read.
    action_message = request.query_params.get("ok")
    error = request.query_params.get("error")

    # ADR-027, show this user's API tokens inline + render the
    # one-time cleartext banner when ``?new_token=`` is set (the mint
    # POST redirects back here with the freshly-minted token in the
    # URL exactly once; if the operator reloads the page, the query
    # param is gone and the banner does not re-render).
    api_tokens: list[dict] = []
    try:
        from mcp_proxy.db import list_user_api_tokens
        api_tokens = await list_user_api_tokens(principal_id)
    except Exception as exc:  # noqa: BLE001
        _log.warning("user_detail_page: api_tokens query failed: %s", exc)
    new_api_token = request.query_params.get("new_token")
    new_api_token_label = request.query_params.get("new_token_label")
    api_token_error = request.query_params.get("token_error")

    return templates.TemplateResponse("user_detail.html", _ctx(
        request, session,
        active="users",
        user=user,
        audit_entries=audit_entries,
        org_id=org_id,
        trust_domain=trust_domain,
        frontdesk_enabled=fd_enabled,
        action_message=action_message,
        error=error,
        api_tokens=api_tokens,
        new_api_token=new_api_token,
        new_api_token_label=new_api_token_label,
        api_token_error=api_token_error,
    ))


@router.post("/users/{principal_id:path}/reset-password")
async def users_reset_password(principal_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=csrf",
            status_code=303,
        )
    if _frontdesk_admin_target() is None:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+not+configured",
            status_code=303,
        )

    _, user_name = _split_principal_id(principal_id)
    if not user_name:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=invalid+principal+id",
            status_code=303,
        )

    # ADR-034 follow-up, admin picks the reset password from the
    # form instead of receiving a server-generated one through a
    # ticket store (broke under multi-worker uvicorn, F0.1).
    form = await request.form()
    new_pw = (form.get("password") or "").strip()
    new_pw_confirm = (form.get("password_confirm") or "").strip()
    if not new_pw:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=New+password+is+required",
            status_code=303,
        )
    if new_pw != new_pw_confirm:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Password+confirmation+does+not+match",
            status_code=303,
        )
    if len(new_pw) < 12:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Password+must+be+at+least+12+characters",
            status_code=303,
        )

    status_code, body, transport_err = await _frontdesk_admin_call(
        "POST",
        f"/admin/users/{user_name}/reset-password",
        json_body={"new_password": new_pw},
    )
    if transport_err:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+unreachable",
            status_code=303,
        )
    if status_code == 404:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=User+not+found+on+Frontdesk",
            status_code=303,
        )
    if status_code >= 400:
        _log.warning(
            "users_reset_password: frontdesk rejected status=%s",
            status_code,
        )
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Reset+failed",
            status_code=303,
        )

    # No cleartext in the redirect URL, admin already knows the
    # password (they typed it). ``must_change_password=True`` (set
    # implicitly by the Frontdesk reset endpoint) forces rotation
    # at the user's next sign-in.
    from urllib.parse import quote
    return RedirectResponse(
        f"/proxy/users/{quote(principal_id)}"
        "?ok=Password+reset+-+communicate+the+new+password+out-of-band",
        status_code=303,
    )


@router.post("/users/{principal_id:path}/provision-to-frontdesk")
async def users_provision_to_frontdesk(principal_id: str, request: Request):
    """Promote a registry-only user to a Frontdesk-backed credential.

    Closes the gap surfaced 2026-05-13: customer installs Mastio
    standalone (no Frontdesk), creates users via the registry-only
    fallback path (PR #596), then later attaches a Frontdesk bundle.
    Pre-fix the operator had no way to mint a Frontdesk credential
    for those existing users without ``delete + recreate`` or curling
    the Frontdesk Ambassador admin API by hand.

    Mints a 16-char temp password, forwards it to the Frontdesk via
    POST ``/admin/users`` (same call path users_create uses on the
    happy create-with-Frontdesk path), surfaces the password back to
    the operator via a single-consume ticket so the cleartext never
    rides in URL / nginx logs / browser history.

    Refused when:
      - Frontdesk Ambassador not configured (no target to call)
      - User is already present in the Frontdesk (avoid silent rotate)
      - principal_id cannot be parsed
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=csrf",
            status_code=303,
        )
    if _frontdesk_admin_target() is None:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+not+configured",
            status_code=303,
        )

    _, user_name = _split_principal_id(principal_id)
    if not user_name:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=invalid+principal+id",
            status_code=303,
        )

    # ADR-034 follow-up, admin picks the password from the form, same
    # rationale as users_create + users_reset_password above (no
    # multi-worker ticket store, no cleartext on the wire beyond the
    # POST body + Frontdesk bcrypt hash).
    form = await request.form()
    new_pw = (form.get("password") or "").strip()
    new_pw_confirm = (form.get("password_confirm") or "").strip()
    if not new_pw:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Initial+password+is+required",
            status_code=303,
        )
    if new_pw != new_pw_confirm:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Password+confirmation+does+not+match",
            status_code=303,
        )
    if len(new_pw) < 12:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Password+must+be+at+least+12+characters",
            status_code=303,
        )

    status_code, body, transport_err = await _frontdesk_admin_call(
        "POST",
        "/admin/users",
        json_body={
            "user_name": user_name,
            "password": new_pw,
            "must_change_password": True,
        },
    )
    if transport_err:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+unreachable",
            status_code=303,
        )
    if status_code == 409:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=User+already+in+Frontdesk",
            status_code=303,
        )
    if status_code >= 400:
        _log.warning(
            "users_provision_to_frontdesk: frontdesk rejected status=%s",
            status_code,
        )
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Provision+failed",
            status_code=303,
        )

    operator = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )
    try:
        from mcp_proxy.db import log_audit
        await log_audit(
            agent_id=principal_id,
            action="user.provision_to_frontdesk",
            status="success",
            details={
                "operator": operator,
                "user_name": user_name,
            },
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "users_provision_to_frontdesk: audit append failed for %s: %s",
            principal_id, exc,
        )

    # No banner on redirect, admin already knows the password they
    # just typed in the form.
    from urllib.parse import quote
    return RedirectResponse(
        f"/proxy/users/{quote(principal_id)}"
        "?ok=User+provisioned+to+Frontdesk+-+communicate+the+password+out-of-band",
        status_code=303,
    )


@router.post("/users/{principal_id:path}/delete")
async def users_delete(principal_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=csrf",
            status_code=303,
        )

    intercept = await maybe_intercept_for_approval(
        session=session,
        action_type=ACTION_USERS_DELETE,
        payload={"principal_id": principal_id},
        request=request,
    )
    if intercept is not None:
        return intercept

    if _frontdesk_admin_target() is None:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+not+configured",
            status_code=303,
        )

    _, user_name = _split_principal_id(principal_id)
    if not user_name:
        return RedirectResponse(
            "/proxy/users?error=invalid+principal+id",
            status_code=303,
        )

    status_code, _, transport_err = await _frontdesk_admin_call(
        "DELETE",
        f"/admin/users/{user_name}",
    )
    if transport_err:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+unreachable",
            status_code=303,
        )
    # 404 on the Frontdesk side means the Frontdesk row was already gone;
    # we still scrub the Mastio attribution row so the dashboard reflects
    # reality.
    if status_code not in (204, 404):
        _log.warning(
            "users_delete: frontdesk rejected status=%s",
            status_code,
        )
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Delete+failed+on+Frontdesk",
            status_code=303,
        )

    try:
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            await conn.execute(
                text(
                    "DELETE FROM local_user_principals WHERE principal_id = :pid"
                ),
                {"pid": principal_id},
            )
    except Exception as exc:  # noqa: BLE001
        _log.warning("users_delete: mastio cleanup failed: %s", exc)

    from urllib.parse import quote
    return RedirectResponse(
        f"/proxy/users?ok=Deleted+{quote(user_name)}",
        status_code=303,
    )


@router.post("/users/{principal_id:path}/reset-tofu-pin")
async def users_reset_tofu_pin(principal_id: str, request: Request):
    """Clear the TOFU-pinned pubkey for a user principal.

    Recovery path for the v0.1 keystore-loss case: Connector wiped
    its on-disk keypair, customer rebuilt the laptop, or an early
    Mastio (pre-PR #656) ran with in-memory keys and lost the pin
    on restart. Operator confirms identity out-of-band, hits this
    button, the next CSR from the user is accepted regardless of
    pubkey and the fresh thumb gets repinned at signature time.

    Mastio-local: the TOFU pin lives only in ``local_user_principals``
    (the Frontdesk doesn't carry it). No Frontdesk bridge required.
    Audit chain captures the reset with action=``reset_tofu_pin``
    so an attacker who flips a real user's pin to their own pubkey
    is recoverable forensically.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=csrf",
            status_code=303,
        )

    _, user_name = _split_principal_id(principal_id)
    if not user_name:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=invalid+principal+id",
            status_code=303,
        )

    from mcp_proxy.db import clear_user_principal_pubkey_thumbprint, log_audit
    try:
        cleared = await clear_user_principal_pubkey_thumbprint(principal_id)
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "users_reset_tofu_pin: clear failed for %s: %s",
            principal_id, exc,
        )
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Reset+failed",
            status_code=303,
        )

    if not cleared:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=No+pin+to+clear",
            status_code=303,
        )

    operator = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )
    try:
        await log_audit(
            agent_id=principal_id,
            action="reset_tofu_pin",
            status="success",
            details={
                "operator": operator,
                "user_name": user_name,
            },
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "users_reset_tofu_pin: audit append failed for %s: %s",
            principal_id, exc,
        )

    return RedirectResponse(
        f"/proxy/users/{principal_id}?ok=TOFU+pin+cleared",
        status_code=303,
    )
