"""Mastio dashboard - Settings sub-router.

Sprint F-B-201 PR-13 of 13 (sprint closer). Extracts the OIDC settings
page, the local-password toggle, the admin password rotation handler,
and the license hot-swap handler from the
``mcp_proxy/dashboard/router.py`` god-object.

Mounted via ``router.include_router(settings_routes.router)``.

Routes (5):

  GET  /proxy/settings                         OIDC config + toggle page
  POST /proxy/settings                         persist OIDC settings
  POST /proxy/settings/local-password          flip password sign-in toggle
  POST /proxy/settings/admin-password/change   rotate dashboard admin password
  POST /proxy/settings/license                 hot-swap license JWT

The display-name HTMX endpoints under ``/proxy/settings/org/...`` live
in the sibling ``core_routes.py`` module since they share the inline-
edit partial used by the overview header card.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_LICENSE_IMPORT,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import (
    require_login,
    set_admin_password,
    verify_admin_password,
    verify_csrf,
)

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-settings"])


# ─────────────────────────────────────────────────────────────────────────────
# Settings (OIDC config)
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Display current OIDC config (issuer + client_id) with an edit form.

    The client_secret is NEVER rendered. We only show whether a value is set.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.config import get_settings
    from mcp_proxy.dashboard.oidc import is_oidc_configured, load_oidc_config
    from mcp_proxy.dashboard.session import is_local_password_login_enabled

    cfg = await load_oidc_config()
    return templates.TemplateResponse("settings.html", _ctx(
        request, session,
        active="settings",
        issuer_url=cfg["issuer_url"],
        client_id=cfg["client_id"],
        has_client_secret=bool(cfg["client_secret"]),
        local_password_enabled=await is_local_password_login_enabled(),
        oidc_configured=await is_oidc_configured(),
        force_local_password_env=get_settings().force_local_password,
        error=request.query_params.get("error"),
        success=request.query_params.get("ok"),
    ))


@router.post("/settings")
async def settings_submit(request: Request):
    """Persist OIDC settings. Empty client_secret leaves the stored value
    untouched so the admin can update other fields without resupplying it."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.dashboard.oidc import load_oidc_config, save_oidc_config
    from mcp_proxy.db import log_audit

    form = await request.form()
    issuer_url = str(form.get("oidc_issuer_url", "")).strip()
    client_id = str(form.get("oidc_client_id", "")).strip()
    client_secret_raw = str(form.get("oidc_client_secret", ""))

    errors: list[str] = []
    if issuer_url and not issuer_url.startswith(("http://", "https://")):
        errors.append("Issuer URL must start with http:// or https://")
    if issuer_url and not client_id:
        errors.append("Client ID is required when issuer URL is set.")

    if errors:
        from mcp_proxy.config import get_settings
        from mcp_proxy.dashboard.oidc import is_oidc_configured
        from mcp_proxy.dashboard.session import is_local_password_login_enabled
        cfg = await load_oidc_config()
        return templates.TemplateResponse("settings.html", _ctx(
            request, session,
            active="settings",
            issuer_url=issuer_url or cfg["issuer_url"],
            client_id=client_id or cfg["client_id"],
            has_client_secret=bool(cfg["client_secret"]),
            local_password_enabled=await is_local_password_login_enabled(),
            oidc_configured=await is_oidc_configured(),
            force_local_password_env=get_settings().force_local_password,
            error="; ".join(errors),
            success=None,
        ), status_code=400)

    # Only overwrite client_secret if the admin typed something. An empty
    # input means "keep current value" - otherwise an admin who only wants
    # to rename the client_id would silently lose the stored secret.
    secret_arg = client_secret_raw if client_secret_raw != "" else None
    await save_oidc_config(issuer_url, client_id, secret_arg)

    await log_audit(
        agent_id="admin",
        action="settings.oidc_update",
        status="success",
        detail=f"issuer={issuer_url or '(cleared)'}, client_id={client_id or '(cleared)'}",
    )

    from mcp_proxy.config import get_settings
    from mcp_proxy.dashboard.oidc import is_oidc_configured
    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    cfg = await load_oidc_config()
    return templates.TemplateResponse("settings.html", _ctx(
        request, session,
        active="settings",
        issuer_url=cfg["issuer_url"],
        client_id=cfg["client_id"],
        has_client_secret=bool(cfg["client_secret"]),
        local_password_enabled=await is_local_password_login_enabled(),
        oidc_configured=await is_oidc_configured(),
        force_local_password_env=get_settings().force_local_password,
        error=None,
        success="OIDC configuration saved.",
    ))


@router.post("/settings/local-password")
async def settings_local_password(request: Request):
    """Flip the local-password sign-in toggle from Settings.

    Single-click lockout guard: we refuse to disable the toggle when no
    OIDC provider is configured - without SSO or an env break-glass the
    admin would have no way back into the dashboard. Operators who
    really want a password-less deploy can set the env
    ``MCP_PROXY_FORCE_LOCAL_PASSWORD=1`` and re-enable later; the guard
    is here because the UI flip is the easy-to-misfire path.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.dashboard.oidc import is_oidc_configured
    from mcp_proxy.dashboard.session import set_local_password_login_enabled
    from mcp_proxy.db import log_audit

    form = await request.form()
    enabled = str(form.get("enabled", "")).strip() not in ("0", "false", "no", "off", "")

    if not enabled and not await is_oidc_configured():
        return HTMLResponse(
            "Refusing to disable password sign-in: no OIDC provider is "
            "configured on this proxy. Configure OIDC in Settings first, "
            "otherwise flipping this toggle would lock the admin out.",
            status_code=400,
        )

    await set_local_password_login_enabled(enabled)
    await log_audit(
        agent_id="admin",
        action="auth.password_login_toggle",
        status="success",
        detail=f"source=dashboard enabled={enabled}",
    )
    return HTMLResponse(
        f"Local password sign-in {'enabled' if enabled else 'disabled'}.",
        status_code=200,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Admin password rotation (issue #653)
#
# The Mastio admin password used to be rotate-only via ``python -m
# mcp_proxy.cli reset-password`` over docker exec, which every first-time
# operator hit as "I logged in with MCP_PROXY_INITIAL_ADMIN_PASSWORD and
# now there's no way to change it from the dashboard". This handler
# exposes the same helper (``set_admin_password``) via a small form on
# the Settings page.
#
# Auth: requires an existing dashboard session (the helper assumes the
# caller already authenticated). The CSRF token gates POSTs from the
# same browser session. Current-password re-check ensures a stolen
# cookie alone is not enough to rotate.
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/settings/admin-password/change")
async def settings_admin_password_change(request: Request):
    """Rotate the dashboard admin password from the Settings page."""
    from mcp_proxy.db import log_audit

    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    current = str(form.get("current_password", ""))
    new = str(form.get("new_password", ""))
    confirm = str(form.get("new_password_confirm", ""))

    if not current or not new or not confirm:
        return RedirectResponse(
            "/proxy/settings?error=All+three+password+fields+are+required",
            status_code=303,
        )

    if new != confirm:
        return RedirectResponse(
            "/proxy/settings?error=New+passwords+do+not+match",
            status_code=303,
        )

    # Generic 401 on bad current password - don't leak whether the value
    # was wrong vs the session was somehow detached from the persisted
    # admin row. Same pattern as the /proxy/login error handler.
    if not await verify_admin_password(current):
        _log.warning(
            "admin password change rejected: wrong current password "
            "(actor=%s)", getattr(session, "username", "?"),
        )
        return RedirectResponse(
            "/proxy/settings?error=Current+password+is+wrong",
            status_code=303,
        )

    try:
        await set_admin_password(new)
    except ValueError as exc:
        # set_admin_password enforces MIN_PASSWORD_LENGTH and possibly
        # other complexity rules; surface the constraint to the operator.
        from urllib.parse import quote
        return RedirectResponse(
            f"/proxy/settings?error={quote(str(exc))}",
            status_code=303,
        )

    actor = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "admin"
    )
    await log_audit(
        agent_id=actor,
        action="admin_password_rotated",
        status="success",
        detail=f"source=dashboard actor={actor}",
    )
    return RedirectResponse(
        "/proxy/settings?ok=Admin+password+rotated."
        "+Re-login+required+on+next+session.",
        status_code=303,
    )


# ─────────────────────────────────────────────────────────────────────────────
# License hot-swap (H3 P0.2)
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/settings/license")
async def settings_license_swap(request: Request):
    """Hot-swap the in-process license JWT without a restart.

    Closes the rotation gap for the first paid deal: customers on a
    paid tier need to rotate the license JWT every ~90 days without
    bouncing the bundle. Validates the candidate token against the
    baked / overridden public key; on success the cache is replaced
    atomically and the plugin registry is invalidated so the feature
    gate re-applies on the next call. On validation failure the cache
    stays unchanged and the operator gets a flash message.

    Optional 4-eyes gate: when the enterprise rbac_multi_admin plugin
    is loaded and policy-gated, the import is queued for a second
    admin signoff via ``ACTION_LICENSE_IMPORT``. Community deploys
    skip the gate entirely.
    """
    from urllib.parse import quote

    from mcp_proxy.db import log_audit
    from mcp_proxy.license import LicenseSwapError, swap_token

    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    candidate = str(form.get("license_jwt", "")).strip()
    if not candidate:
        return RedirectResponse(
            "/proxy/settings?error=Paste+the+license+JWT+before+submitting",
            status_code=303,
        )

    # 4-eyes gate. We forward the JWT prefix to the plugin payload so
    # the second signer can see WHICH license is being imported (the
    # 90gg rotation procedure ships out-of-band, so the prefix is
    # enough to cross-reference); we do NOT log the full JWT to the
    # payload because the plugin persists it for audit.
    jwt_prefix = candidate.split(".", 1)[0][:80]
    intercept = await maybe_intercept_for_approval(
        session=session,
        action_type=ACTION_LICENSE_IMPORT,
        payload={"license_jwt_prefix": jwt_prefix},
        request=request,
    )
    if intercept is not None:
        return intercept

    try:
        claims = swap_token(candidate)
    except LicenseSwapError as exc:
        # Audit the failed swap attempt so a paste-error / hostile JWT
        # is forensically visible. The candidate token itself is NOT
        # logged (it may be a valid JWT for the wrong tenant and we do
        # not want to leak it via grep).
        actor = (
            getattr(session, "principal_id", None)
            or getattr(session, "username", None)
            or "admin"
        )
        await log_audit(
            agent_id=actor,
            action="license_swap",
            status="error",
            detail=f"reason={exc} actor={actor}",
        )
        return RedirectResponse(
            f"/proxy/settings?error={quote(f'License swap rejected: {exc}')}",
            status_code=303,
        )

    actor = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "admin"
    )
    await log_audit(
        agent_id=actor,
        action="license_swap",
        status="success",
        detail=(
            f"tier={claims.tier} org={claims.org} "
            f"features={len(claims.features)} exp={claims.exp} actor={actor}"
        ),
    )
    return RedirectResponse(
        f"/proxy/settings?ok={quote('License updated. Tier: ' + claims.tier)}",
        status_code=303,
    )
