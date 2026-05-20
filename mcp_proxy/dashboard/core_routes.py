"""Mastio dashboard - Core sub-router.

Sprint F-B-201 PR-13 of 13 (sprint closer). Extracts the residual
"core" surface from ``mcp_proxy/dashboard/router.py``:

- the smart entry point ``/proxy/``
- the HTMX org-status banner ``/proxy/org-status``
- the inline-edit display-name partials under
  ``/proxy/settings/org/display-name`` (view / edit / update)
- the post-login landing page ``/proxy/overview``

Mounted via ``router.include_router(core_routes.router)``.

Routes (6):

  GET  /proxy/                                 smart entry point (303)
  GET  /proxy/org-status                       HTMX broker-poll banner
  GET  /proxy/settings/org/display-name        title partial (Cancel)
  GET  /proxy/settings/org/display-name/edit   title partial (edit mode)
  POST /proxy/settings/org/display-name        persist new display name
  GET  /proxy/overview                         post-login landing
"""
from __future__ import annotations

import logging
import pathlib

import httpx

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._helpers import _ctx, _post_login_redirect
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    get_session,
    is_admin_password_set,
    require_login,
    verify_csrf,
)

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-core"])


# ─────────────────────────────────────────────────────────────────────────────
# Smart entry point
# ─────────────────────────────────────────────────────────────────────────────
#
# State machine:
#
#   no admin_password_hash      -> /proxy/register   (one-shot account creation)
#   hash set, no session        -> /proxy/login      (sign in)
#   hash set, session, no org   -> /proxy/setup      (broker uplink wizard)
#   hash set, session, org      -> /proxy/overview   (operational dashboard)


@router.get("/", response_class=HTMLResponse)
async def proxy_root(request: Request):
    """Smart entry point - route based on registration + session + broker state."""
    if not await is_admin_password_set():
        return RedirectResponse(url="/proxy/register", status_code=303)

    session = get_session(request)
    if not session.logged_in:
        return RedirectResponse(url="/proxy/login", status_code=303)

    return RedirectResponse(url=await _post_login_redirect(), status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Org Status Polling (HTMX)
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/org-status")
async def org_status(request: Request):
    """HTMX endpoint: check org registration status with the broker."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.db import get_config, set_config

    org_id = await get_config("org_id")
    if not org_id:
        return HTMLResponse("")

    org_status_val = await get_config("org_status")

    # Already active - no banner needed
    if org_status_val == "active":
        return HTMLResponse("")

    # Not pending - nothing to poll
    if org_status_val != "pending":
        return HTMLResponse("")

    # Poll broker for status
    broker_url = await get_config("broker_url")
    org_secret = await get_config("org_secret")

    if not broker_url or not org_secret:
        return HTMLResponse(
            '<div class="px-4 py-2.5 bg-gray-500/10 border-b border-gray-700/50 text-xs text-gray-400">'
            'Cannot check organization status - broker not configured</div>'
        )

    try:
        from mcp_proxy.config import broker_tls_verify, get_settings
        async with httpx.AsyncClient(
            verify=broker_tls_verify(get_settings()), timeout=5.0,
        ) as http:
            resp = await http.get(
                f"{broker_url}/v1/registry/orgs/me",
                headers={"X-Org-Id": org_id, "X-Org-Secret": org_secret},
            )
            if resp.is_success:
                data = resp.json()
                status = data.get("status", "unknown")

                # Update cached status
                if status != org_status_val:
                    await set_config("org_status", status)

                if status == "pending":
                    return HTMLResponse(
                        '<div class="px-4 py-2.5 bg-amber-500/10 border-b border-amber-600/30 text-xs text-amber-400 flex items-center gap-2">'
                        '<svg class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/></svg>'
                        'Organization registration pending - waiting for broker admin approval'
                        '</div>'
                    )
                elif status == "active":
                    return HTMLResponse(
                        '<div id="org-active-banner" class="px-4 py-2.5 bg-emerald-500/10 border-b border-emerald-600/30 text-xs text-emerald-400 flex items-center gap-2">'
                        '<span class="w-2 h-2 rounded-full bg-emerald-500"></span>'
                        'Organization active - you can now create agents'
                        '</div>'
                        '<script>setTimeout(function(){var el=document.getElementById("org-active-banner");if(el)el.remove();},5000);</script>'
                    )
                elif status == "rejected":
                    return HTMLResponse(
                        '<div class="px-4 py-2.5 bg-red-500/10 border-b border-red-600/30 text-xs text-red-400 flex items-center gap-2">'
                        '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
                        'Organization registration was rejected by the broker admin'
                        '</div>'
                    )
            else:
                return HTMLResponse(
                    '<div class="px-4 py-2.5 bg-gray-500/10 border-b border-gray-700/50 text-xs text-gray-400">'
                    f'Cannot check status (HTTP {resp.status_code})</div>'
                )
    except Exception:
        return HTMLResponse(
            '<div class="px-4 py-2.5 bg-gray-500/10 border-b border-gray-700/50 text-xs text-gray-400">'
            'Cannot check organization status - broker unreachable</div>'
        )


# ─────────────────────────────────────────────────────────────────────────────
# Org settings - inline-edit display name (overview card)
# ─────────────────────────────────────────────────────────────────────────────

_DISPLAY_NAME_MAX_LEN = 255


async def _render_org_title_block(
    request: Request,
    session: ProxyDashboardSession,
    *,
    mode: str,
) -> HTMLResponse:
    from mcp_proxy.db import get_config

    org_id = await get_config("org_id") or ""
    display_name = await get_config("display_name") or ""
    return templates.TemplateResponse(
        "_org_title_block.html",
        _ctx(
            request, session,
            mode=mode,
            org_id=org_id,
            display_name=display_name,
        ),
    )


@router.get("/settings/org/display-name", response_class=HTMLResponse)
async def org_display_name_view(request: Request):
    """HTMX endpoint: return the static title partial (used by Cancel)."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return await _render_org_title_block(request, session, mode="view")


@router.get("/settings/org/display-name/edit", response_class=HTMLResponse)
async def org_display_name_edit(request: Request):
    """HTMX endpoint: swap the title partial into inline-edit mode."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return await _render_org_title_block(request, session, mode="edit")


@router.post("/settings/org/display-name", response_class=HTMLResponse)
async def org_display_name_update(request: Request):
    """Persist a new friendly display name for the org.

    The org_id is derived from the Org CA pubkey in standalone (ADR-006
    section 2.2) and immutable here; only the human-facing label is editable.
    Empty input clears the label, falling back to the hex org_id in the
    UI.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import log_audit, set_config

    form = await request.form()
    raw = str(form.get("display_name", "")).strip()
    if len(raw) > _DISPLAY_NAME_MAX_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Display name must be at most {_DISPLAY_NAME_MAX_LEN} characters.",
        )

    await set_config("display_name", raw)
    await log_audit(
        agent_id="admin",
        action="org.display_name.update",
        status="success",
        detail=f"display_name={raw}" if raw else "display_name=<cleared>",
    )

    return await _render_org_title_block(request, session, mode="view")


# ─────────────────────────────────────────────────────────────────────────────
# Overview (post-login landing)
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/overview", response_class=HTMLResponse)
async def overview_page(request: Request):
    """Landing page after login: org name, broker uplink, federation status."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.config import get_settings as _get_settings
    from mcp_proxy.db import get_config, list_agents

    org_id = await get_config("org_id") or ""
    display_name = await get_config("display_name") or ""
    broker_url = await get_config("broker_url") or ""
    org_status = await get_config("org_status") or ""

    # ADR-006 section 2.2 - show the deterministic org_id in standalone mode so
    # the admin can paste it into a broker attach-ca invite without
    # digging into the DB. In federated mode the uplink is already
    # bound, so the card is hidden to avoid UI noise.
    _settings = _get_settings()
    standalone_mode = bool(_settings.standalone) and not broker_url
    if standalone_mode and not org_id:
        # The derivation runs at lifespan time, but an operator who
        # boots with MCP_PROXY_ORG_ID set will have a non-derived value.
        # Fall back to settings.org_id so the card always renders.
        org_id = _settings.org_id

    # Federation subscriber live stats, if running
    fed_stats = getattr(request.app.state, "federation_subscriber_stats", None)
    fed_running = getattr(request.app.state, "federation_subscriber_task", None) is not None

    # Counts
    local_agents = await list_agents()
    local_count = len(local_agents)
    local_active_count = sum(1 for a in local_agents if a.get("is_active"))

    federated_count = 0
    federated_orgs = 0
    backend_total = 0
    backend_enabled = 0
    binding_total = 0
    binding_active = 0
    recent_backends: list[dict] = []
    try:
        from sqlalchemy import text as _text

        from mcp_proxy.db import get_db as _get_db
        async with _get_db() as conn:
            row = (await conn.execute(
                _text(
                    "SELECT COUNT(*) AS c, COUNT(DISTINCT org_id) AS o "
                    "FROM cached_federated_agents WHERE revoked = 0"
                )
            )).mappings().first()
            if row:
                federated_count = int(row["c"] or 0)
                federated_orgs = int(row["o"] or 0)

            # Backend totals (ADR-007 Phase 1 - table `local_mcp_resources`,
            # surfaced here as "backends" for the operator UI).
            brow = (await conn.execute(
                _text(
                    "SELECT COUNT(*) AS total, "
                    "SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled "
                    "FROM local_mcp_resources"
                )
            )).mappings().first()
            if brow:
                backend_total = int(brow["total"] or 0)
                backend_enabled = int(brow["enabled"] or 0)

            grow = (await conn.execute(
                _text(
                    "SELECT COUNT(*) AS total, "
                    "SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) AS active "
                    "FROM local_agent_resource_bindings"
                )
            )).mappings().first()
            if grow:
                binding_total = int(grow["total"] or 0)
                binding_active = int(grow["active"] or 0)

            # Three newest backends for the overview panel.
            rrows = (await conn.execute(
                _text(
                    "SELECT name, endpoint_url, enabled, created_at "
                    "FROM local_mcp_resources "
                    "ORDER BY created_at DESC LIMIT 3"
                )
            )).mappings().all()
            recent_backends = [dict(r) for r in rrows]
    except Exception:
        # cache/backend tables may be missing on older schemas - the
        # overview still renders, just with zeros.
        pass

    # Three newest local agents for the overview panel.
    recent_agents = [
        {
            "agent_id": a.get("agent_id"),
            "display_name": a.get("display_name"),
            "is_active": a.get("is_active"),
            "created_at": a.get("created_at"),
        }
        for a in (local_agents or [])[:3]
    ]

    return templates.TemplateResponse("overview.html", _ctx(
        request, session,
        active="overview",
        org_id=org_id,
        display_name=display_name,
        broker_url=broker_url,
        org_status=org_status,
        local_count=local_count,
        local_active_count=local_active_count,
        federated_count=federated_count,
        federated_orgs=federated_orgs,
        fed_stats=fed_stats,
        fed_running=fed_running,
        standalone_mode=standalone_mode,
        backend_total=backend_total,
        backend_enabled=backend_enabled,
        binding_total=binding_total,
        binding_active=binding_active,
        recent_agents=recent_agents,
        recent_backends=recent_backends,
    ))
