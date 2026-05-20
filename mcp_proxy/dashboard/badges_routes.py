"""Mastio dashboard — HTMX status badges sub-router.

Sprint F-B-201 PR-13 of 13. Extracts the small HTMX fragments the
sidebar polls to surface "you have N unread X" indicators (agent
count, pending enrollments, registered users, pending 4-eyes
approvals, last-hour audit volume, pending federation updates,
upstream Mastio version advisory) from
``mcp_proxy/dashboard/router.py``.

Each handler returns either an empty body (no badge needed) or a
small ``<span>`` with tint+count. Auth-gated to logged-in sessions
so an anonymous caller can't enumerate counts or hit upstream APIs
(``check_for_updates`` calls GHCR).

Mounted via ``router.include_router(badges_routes.router)``.

Routes (7):

  GET /proxy/badge/agents          internal agent count
  GET /proxy/badge/enrollments     pending Connector enrollment queue
  GET /proxy/badge/users           registered user-principal count
  GET /proxy/badge/approvals       pending 4-eyes approvals (enterprise)
  GET /proxy/badge/audit           audit_log rows in the last hour
  GET /proxy/badge/updates         pending federation migrations
  GET /proxy/badge/version         upstream Mastio release advisory
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from mcp_proxy import license as _license_mod
from mcp_proxy.dashboard.session import get_session

_log = logging.getLogger("mcp_proxy.dashboard")

router = APIRouter(tags=["dashboard-badges"])


@router.get("/badge/agents")
async def badge_agents(request: Request):
    """Return agent count badge fragment."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.db import list_agents
    agents = await list_agents()
    active = sum(1 for a in agents if a["is_active"])
    if active:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-teal-500/20 text-teal-400">{active}</span>'
        )
    return HTMLResponse("")


@router.get("/badge/enrollments")
async def badge_enrollments(request: Request):
    """Return pending enrollment count badge fragment."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.db import get_db as _get_db
    from mcp_proxy.enrollment import service as _enrollment_service

    try:
        async with _get_db() as conn:
            pending = await _enrollment_service.list_pending(conn)
    except Exception:  # table may not exist in pre-migrated setups
        return HTMLResponse("")

    count = len(pending)
    if count:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-amber-500/20 text-amber-400">{count}</span>'
        )
    return HTMLResponse("")


@router.get("/badge/users")
async def badge_users(request: Request):
    """Return user-principal count badge fragment for the sidebar."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")
    try:
        from mcp_proxy.db import count_user_principals
        n = await count_user_principals()
    except Exception:  # table may not exist in pre-migrated setups
        return HTMLResponse("")
    if n:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-accent-500/15 text-accent-400">{n}</span>'
        )
    return HTMLResponse("")


@router.get("/badge/approvals")
async def badge_approvals(request: Request):
    """Pending 4-eyes approvals count for the sidebar.

    Empty in community mode (no ``rbac_multi_admin`` feature in the
    license) or when the enterprise plugin is not installed on this
    deploy — the late import keeps the open-core build independent of
    the enterprise package. Anything unexpected on the read path
    degrades silently to "no badge" rather than breaking the nav.
    """
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")
    if not _license_mod.has_feature("rbac_multi_admin"):
        return HTMLResponse("")
    try:
        from cullis_enterprise.mastio.rbac_multi_admin import (
            models as _approvals_models,
        )
        pending = await _approvals_models.list_pending_approvals()
    except Exception:
        return HTMLResponse("")
    count = len(pending)
    if count:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-amber-500/20 text-amber-400">{count}</span>'
        )
    return HTMLResponse("")


@router.get("/badge/audit")
async def badge_audit(request: Request):
    """Return recent audit count badge fragment."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from sqlalchemy import text

    from mcp_proxy.db import get_db

    async with get_db() as db:
        result = await db.execute(
            text("SELECT COUNT(*) as cnt FROM audit_log WHERE timestamp > datetime('now', '-1 hour')")
        )
        row = result.mappings().first()
        count = row["cnt"] if row else 0

    if count:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-teal-500/20 text-teal-400">{count}</span>'
        )
    return HTMLResponse("")


@router.get("/badge/updates")
async def badge_updates(request: Request):
    """Return federation-update pending count badge fragment.

    Tint encodes the most severe pending criticality on the proxy:
      - red  → at least one ``critical`` pending migration.
      - amber → only ``warning`` / ``info`` migrations pending.
      - empty → no pending migrations.

    Counts all pending migrations regardless of severity so operators
    see the workload at a glance; the tint signals urgency.
    """
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    try:
        from mcp_proxy.db import get_pending_updates
        from mcp_proxy.updates import discover
    except Exception:
        return HTMLResponse("")

    migrations = discover()
    try:
        rows_by_id = {
            r["migration_id"]: r for r in await get_pending_updates()
        }
    except Exception:
        # Table may not exist yet on a pre-0019 deploy; the badge is
        # observability, not a correctness signal — degrade silent.
        return HTMLResponse("")

    critical_pending = 0
    other_pending = 0
    for m in migrations:
        row = rows_by_id.get(m.migration_id)
        if row is None or row["status"] != "pending":
            continue
        if m.criticality == "critical":
            critical_pending += 1
        else:
            other_pending += 1

    total = critical_pending + other_pending
    if not total:
        return HTMLResponse("")

    tint_cls = (
        "bg-red-500/20 text-red-400"
        if critical_pending
        else "bg-amber-500/20 text-amber-400"
    )
    return HTMLResponse(
        f'<span class="px-1.5 py-0.5 rounded-full text-xs {tint_cls}">'
        f'{total}</span>'
    )


@router.get("/badge/version")
async def badge_version(request: Request):
    """HTMX fragment — single-pixel-thin banner that says "Update
    available: 0.3.0-rc3" and links to the modal with the copy-paste
    install command. Empty response when no update is pending so the
    sidebar stays clean.

    M-dash-3 audit fix: every interpolated value is HTML-escaped
    before reaching the response. ``release_url``, ``latest``, and
    ``install_command`` come from the GitHub Releases API (or a tag
    name that an attacker who compromises the GHCR repo could craft)
    and used to be embedded raw in ``href=...`` / ``title=...`` /
    text-content positions, giving a stored-XSS surface against any
    operator viewing the dashboard.
    """
    import html as _html

    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.version_check import check_for_updates
    status = await check_for_updates()
    if not status.update_available or not status.install_command:
        return HTMLResponse("")

    # ``quote=True`` escapes ``"`` so attribute-context interpolations
    # cannot break out into new attributes.
    cmd = _html.escape(status.install_command, quote=True)
    latest = _html.escape(status.latest or "", quote=True)
    current = _html.escape(str(status.current), quote=True)
    release_url = _html.escape(status.release_url or "", quote=True)
    return HTMLResponse(
        f'<a href="{release_url}" target="_blank" rel="noopener" '
        f'class="block px-3 py-2 rounded text-xs font-mono '
        f'bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 transition" '
        f'title="Run ``{cmd}`` on the Mastio host to upgrade. '
        f'See release notes on GitHub.">'
        f'⤴ Update: <span class="font-semibold">{latest}</span> '
        f'<span class="opacity-60">(running {current})</span>'
        f'</a>'
    )
