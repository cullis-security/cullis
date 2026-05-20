"""Mastio dashboard - API status sub-router.

Sprint F-B-201 PR-13 of 13 (sprint closer). Extracts the
update-advisory HTMX banner + dismiss handler + JSON version-status
endpoint from ``mcp_proxy/dashboard/router.py``.

Mounted via ``router.include_router(api_status_routes.router)``.

Routes (3):

  GET  /proxy/api/update-status            HTMX update-banner fragment
  POST /proxy/api/update-status/dismiss    operator dismiss current latest
  GET  /proxy/api/version-status           JSON polled by the dashboard frame

The container can't auto-replace itself (no docker.sock), so we advise
+ show the operator the exact ``./deploy.sh --upgrade <ver>`` they
should run on the host.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import (
    get_session,
    require_login,
    verify_csrf,
)

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-api-status"])


@router.get("/api/update-status")
async def api_update_status(request: Request):
    """Render the update-available banner fragment (HTMX target).

    Polls GitHub releases lazily - first call after the 24h cache
    expiry pays the latency, subsequent calls within the window read
    from ``proxy_config``. Returns empty HTML when no update is
    available or the operator has dismissed the current latest.

    No-auth on the GET would leak the running Mastio version to any
    visitor; gate to logged-in sessions only. The banner is
    operator-only by design.
    """
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.dashboard.update_check import get_update_status

    try:
        status = await get_update_status()
    except Exception as exc:  # noqa: BLE001
        # Never blank the page on update-check failure - log and
        # render empty so the dashboard keeps working offline.
        _log.warning("api_update_status: failed: %s", exc)
        return HTMLResponse("")

    if not status.available:
        return HTMLResponse("")

    # Strip the ``mastio-v`` prefix so the tarball filename matches the
    # release-mastio.yml artifact naming (``cullis-mastio-bundle-X.Y.Z.tar.gz``).
    latest_tag = status.latest or ""
    latest_stripped = latest_tag.removeprefix("mastio-v") if latest_tag else ""
    return templates.TemplateResponse(
        "update_banner.html",
        {
            "request": request,
            "current": status.current,
            "latest": latest_tag,
            "latest_stripped": latest_stripped,
            "latest_url": status.latest_url or "",
            "csrf_token": session.csrf_token,
        },
    )


@router.post("/api/update-status/dismiss")
async def api_update_status_dismiss(request: Request):
    """Operator dismisses the banner for the current latest version.

    Pins the dismissed tag in ``proxy_config``; the banner stays
    hidden until a newer release shows up in a future poll. Audit
    row captures who dismissed and which version so the operator
    can find their own dismissal later (rare but useful).
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse("/proxy/overview?error=csrf", status_code=303)

    from mcp_proxy.dashboard.update_check import dismiss_current_latest
    from mcp_proxy.db import log_audit

    dismissed = await dismiss_current_latest()
    operator = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )
    if dismissed is not None:
        try:
            await log_audit(
                agent_id=operator,
                action="update_check.dismiss",
                status="success",
                details={"dismissed_tag": dismissed},
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "api_update_status_dismiss: audit append failed: %s", exc,
            )

    # Redirect back to the page the operator was on (Referer) or
    # overview as a safe default. Refresh causes the HTMX banner load
    # to re-fetch and see dismissed=true -> empty fragment.
    referer = request.headers.get("referer", "/proxy/overview")
    # Defensive: only honor same-origin referers so a malicious link
    # can't bounce the operator off the dashboard.
    if not referer.startswith("/") and "/proxy/" not in referer:
        referer = "/proxy/overview"
    return RedirectResponse(referer, status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Update advisory - JSON polled by the dashboard frame.
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/api/version-status")
async def api_version_status(request: Request):
    """JSON the banner polls every few minutes - surfaces a newer
    Mastio release on GHCR when one is out.

    Auth-gated to dashboard sessions: a leaked anonymous endpoint
    that hits the GitHub API on every request would be an easy
    rate-limit target. Logged-in admins are the only audience for
    this advisory anyway.
    """
    session = get_session(request)
    if not session.logged_in:
        return JSONResponse({"update_available": False}, status_code=200)

    from dataclasses import asdict as _asdict

    from mcp_proxy.version_check import check_for_updates

    status = await check_for_updates()
    return JSONResponse(_asdict(status))
