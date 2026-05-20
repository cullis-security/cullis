"""Mastio dashboard — Connector enrollments sub-router.

Sprint F-B-201 PR-12 of 13. Extracts the admin review queue for
pending Connector enrollment requests from
``mcp_proxy/dashboard/router.py``.

The JSON API lives under ``/v1/admin/enrollments/*``
(``mcp_proxy.enrollment.router``); these routes render the HTML
dashboard page and accept form-based POST submissions so the
approve/reject flow matches the prevailing form+CSRF pattern used
by the rest of the dashboard (agents/create, vault/save, etc).

Mounted via ``router.include_router(enrollments_routes.router)``.

Routes (3):

  GET  /proxy/enrollments                          pending queue page
  POST /proxy/enrollments/{session_id}/approve     issue cert + capabilities
  POST /proxy/enrollments/{session_id}/reject      record rejection reason
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_AGENT_ENROLL,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-enrollments"])


def _resolve_agent_manager(request: Request):
    """Return a usable AgentManager for enrollment approval.

    Prefers ``app.state.agent_manager`` (set in tests), then the one
    embedded in ``app.state.broker_bridge``, then falls back to
    constructing one on the fly and loading the Org CA from config.
    """
    from mcp_proxy.egress.agent_manager import AgentManager

    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is not None:
        return mgr

    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is not None:
        embedded = getattr(bridge, "_agent_manager", None)
        if embedded is not None:
            return embedded

    # Fallback: construct from config. ``load_org_ca_from_config`` is a
    # no-op when no CA is stored; the enrollment service will then raise a
    # clean 503 that we surface in the page.
    from mcp_proxy.config import get_settings

    settings = get_settings()
    return AgentManager(org_id=settings.org_id, trust_domain=settings.trust_domain)


def _enroll_error_response(
    request: Request,
    message: str,
    *,
    status_code: int = 400,
) -> Response:
    """Content-negotiated error response for dashboard enrollment form handlers.

    Browsers (`Accept: text/html...`) keep the 303 redirect + flash error so
    the form page re-renders with the message inline. CLI/script callers
    (curl default `*/*`, `application/json`, fetch JS) get a structured
    `400` with `{"detail": <message>}` instead of a 303 they would silently
    follow into a 200 page with the real error buried in the query string.
    """
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        from urllib.parse import quote
        return RedirectResponse(
            url=f"/proxy/enrollments?error={quote(message)}",
            status_code=303,
        )
    return JSONResponse(
        status_code=status_code,
        content={"detail": message},
    )


@router.get("/enrollments", response_class=HTMLResponse)
async def enrollments_page(request: Request):
    """Admin-only list of pending Connector enrollment requests."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_db as _get_db
    from mcp_proxy.enrollment import service as _enrollment_service

    async with _get_db() as conn:
        pending = await _enrollment_service.list_pending(conn)

    flash = request.query_params.get("flash")
    flash_kind = request.query_params.get("flash_kind", "success")
    error = request.query_params.get("error")

    return templates.TemplateResponse("enrollments.html", _ctx(
        request, session,
        active="enrollments",
        pending=pending,
        flash=flash,
        flash_kind=flash_kind,
        error=error,
    ))


@router.post("/enrollments/{session_id}/approve")
async def enrollments_approve(request: Request, session_id: str):
    """Form-based approve handler. Calls the service and redirects back."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import get_db as _get_db
    from mcp_proxy.enrollment import service as _enrollment_service

    form = await request.form()
    agent_id = str(form.get("agent_id", "")).strip()
    capabilities_raw = str(form.get("capabilities", "")).strip()
    groups_raw = str(form.get("groups", "")).strip()

    if not agent_id:
        return _enroll_error_response(request, "agent_id is required")

    capabilities = [c.strip() for c in capabilities_raw.split(",") if c.strip()]
    groups = [g.strip() for g in groups_raw.split(",") if g.strip()]

    # H3 P0.5 — 4-eyes intercept. When the enterprise rbac_multi_admin
    # plugin is loaded and policy-gated, this submits the action for a
    # second admin signoff and redirects the submitter to the approvals
    # page. When no plugin opts in (community / single-admin deploys),
    # the helper returns None and the endpoint proceeds unchanged.
    intercept = await maybe_intercept_for_approval(
        session=session,
        action_type=ACTION_AGENT_ENROLL,
        payload={
            "session_id": session_id,
            "agent_id": agent_id,
            "capabilities": capabilities,
            "groups": groups,
        },
        request=request,
    )
    if intercept is not None:
        return intercept

    agent_manager = _resolve_agent_manager(request)

    try:
        async with _get_db() as conn:
            record = await _enrollment_service.approve(
                conn,
                session_id=session_id,
                agent_id=agent_id,
                capabilities=capabilities,
                groups=groups,
                admin_name=session.role or "admin",
                agent_manager=agent_manager,
            )
    except _enrollment_service.EnrollmentError as exc:
        return _enroll_error_response(request, str(exc))

    _log.info(
        "enrollment_approved via dashboard: session=%s agent=%s admin=%s",
        session_id, record.get("agent_id_assigned"), session.role,
    )
    from urllib.parse import quote
    msg = f"Approved enrollment — agent {record.get('agent_id_assigned', agent_id)} issued"
    return RedirectResponse(
        url=f"/proxy/enrollments?flash={quote(msg)}",
        status_code=303,
    )


@router.post("/enrollments/{session_id}/reject")
async def enrollments_reject(request: Request, session_id: str):
    """Form-based reject handler. Calls the service and redirects back."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import get_db as _get_db
    from mcp_proxy.enrollment import service as _enrollment_service

    form = await request.form()
    reason = str(form.get("reason", "")).strip()
    if not reason:
        return _enroll_error_response(request, "Rejection reason is required")

    try:
        async with _get_db() as conn:
            await _enrollment_service.reject(
                conn,
                session_id=session_id,
                reason=reason,
                admin_name=session.role or "admin",
            )
    except _enrollment_service.EnrollmentError as exc:
        return _enroll_error_response(request, str(exc))

    _log.info(
        "enrollment_rejected via dashboard: session=%s admin=%s",
        session_id, session.role,
    )
    return RedirectResponse(
        url="/proxy/enrollments?flash=Enrollment+rejected&flash_kind=success",
        status_code=303,
    )
