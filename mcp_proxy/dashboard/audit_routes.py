"""Mastio dashboard - Audit sub-router.

Sprint F-B-201 PR-7 of 10. Extracts the audit log viewer (admin +
traffic streams unified) from ``mcp_proxy/dashboard/router.py`` into
a dedicated module. One route + one private helper.

Mounted via ``router.include_router(audit_routes.router)``.

Routes (1):

  GET  /proxy/audit         unified audit log viewer (admin + traffic)

The handler keeps both streams merged into a single view exactly as
before: legacy ``audit_log`` rows (auth, enroll, agent CRUD, policy)
plus the hash-chained ``local_audit`` rows (oneshot, mcp tool execute,
session send).
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-audit"])


def _pretty_and_recipient(raw: str | None) -> tuple[str | None, str | None]:
    """Pretty-print a JSON detail string and pluck the recipient hint.

    The proxy writes traffic events to ``local_audit.details`` as JSON
    strings (oneshot forwarded, mcp tool execute, session send...). We
    parse the payload once server-side so the template can show both a
    formatted blob in the inspector and a ``Target`` hint in the row
    without doing the parsing twice.
    """
    import json as _json
    if not raw:
        return None, None
    try:
        parsed = _json.loads(raw)
    except (ValueError, TypeError):
        return raw, None
    pretty = _json.dumps(parsed, indent=2, sort_keys=True)
    recipient = None
    if isinstance(parsed, dict):
        recipient = (
            parsed.get("recipient")
            or parsed.get("recipient_agent_id")
            or parsed.get("target_agent_id")
            or parsed.get("target")
        )
    return pretty, recipient


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_db, list_agents

    agent_filter = request.query_params.get("agent", "")
    action_filter = request.query_params.get("action", "")
    status_filter = request.query_params.get("status", "")
    source_filter = request.query_params.get("source", "")  # '', 'admin', 'traffic'
    page = int(request.query_params.get("page", "1"))
    per_page = 50

    from sqlalchemy import text

    # ``audit_log`` uses ``status='success'``; ``local_audit`` uses
    # ``result='ok'`` for the same concept. Map the UI filter once and
    # use the per-table equivalent when building WHERE clauses.
    local_audit_result_for = {"success": "ok", "ok": "ok", "error": "error", "denied": "denied"}

    async with get_db() as db:
        admin_rows: list[dict] = []
        traffic_rows: list[dict] = []

        # Admin stream - legacy ``audit_log`` (auth, enroll, agent CRUD, policy...)
        if source_filter in ("", "admin"):
            a_conds: list[str] = []
            a_params: dict[str, object] = {}
            if agent_filter:
                a_conds.append("agent_id = :agent_id")
                a_params["agent_id"] = agent_filter
            if action_filter:
                a_conds.append("action = :action")
                a_params["action"] = action_filter
            if status_filter:
                a_conds.append("status = :status")
                a_params["status"] = status_filter
            a_where = (" WHERE " + " AND ".join(a_conds)) if a_conds else ""
            result = await db.execute(
                text(f"SELECT * FROM audit_log{a_where} ORDER BY timestamp DESC LIMIT 500"),
                a_params,
            )
            admin_rows = [dict(r) for r in result.mappings().all()]

        # Traffic stream - hash-chained ``local_audit`` (oneshot, mcp, sessions)
        if source_filter in ("", "traffic"):
            t_conds: list[str] = []
            t_params: dict[str, object] = {}
            if agent_filter:
                t_conds.append("agent_id = :agent_id")
                t_params["agent_id"] = agent_filter
            if action_filter:
                t_conds.append("event_type = :event_type")
                t_params["event_type"] = action_filter
            if status_filter:
                t_conds.append("result = :result")
                t_params["result"] = local_audit_result_for.get(status_filter, status_filter)
            t_where = (" WHERE " + " AND ".join(t_conds)) if t_conds else ""
            result = await db.execute(
                text(f"SELECT * FROM local_audit{t_where} ORDER BY timestamp DESC LIMIT 500"),
                t_params,
            )
            traffic_rows = [dict(r) for r in result.mappings().all()]

        # Distinct actions + event_types for the filter dropdown.
        r1 = await db.execute(text("SELECT DISTINCT action FROM audit_log WHERE action IS NOT NULL"))
        r2 = await db.execute(text("SELECT DISTINCT event_type FROM local_audit WHERE event_type IS NOT NULL"))
        actions = sorted(set(r[0] for r in r1.fetchall()) | set(r[0] for r in r2.fetchall()))

    # Normalize both streams into a single shape so the template has
    # exactly one cell layout to render. Fields that only exist in one
    # table are left as ``None`` for the other source; the inspector
    # hides rows where the value is missing.
    unified: list[dict] = []
    for r in admin_rows:
        detail_pretty, _ = _pretty_and_recipient(r.get("detail"))
        unified.append({
            "source": "admin",
            "timestamp": r.get("timestamp"),
            "agent_id": r.get("agent_id"),
            "event": r.get("action"),
            "status": r.get("status"),
            "target": r.get("tool_name"),
            "tool_name": r.get("tool_name"),
            "duration_ms": r.get("duration_ms"),
            "request_id": r.get("request_id"),
            "session_id": None,
            "org_id": None,
            "chain_seq": None,
            "entry_hash": None,
            "peer_org_id": None,
            "detail_pretty": detail_pretty,
        })
    for r in traffic_rows:
        detail_pretty, recipient = _pretty_and_recipient(r.get("details"))
        raw_result = r.get("result")
        status_display = "success" if raw_result == "ok" else raw_result
        unified.append({
            "source": "traffic",
            "timestamp": r.get("timestamp"),
            "agent_id": r.get("agent_id"),
            "event": r.get("event_type"),
            "status": status_display,
            "target": recipient,
            "tool_name": None,
            "duration_ms": None,
            "request_id": None,
            "session_id": r.get("session_id"),
            "org_id": r.get("org_id"),
            "chain_seq": r.get("chain_seq"),
            "entry_hash": r.get("entry_hash"),
            "peer_org_id": r.get("peer_org_id"),
            "detail_pretty": detail_pretty,
        })

    # ISO-8601 strings sort correctly as plain strings, no parsing needed.
    unified.sort(key=lambda x: x["timestamp"] or "", reverse=True)

    total = len(unified)
    admin_total = sum(1 for e in unified if e["source"] == "admin")
    traffic_total = total - admin_total
    total_pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page
    entries = unified[offset:offset + per_page]

    agents = await list_agents()
    agent_ids = sorted(set(a["agent_id"] for a in agents))

    return templates.TemplateResponse("audit.html", _ctx(
        request, session,
        active="audit",
        entries=entries,
        agent_ids=agent_ids,
        actions=actions,
        agent_filter=agent_filter,
        action_filter=action_filter,
        status_filter=status_filter,
        source_filter=source_filter,
        page=page,
        total_pages=total_pages,
        admin_total=admin_total,
        traffic_total=traffic_total,
        total=total,
    ))
