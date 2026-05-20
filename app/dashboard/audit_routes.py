"""Court dashboard — Audit Log sub-router.

Sprint 2 / F-B-202 PR-9 of 10. Extracts the audit-log table + hash
chain verification (section 14 of router.py).

Mounted via ``router.include_router(audit_routes.router)``.

Routes (2):

  GET  /dashboard/audit              search + paginate audit table
  POST /dashboard/audit/verify       run audit-chain integrity check (admin-only)

The verify endpoint is the dispute-grade Track-A control point — it
walks the hash chain end-to-end and reports the first broken link.
Admin-only + CSRF gated.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.dashboard._helpers import _build_audit_event_dict, _ctx
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login, verify_csrf
from app.db.audit import AuditLog
from app.db.database import get_db

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-audit"])

_AUDIT_LIMIT = 200


@router.get("/audit", response_class=HTMLResponse)
async def audit_log(
    request: Request,
    q: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    query = select(AuditLog).order_by(AuditLog.id.desc())

    if q:
        q = q[:100]  # Limit search term length to prevent expensive LIKE queries
        # Escape LIKE wildcards in user input to prevent pattern abuse
        _escaped = q.replace("%", r"\%").replace("_", r"\_")
        pattern = f"%{_escaped}%"
        query = query.where(or_(
            AuditLog.event_type.ilike(pattern),
            AuditLog.agent_id.ilike(pattern),
            AuditLog.org_id.ilike(pattern),
            AuditLog.result.ilike(pattern),
            AuditLog.details.ilike(pattern),
        ))

    query = query.limit(_AUDIT_LIMIT)
    result = await db.execute(query)
    events = result.scalars().all()

    event_list = [_build_audit_event_dict(e) for e in events]

    return templates.TemplateResponse("audit.html",
        _ctx(request, session, active="audit", events=event_list, query=q or "", limit=_AUDIT_LIMIT)
    )


@router.post("/audit/verify", response_class=HTMLResponse)
async def verify_audit_chain(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin-only: verify the cryptographic integrity of the audit log chain."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from app.db.audit import verify_chain
    is_valid, total, broken_id = await verify_chain(db)

    verify_result = {"valid": is_valid, "total": total, "broken_id": broken_id}

    # Re-render audit page with verification result
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(_AUDIT_LIMIT)
    result = await db.execute(query)
    events = result.scalars().all()
    event_list = [_build_audit_event_dict(e) for e in events]

    return templates.TemplateResponse("audit.html",
        _ctx(request, session, active="audit", events=event_list, query="",
             limit=_AUDIT_LIMIT, verify_result=verify_result)
    )
