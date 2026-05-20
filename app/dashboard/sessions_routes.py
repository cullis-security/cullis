"""Court dashboard — Sessions sub-router.

Sprint 2 / F-B-202 PR-9 of 10. Extracts the session-list page
(section 13 of router.py).

Mounted via ``router.include_router(sessions_routes.router)``.

Routes (1):

  GET  /dashboard/sessions      list (filter by status, last 100)

Read-only — no CSRF / sealed gate.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.broker.db_models import SessionMessageRecord, SessionRecord
from app.dashboard._helpers import _ctx
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login
from app.db.database import get_db

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-sessions"])


@router.get("/sessions", response_class=HTMLResponse)
async def sessions_list(
    request: Request,
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(SessionRecord).order_by(SessionRecord.created_at.desc())
    if status:
        q = q.where(SessionRecord.status == status)
    q = q.limit(100)

    result = await db.execute(q)
    sessions = result.scalars().all()

    # Count messages per session
    msg_counts = {}
    if sessions:
        session_ids = [s.session_id for s in sessions]
        count_q = (
            select(SessionMessageRecord.session_id, func.count(SessionMessageRecord.id))
            .where(SessionMessageRecord.session_id.in_(session_ids))
            .group_by(SessionMessageRecord.session_id)
        )
        for row in (await db.execute(count_q)).all():
            msg_counts[row[0]] = row[1]

    session_list = []
    for s in sessions:
        session_list.append({
            "session_id": s.session_id,
            "initiator_agent_id": s.initiator_agent_id,
            "initiator_org_id": s.initiator_org_id,
            "target_agent_id": s.target_agent_id,
            "target_org_id": s.target_org_id,
            "status": s.status,
            "message_count": msg_counts.get(s.session_id, 0),
            "created_at": s.created_at,
        })

    return templates.TemplateResponse("sessions.html",
        _ctx(request, session, active="sessions", sessions=session_list, status_filter=status)
    )
