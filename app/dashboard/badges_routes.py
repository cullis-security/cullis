"""Court dashboard — HTMX nav badge fragments.

Sprint 2 / F-B-202 PR-4 of 10. Extracts the six badge endpoints that
the dashboard nav auto-refreshes every 10s. Each handler returns a
small HTML fragment (a count chip or empty string when zero); the
empty-string response keeps the badge hidden when no attention is
needed.

Wired via ``router.include_router(badges_routes.router)``.
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.broker.db_models import SessionRecord
from app.dashboard import _demo_cast
from app.dashboard._helpers import _count_chip
from app.dashboard._template_env import build_templates
from app.dashboard.session import get_session
from app.db.database import get_db
from app.registry.org_store import OrganizationRecord
from app.registry.store import AgentRecord

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-badges"])


@router.get("/badge/pending-orgs", response_class=HTMLResponse)
async def badge_pending_orgs(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    if not session.logged_in or not session.is_admin:
        return ""
    count = (await db.execute(
        select(func.count(OrganizationRecord.org_id))
        .where(OrganizationRecord.status == "pending")
    )).scalar() or 0
    if count > 0:
        return f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-yellow-500/20 text-yellow-400">{count}</span>'
    return ""


@router.get("/badge/pending-sessions", response_class=HTMLResponse)
async def badge_pending_sessions(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    if not session.logged_in:
        return ""
    count_q = select(func.count(SessionRecord.session_id)).where(SessionRecord.status == "pending")
    count = (await db.execute(count_q)).scalar() or 0
    if count > 0:
        return f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-yellow-500/20 text-yellow-400">{count}</span>'
    return ""


@router.get("/badge/users-count", response_class=HTMLResponse)
async def badge_users_count(request: Request):
    session = get_session(request)
    if not session.logged_in:
        return ""
    return _count_chip(len(_demo_cast.users_cast()))


@router.get("/badge/agents-count", response_class=HTMLResponse)
async def badge_agents_count(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    if not session.logged_in:
        return ""
    count = (await db.execute(select(func.count(AgentRecord.agent_id)))).scalar() or 0
    if count == 0:
        # During demo recording the registry may not yet be populated.
        # Fall back to the cast count so the badge is screenshot-ready.
        count = len(_demo_cast.agent_extras_keys())
    return _count_chip(int(count))


@router.get("/badge/workloads-count", response_class=HTMLResponse)
async def badge_workloads_count(request: Request):
    session = get_session(request)
    if not session.logged_in:
        return ""
    return _count_chip(len(_demo_cast.workloads_cast()))


@router.get("/badge/resources-count", response_class=HTMLResponse)
async def badge_resources_count(request: Request):
    session = get_session(request)
    if not session.logged_in:
        return ""
    return _count_chip(len(_demo_cast.resources_cast()))
