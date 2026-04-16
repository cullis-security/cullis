"""Dashboard CRUD for ADR-006 intra-org policies (follow-up to PR #126).

The policy *engine* shipped in #126 reads from ``local_policies`` at
every ``/v1/egress/send``; the table's been populated by raw SQL
since then. This module adds the admin UI for that table so operators
aren't writing INSERTs by hand.

Kept in a separate file (not merged into ``dashboard/router.py``) so
this PR doesn't collide with unrelated dashboard work from parallel
agents. Wired in ``main.py`` via ``include_router`` with prefix
``/proxy/local-policies``.

Rule JSON matches the broker's message-rule schema (ADR-006 §5 /
#126 commit body) so a policy authored here behaves identically to
one on the broker side.
"""
from __future__ import annotations

import json
import logging
import pathlib
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text

from mcp_proxy.config import get_settings
from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
    verify_csrf,
)
from mcp_proxy.db import get_db, log_audit

_log = logging.getLogger("mcp_proxy.dashboard.policies_local")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

router = APIRouter(prefix="/proxy/local-policies", tags=["dashboard-local-policies"])


def _ctx(request: Request, session: ProxyDashboardSession, **kwargs) -> dict:
    return {
        "request": request,
        "session": session,
        "csrf_token": session.csrf_token,
        "active": "local_policies",
        **kwargs,
    }


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _list_rows() -> list[dict]:
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT policy_id, org_id, policy_type, name, scope,
                       rules_json, enabled, created_at, updated_at
                  FROM local_policies
                 ORDER BY created_at DESC
                """
            ),
        )
        return [dict(r) for r in result.mappings()]


# ── Pages ────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def policies_list(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    rows = await _list_rows()
    settings = get_settings()
    return templates.TemplateResponse("policies_local.html", _ctx(
        request, session,
        policies=rows,
        default_org_id=settings.org_id or "",
    ))


@router.post("/create")
async def policies_create(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    name = str(form.get("name", "")).strip()
    org_id = str(form.get("org_id", "")).strip() or None
    policy_type = str(form.get("policy_type", "message")).strip()
    rules_raw = str(form.get("rules_json", "")).strip()
    enabled = 1 if form.get("enabled") in ("1", "true", "on") else 0

    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    if policy_type not in ("message", "session"):
        raise HTTPException(status_code=400, detail="policy_type must be message|session")
    try:
        parsed = json.loads(rules_raw) if rules_raw else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"invalid rules_json: {exc}") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="rules_json must be an object")

    policy_id = str(uuid.uuid4())
    ts = _iso_now()
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_policies (
                    policy_id, org_id, policy_type, name, scope,
                    rules_json, enabled, created_at, updated_at
                ) VALUES (
                    :pid, :org, :ptype, :name, 'intra',
                    :rules, :enabled, :ts, :ts
                )
                """
            ),
            {
                "pid": policy_id,
                "org": org_id,
                "ptype": policy_type,
                "name": name,
                "rules": json.dumps(parsed, separators=(",", ":"), sort_keys=True),
                "enabled": enabled,
                "ts": ts,
            },
        )

    await log_audit(
        agent_id="admin",
        action="local_policy.create",
        status="success",
        detail=f"policy_id={policy_id} name={name} enabled={enabled}",
    )
    return RedirectResponse(url="/proxy/local-policies", status_code=303)


@router.post("/{policy_id}/toggle")
async def policies_toggle(policy_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    async with get_db() as conn:
        # Flip enabled in one statement so concurrent admins don't race.
        await conn.execute(
            text(
                """
                UPDATE local_policies
                   SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END,
                       updated_at = :ts
                 WHERE policy_id = :pid
                """
            ),
            {"pid": policy_id, "ts": _iso_now()},
        )
    await log_audit(
        agent_id="admin",
        action="local_policy.toggle",
        status="success",
        detail=f"policy_id={policy_id}",
    )
    return RedirectResponse(url="/proxy/local-policies", status_code=303)


@router.post("/{policy_id}/delete")
async def policies_delete(policy_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    async with get_db() as conn:
        await conn.execute(
            text("DELETE FROM local_policies WHERE policy_id = :pid"),
            {"pid": policy_id},
        )
    await log_audit(
        agent_id="admin",
        action="local_policy.delete",
        status="success",
        detail=f"policy_id={policy_id}",
    )
    return RedirectResponse(url="/proxy/local-policies", status_code=303)
