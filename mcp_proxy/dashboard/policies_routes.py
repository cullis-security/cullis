"""Mastio dashboard — Policies sub-router.

Sprint F-B-201 PR-6 of 10. Extracts the policy editor (rules JSON +
PDP webhook configuration + webhook connectivity probe) from
``mcp_proxy/dashboard/router.py``. Three routes total.

Mounted via ``router.include_router(policies_routes.router)``.

Routes (3):

  GET  /proxy/policies               policy editor page
  POST /proxy/policies/save          persist rules / PDP config (CSRF + approval gate)
  POST /proxy/policies/test-webhook  HTMX PDP webhook probe (CSRF + SSRF-guarded)
"""
from __future__ import annotations

import html as _html
import json
import logging
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_POLICIES_SAVE,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import _ctx, _enforce_safe_outbound_url
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-policies"])


@router.get("/policies", response_class=HTMLResponse)
async def policies_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_config

    rules_json = await get_config("policy_rules") or json.dumps({
        "allowed_orgs": [],
        "blocked_agents": [],
        "capabilities": {},
    }, indent=2)

    pdp_url = await get_config("pdp_webhook_url") or ""
    pdp_timeout = await get_config("pdp_timeout") or "5"

    return templates.TemplateResponse("policies.html", _ctx(
        request, session,
        active="policies",
        rules_json=rules_json,
        pdp_url=pdp_url,
        pdp_timeout=pdp_timeout,
    ))


@router.post("/policies/save")
async def policies_save(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    payload = {k: str(v) for k, v in form.items() if k != "csrf_token"}
    intercept = await maybe_intercept_for_approval(
        session=session, action_type=ACTION_POLICIES_SAVE, payload=payload,
        request=request,
    )
    if intercept is not None:
        return intercept

    from mcp_proxy.db import set_config, get_config, log_audit

    tab = str(form.get("tab", "rules"))

    if tab == "rules":
        rules_raw = str(form.get("rules_json", ""))
        try:
            parsed = json.loads(rules_raw)
            rules_json = json.dumps(parsed, indent=2)
        except json.JSONDecodeError:
            # Re-render with error
            pdp_url = await get_config("pdp_webhook_url") or ""
            pdp_timeout = await get_config("pdp_timeout") or "5"
            return templates.TemplateResponse("policies.html", _ctx(
                request, session,
                active="policies",
                rules_json=rules_raw,
                pdp_url=pdp_url,
                pdp_timeout=pdp_timeout,
                error="Invalid JSON in policy rules.",
            ))

        await set_config("policy_rules", rules_json)
        await log_audit(
            agent_id="admin",
            action="policy.update_rules",
            status="success",
        )

    elif tab == "pdp":
        pdp_url = str(form.get("pdp_url", "")).strip()
        pdp_timeout = str(form.get("pdp_timeout", "5")).strip()
        await set_config("pdp_webhook_url", pdp_url)
        await set_config("pdp_timeout", pdp_timeout)
        await log_audit(
            agent_id="admin",
            action="policy.update_pdp",
            status="success",
            detail=f"url={pdp_url}, timeout={pdp_timeout}s",
        )

    return RedirectResponse(url="/proxy/policies", status_code=303)


@router.post("/policies/test-webhook")
async def policies_test_webhook(request: Request):
    """HTMX endpoint: test PDP webhook connectivity."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return HTMLResponse('<span class="text-red-400">Not authenticated</span>')

    # Wave B G1 — verify CSRF + SSRF allow-list + escape exception text
    if not await verify_csrf(request, session):
        return HTMLResponse('<span class="text-red-400">CSRF check failed</span>')

    form = await request.form()
    webhook_url = str(form.get("pdp_url", "")).strip()

    if not webhook_url:
        return HTMLResponse('<span class="text-red-400">Enter a webhook URL first</span>')

    try:
        _enforce_safe_outbound_url(webhook_url)
    except ValueError as exc:
        return HTMLResponse(
            f'<span class="text-red-400">{_html.escape(str(exc))}</span>'
        )

    try:
        import httpx
        test_payload = {
            "agent_id": "test::probe",
            "action": "tool_execute",
            "tool": "test_tool",
            "capabilities": ["test"],
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(webhook_url, json=test_payload)
            if resp.status_code == 200:
                return HTMLResponse(
                    '<span class="text-emerald-400 flex items-center gap-1.5">'
                    '<span class="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>'
                    'Webhook responded OK</span>'
                )
            return HTMLResponse(
                f'<span class="text-yellow-400">HTTP {resp.status_code}</span>'
            )
    except Exception as exc:
        return HTMLResponse(
            f'<span class="text-red-400">Connection failed: '
            f'{_html.escape(str(exc))}</span>'
        )
