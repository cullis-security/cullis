"""ADR-029 Phase E, dashboard authoring for tool-level PDP rules.

The Phase C endpoint ``POST /v1/policy/tool-call`` reads
``policy_rules.tool_rules`` and decides allow/deny per tool. Until
this module landed an admin had to hand-edit the JSON document on
the existing ``/proxy/policies`` Built-in Rules tab. This router
exposes a structured form-based UI so the operator can add, edit,
and remove tool rules without touching JSON.

Storage stays the same single ``policy_rules`` config row, so a
policy authored here is identical to one written in the JSON
editor; the two surfaces stay in sync because they read and write
the same underlying document.

Routes:
  GET  /proxy/policies/tool-rules                 list + form
  POST /proxy/policies/tool-rules/save            upsert one rule
  POST /proxy/policies/tool-rules/{tool}/delete   remove one rule
"""
from __future__ import annotations

import json
import logging
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
    verify_csrf,
)
from mcp_proxy.db import get_config, log_audit, set_config

_log = logging.getLogger("mcp_proxy.dashboard.tool_rules")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

router = APIRouter(
    prefix="/proxy/policies/tool-rules",
    tags=["dashboard-tool-rules"],
)


def _ctx(request: Request, session: ProxyDashboardSession, **kwargs) -> dict:
    return {
        "request": request,
        "session": session,
        "csrf_token": session.csrf_token,
        "active": "policies",
        **kwargs,
    }


def _parse_csv_list(raw: str) -> list[str]:
    """Take a comma-or-newline separated string and return the
    trimmed non-empty tokens. Used to convert form fields like
    ``allowed_principals="acme::user::mario, acme::user::anna"`` into
    a list."""
    if not raw:
        return []
    parts: list[str] = []
    for chunk in raw.replace("\r", "").replace("\n", ",").split(","):
        token = chunk.strip()
        if token:
            parts.append(token)
    return parts


async def _read_policy_rules() -> dict:
    rules_raw = await get_config("policy_rules")
    if not rules_raw:
        return {}
    try:
        return json.loads(rules_raw)
    except json.JSONDecodeError:
        _log.warning("policy_rules JSON malformed, treating as empty doc")
        return {}


async def _write_policy_rules(doc: dict) -> None:
    await set_config("policy_rules", json.dumps(doc, indent=2, sort_keys=True))


@router.get("", response_class=HTMLResponse)
async def tool_rules_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    doc = await _read_policy_rules()
    tool_rules_raw = doc.get("tool_rules") if isinstance(doc.get("tool_rules"), dict) else {}
    # Normalise for the template: stable ordering by tool name.
    rules_list: list[dict] = []
    for tool_name in sorted(tool_rules_raw.keys()):
        rule = tool_rules_raw[tool_name]
        if not isinstance(rule, dict):
            continue
        rules_list.append({
            "tool_name": tool_name,
            "allowed_principals": rule.get("allowed_principals") or [],
            "denied_principals": rule.get("denied_principals") or [],
            "allowed_models": rule.get("allowed_models") or [],
            "allowed_mcp_servers": rule.get("allowed_mcp_servers") or [],
        })

    return templates.TemplateResponse(
        "tool_rules.html",
        _ctx(request, session, rules=rules_list),
    )


@router.post("/save")
async def tool_rules_save(request: Request):
    """Upsert a single tool rule keyed by its tool_name.

    The form sends the four list-shaped fields as comma/newline
    separated text for ergonomics; the handler parses them back into
    lists before merging into the JSON document.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    tool_name = str(form.get("tool_name", "")).strip()
    if not tool_name:
        raise HTTPException(status_code=400, detail="tool_name is required")

    rule: dict = {}
    ap = _parse_csv_list(str(form.get("allowed_principals", "")))
    if ap:
        rule["allowed_principals"] = ap
    dp = _parse_csv_list(str(form.get("denied_principals", "")))
    if dp:
        rule["denied_principals"] = dp
    am = _parse_csv_list(str(form.get("allowed_models", "")))
    if am:
        rule["allowed_models"] = am
    ams = _parse_csv_list(str(form.get("allowed_mcp_servers", "")))
    if ams:
        rule["allowed_mcp_servers"] = ams

    doc = await _read_policy_rules()
    tool_rules = doc.get("tool_rules") if isinstance(doc.get("tool_rules"), dict) else {}
    tool_rules[tool_name] = rule
    doc["tool_rules"] = tool_rules
    await _write_policy_rules(doc)

    await log_audit(
        agent_id="admin",
        action="policy.tool_rules_upsert",
        status="success",
        tool_name=tool_name,
        details={"rule_keys": list(rule.keys())},
    )

    return RedirectResponse(url="/proxy/policies/tool-rules", status_code=303)


@router.post("/{tool_name}/delete")
async def tool_rules_delete(tool_name: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    doc = await _read_policy_rules()
    tool_rules = doc.get("tool_rules") if isinstance(doc.get("tool_rules"), dict) else {}
    if tool_name in tool_rules:
        del tool_rules[tool_name]
        doc["tool_rules"] = tool_rules
        await _write_policy_rules(doc)
        await log_audit(
            agent_id="admin",
            action="policy.tool_rules_delete",
            status="success",
            tool_name=tool_name,
        )

    return RedirectResponse(url="/proxy/policies/tool-rules", status_code=303)
