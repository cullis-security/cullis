"""Dashboard authoring for Rego policies.

The engine (mcp_proxy.policy.rego_engine) compiles the operator's
Rego source via the bundled ``opa build`` CLI and persists the
resulting WASM bundle alongside the source. This router is the
authoring surface — a text editor + Save + Delete + inline compile
diagnostics that the operator hits at ``/proxy/policies/rego``.

Storage lives inside the existing ``policy_rules`` config row
under two new fields:

  * ``rego`` (string) — the operator's source, kept for the editor
    to load back on the next page view.
  * ``rego_wasm_base64`` (string) — the compiled WASM bundle,
    base64-encoded so it fits inside the JSON container.

Save flow:

  1. Operator pastes / edits Rego in the textarea, clicks Save.
  2. POST handler calls ``compile_rego(source)``.
  3. On success: persist both fields, audit ``policy.rego_save``,
     redirect back with a success flash.
  4. On RegoCompileError: keep the operator's source in the form
     (no persistence), re-render the page with the ``opa build``
     diagnostic shown inline so they can fix the exact line / column.

Delete flow:

  Strips ``rego`` + ``rego_wasm_base64`` from the JSON document so
  static rules remain active on the next decision. Resources requiring
  delegation deny until Rego is restored. The source is wiped from disk too (no
  hidden retention).

Routes:
  GET  /proxy/policies/rego              editor + diagnostics
  POST /proxy/policies/rego/save         compile + persist
  POST /proxy/policies/rego/delete       wipe rego + rego_wasm
"""
from __future__ import annotations

import base64
import json
import logging
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
    verify_csrf,
)
from mcp_proxy.db import get_config, log_audit, set_config
from mcp_proxy.policy.rego_engine import (
    RegoCompileError,
    compile_rego,
)

_log = logging.getLogger("mcp_proxy.dashboard.rego_rules")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(
    prefix="/proxy/policies/rego",
    tags=["dashboard-rego-rules"],
)


def _ctx(request: Request, session: ProxyDashboardSession, **kwargs) -> dict:
    return {
        "request": request,
        "session": session,
        "csrf_token": session.csrf_token,
        "active": "policies",
        **kwargs,
    }


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


_DEFAULT_EXAMPLE = """package cullis.policy

# Default deny tool_call — explicit allow only.
tool_call := {"decision": "deny", "reason": "no rule matched"} if {
    not allow_tool_call
}

tool_call := {"decision": "allow"} if { allow_tool_call }

# KYC screener: read-only KYC tools.
allow_tool_call if {
    input.agent_id == "orga::kyc-screener"
    input.tool_name == "sanctions_lookup"
}

# Default-allow session.
session := {"decision": "allow"}
"""


@router.get("", response_class=HTMLResponse)
async def rego_rules_page(request: Request):
    """Render the Rego editor with the operator's current source.

    When no Rego has been authored yet, pre-fill the textarea with
    the canonical example so the operator has a starting point
    instead of a blank screen. The example mirrors the worked
    example in the docs page.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    doc = await _read_policy_rules()
    source = doc.get("rego") or ""
    wasm_b64 = doc.get("rego_wasm_base64") or ""

    # Surface the SHA-256 prefix of the compiled bundle so the
    # operator can correlate runtime audit lines
    # (``PDP[rego] decision=allow sha256=ab12cd34...``) with the
    # policy version on the editor page.
    sha_prefix = ""
    if wasm_b64:
        try:
            import hashlib
            wasm = base64.b64decode(wasm_b64, validate=True)
            sha_prefix = hashlib.sha256(wasm).hexdigest()[:12]
        except (ValueError, TypeError):
            sha_prefix = "(invalid base64)"

    return templates.TemplateResponse(
        "rego_rules.html",
        _ctx(
            request, session,
            source=source or _DEFAULT_EXAMPLE,
            has_source=bool(source),
            sha_prefix=sha_prefix,
            compile_error=None,
        ),
    )


@router.post("/save")
async def rego_rules_save(request: Request):
    """Compile the submitted Rego and persist on success.

    On RegoCompileError the page is re-rendered with the operator's
    source preserved in the textarea + the ``opa build`` diagnostic
    inline. No partial persistence: the previous compiled bundle
    stays in place until a successful compile replaces it.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    source = str(form.get("rego", "")).strip()
    if not source:
        # Empty submit: treat as delete (operator cleared the textarea
        # then hit Save). Same outcome as the explicit Delete button.
        return await _delete_rego(session)

    try:
        compiled = compile_rego(source)
    except RegoCompileError as exc:
        _log.info(
            "policy.rego_save compile failed: %s — preserving previous bundle",
            str(exc)[:200],
        )
        await log_audit(
            agent_id="admin",
            action="policy.rego_save",
            status="compile_error",
            details={"error": str(exc)[:500]},
        )
        # Re-render the editor with the operator's source intact and
        # the diagnostic shown next to the Save button.
        doc = await _read_policy_rules()
        prev_wasm_b64 = doc.get("rego_wasm_base64") or ""
        sha_prefix = ""
        if prev_wasm_b64:
            try:
                import hashlib
                wasm = base64.b64decode(prev_wasm_b64, validate=True)
                sha_prefix = hashlib.sha256(wasm).hexdigest()[:12] + " (previous)"
            except (ValueError, TypeError):
                pass
        return templates.TemplateResponse(
            "rego_rules.html",
            _ctx(
                request, session,
                source=source,
                has_source=True,
                sha_prefix=sha_prefix,
                compile_error=str(exc),
            ),
            status_code=400,
        )

    wasm_b64 = base64.b64encode(compiled.wasm).decode("ascii")
    doc = await _read_policy_rules()
    doc["rego"] = source
    doc["rego_wasm_base64"] = wasm_b64
    await _write_policy_rules(doc)

    await log_audit(
        agent_id="admin",
        action="policy.rego_save",
        status="success",
        details={
            "wasm_bytes": len(compiled.wasm),
            "sha256_prefix": compiled.sha256[:12],
        },
    )

    return RedirectResponse(url="/proxy/policies/rego", status_code=303)


@router.post("/delete")
async def rego_rules_delete(request: Request):
    """Wipe both ``rego`` and ``rego_wasm_base64`` from the config."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return await _delete_rego(session)


async def _delete_rego(session: ProxyDashboardSession) -> RedirectResponse:
    """Shared delete path — used by both the explicit Delete button
    and an empty Save submit (operator cleared the textarea)."""
    doc = await _read_policy_rules()
    had_source = bool(doc.get("rego"))
    doc.pop("rego", None)
    doc.pop("rego_wasm_base64", None)
    if had_source:
        await _write_policy_rules(doc)
        await log_audit(
            agent_id="admin",
            action="policy.rego_delete",
            status="success",
        )
    return RedirectResponse(url="/proxy/policies/rego", status_code=303)
