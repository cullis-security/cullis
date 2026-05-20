"""Mastio dashboard — Vault sub-router.

Sprint F-B-201 PR-9 of 10. Extracts the Vault connection management
(view + save + connectivity probe + key migration) from the
``mcp_proxy/dashboard/router.py`` god-object. Four routes total.

Mounted via ``router.include_router(vault_routes.router)``.

Routes (4):

  GET  /proxy/vault               Vault settings page
  POST /proxy/vault/save          persist vault_addr + vault_token (CSRF)
  POST /proxy/vault/test          HTMX connectivity probe (CSRF + SSRF guard)
  POST /proxy/vault/migrate-keys  bulk-migrate agent keys to Vault (CSRF + approval hook)
"""
from __future__ import annotations

import html as _html
import logging
import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_VAULT_MIGRATE_KEYS,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import (
    _ctx,
    _enforce_safe_outbound_url,
    _test_vault_connectivity,
)
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-vault"])


@router.get("/vault", response_class=HTMLResponse)
async def vault_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_config, get_db

    vault_addr = await get_config("vault_addr") or ""
    vault_token = await get_config("vault_token") or ""

    # Count local keys (agent_key:* in proxy_config)
    from sqlalchemy import text

    async with get_db() as db:
        result = await db.execute(
            text("SELECT COUNT(*) as cnt FROM proxy_config WHERE key LIKE 'agent_key:%'")
        )
        row = result.mappings().first()
        local_key_count = row["cnt"] if row else 0

    # Test vault status if configured
    vault_status = None
    vault_key_count = 0
    if vault_addr and vault_token:
        import httpx
        from mcp_proxy.config import get_settings as _s, vault_tls_verify
        try:
            async with httpx.AsyncClient(
                verify=vault_tls_verify(_s()), timeout=5.0,
            ) as client:
                resp = await client.get(
                    f"{vault_addr.rstrip('/')}/v1/sys/health",
                    headers={"X-Vault-Token": vault_token},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vault_status = {
                        "connected": not data.get("sealed", True),
                        "version": data.get("version", "unknown"),
                        "sealed": data.get("sealed", False),
                    }
                else:
                    vault_status = {"connected": False, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            vault_status = {"connected": False, "error": str(exc)}

    return templates.TemplateResponse("vault.html", _ctx(
        request, session,
        active="vault",
        vault_addr=vault_addr,
        vault_token=vault_token,
        vault_status=vault_status,
        local_key_count=local_key_count,
        vault_key_count=vault_key_count,
    ))


@router.post("/vault/save")
async def vault_save(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import set_config, log_audit

    form = await request.form()
    vault_addr = str(form.get("vault_addr", "")).strip()
    vault_token = str(form.get("vault_token", "")).strip()

    errors: list[str] = []
    if not vault_addr:
        errors.append("Vault address is required.")
    if not vault_token:
        errors.append("Vault token is required.")

    if errors:
        return templates.TemplateResponse("vault.html", _ctx(
            request, session,
            active="vault",
            vault_addr=vault_addr,
            vault_token="",
            vault_status=None,
            local_key_count=0,
            vault_key_count=0,
            errors=errors,
        ))

    # Test connectivity before saving
    ok, msg = await _test_vault_connectivity(vault_addr, vault_token)
    if not ok:
        return templates.TemplateResponse("vault.html", _ctx(
            request, session,
            active="vault",
            vault_addr=vault_addr,
            vault_token="",
            vault_status={"connected": False, "error": msg},
            local_key_count=0,
            vault_key_count=0,
            errors=[f"Vault connectivity test failed: {msg}"],
        ))

    await set_config("vault_addr", vault_addr)
    await set_config("vault_token", vault_token)

    await log_audit(
        agent_id="admin",
        action="vault.configure",
        status="success",
        detail=f"addr={vault_addr}",
    )

    return RedirectResponse(url="/proxy/vault", status_code=303)


@router.post("/vault/test")
async def vault_test(request: Request):
    """HTMX endpoint: test Vault connectivity."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return HTMLResponse('<span class="text-red-400">Not authenticated</span>')

    # Wave B G1 — verify CSRF + SSRF allow-list (Vault behind a docker
    # network is the legitimate case; ``allow_private=True`` honours
    # the same flag that PDP webhooks use, so docker-compose vault://
    # addresses keep working).
    if not await verify_csrf(request, session):
        return HTMLResponse('<span class="text-red-400">CSRF check failed</span>')

    form = await request.form()
    vault_addr = str(form.get("vault_addr", "")).strip()
    vault_token = str(form.get("vault_token", "")).strip()

    if not vault_addr:
        return HTMLResponse('<span class="text-red-400">Enter a Vault address first</span>')

    try:
        _enforce_safe_outbound_url(vault_addr, allow_private=True)
    except ValueError as exc:
        return HTMLResponse(
            f'<span class="text-red-400">{_html.escape(str(exc))}</span>'
        )

    if not vault_token:
        # Try stored token
        from mcp_proxy.db import get_config
        vault_token = await get_config("vault_token") or ""

    if not vault_token:
        return HTMLResponse('<span class="text-red-400">Vault token required</span>')

    ok, msg = await _test_vault_connectivity(vault_addr, vault_token)
    if ok:
        return HTMLResponse(
            '<span class="text-emerald-400 flex items-center gap-1.5">'
            '<span class="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>'
            'Vault connected and unsealed</span>'
        )
    return HTMLResponse(f'<span class="text-red-400">{_html.escape(msg)}</span>')


@router.post("/vault/migrate-keys")
async def vault_migrate_keys(request: Request):
    """Migrate all agent private keys from DB to Vault."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    intercept = await maybe_intercept_for_approval(
        session=session, action_type=ACTION_VAULT_MIGRATE_KEYS, payload={},
        request=request,
    )
    if intercept is not None:
        return intercept

    from mcp_proxy.db import get_config, get_db, log_audit

    vault_addr = await get_config("vault_addr")
    vault_token = await get_config("vault_token")
    if not vault_addr or not vault_token:
        raise HTTPException(status_code=400, detail="Vault not configured")

    # Test connectivity first
    ok, msg = await _test_vault_connectivity(vault_addr, vault_token)
    if not ok:
        raise HTTPException(status_code=502, detail=f"Vault unreachable: {msg}")

    import httpx
    from mcp_proxy.config import get_settings as _s, vault_tls_verify

    _vault_verify = vault_tls_verify(_s())

    # Find all agent keys stored in proxy_config (agent_key:* pattern)
    from sqlalchemy import text

    migrated = 0
    async with get_db() as db:
        result = await db.execute(
            text("SELECT key, value FROM proxy_config WHERE key LIKE 'agent_key:%'")
        )
        rows = result.mappings().all()

    for row in rows:
        agent_id = row["key"].replace("agent_key:", "", 1)
        key_pem = row["value"]
        path = f"secret/data/mcp-proxy/agents/{agent_id}"
        url = f"{vault_addr.rstrip('/')}/v1/{path}"
        try:
            async with httpx.AsyncClient(verify=_vault_verify, timeout=5.0) as client:
                resp = await client.post(
                    url,
                    json={"data": {"key_pem": key_pem}},
                    headers={"X-Vault-Token": vault_token},
                )
                resp.raise_for_status()
            migrated += 1
        except Exception as exc:
            _log.warning("Failed to migrate key for %s to Vault: %s", agent_id, exc)

    await log_audit(
        agent_id="admin",
        action="vault.migrate_keys",
        status="success",
        detail=f"Migrated {migrated}/{len(rows)} agent keys to Vault",
    )

    return RedirectResponse(url="/proxy/vault", status_code=303)
