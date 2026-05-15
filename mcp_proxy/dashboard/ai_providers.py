"""Dashboard CRUD for AI provider credentials (ADR-017 Phase 4).

Pairs with :mod:`mcp_proxy.admin.ai_providers` (the headless API). The
admin secret API is what scripts and Terraform talk to; this router is
what an org admin sees in the browser at ``/proxy/ai-providers``.

Each provider in :data:`mcp_proxy.egress.provider_catalog.PROVIDERS`
gets a card with the credentials form. Save / Delete / Test / Toggle
actions live behind CSRF-protected POSTs and write through the same
``upsert_ai_provider_creds`` / ``delete_ai_provider_creds`` /
``set_ai_provider_enabled`` helpers used by the API. The audit chain
sees them with the dashboard session's principal as ``updated_by``,
keeping API + UI rows traceable in the same way.
"""
from __future__ import annotations

import logging
import pathlib
import time

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
    verify_csrf,
)
from mcp_proxy.db import (
    delete_ai_provider_creds,
    get_ai_provider_creds,
    list_ai_provider_creds,
    log_audit,
    set_ai_provider_enabled,
    upsert_ai_provider_creds,
)
from mcp_proxy.egress.provider_catalog import (
    PROVIDERS,
    InvalidCredentialsError,
    fetch_ollama_models,
    get_spec,
    mask_creds,
    validate_creds,
)


_log = logging.getLogger("mcp_proxy.dashboard.ai_providers")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(prefix="/proxy/ai-providers", tags=["dashboard-ai-providers"])


def _ctx(request: Request, session: ProxyDashboardSession, **kwargs) -> dict:
    return {
        "request": request,
        "session": session,
        "csrf_token": session.csrf_token,
        "active": "ai_providers",
        **kwargs,
    }


def _provider_view(provider: str, row: dict | None) -> dict:
    """Render-friendly dict for the ``ai_providers.html`` template."""
    spec = get_spec(provider)
    if spec is None:
        raise HTTPException(404, f"unknown provider {provider!r}")
    return {
        "provider": spec.provider,
        "display_name": spec.display_name,
        "docs_url": spec.docs_url,
        "fields": [
            {
                "name": f.name,
                "label": f.label,
                "secret": f.secret,
                "required": f.required,
                "placeholder": f.placeholder,
                "help_text": f.help_text,
            }
            for f in spec.fields
        ],
        "static_models": list(spec.static_models),
        "dynamic_models": spec.dynamic_models,
        "configured": row is not None,
        "enabled": bool(row["enabled"]) if row else False,
        "creds_masked": mask_creds(provider, row["creds"] or {}) if row else {},
        "updated_at": row.get("updated_at") if row else None,
        "updated_by": row.get("updated_by") if row else None,
    }


async def _all_providers_view() -> list[dict]:
    rows = await list_ai_provider_creds()
    by_name = {r["provider"]: r for r in rows}
    return [_provider_view(p, by_name.get(p)) for p in PROVIDERS]


# ── routes ──────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    providers = await _all_providers_view()
    return templates.TemplateResponse(
        "ai_providers.html",
        _ctx(request, session, providers=providers),
    )


@router.post("/{provider}/save")
async def save(request: Request, provider: str) -> RedirectResponse:
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(403, "csrf token mismatch")

    if provider.lower() not in PROVIDERS:
        raise HTTPException(404, f"unknown provider {provider!r}")
    p = provider.lower()
    spec = get_spec(p)
    assert spec is not None  # known provider per check above

    form = await request.form()
    inbound: dict[str, str] = {}
    for fld in spec.fields:
        raw = form.get(fld.name) or ""
        raw = str(raw).strip()
        if fld.secret and raw == "***":
            # User left the masked placeholder untouched — keep the
            # existing value rather than wiping it.
            existing = await get_ai_provider_creds(p)
            if existing and existing["creds"].get(fld.name):
                inbound[fld.name] = existing["creds"][fld.name]
                continue
            raw = ""
        if raw:
            inbound[fld.name] = raw

    enabled = bool(form.get("enabled"))

    try:
        cleaned = validate_creds(p, inbound)
    except InvalidCredentialsError as exc:
        # Re-render the page with the error inline.
        providers = await _all_providers_view()
        return templates.TemplateResponse(
            "ai_providers.html",
            _ctx(
                request, session,
                providers=providers,
                error_provider=p,
                error=str(exc),
            ),
            status_code=400,
        )

    updated_by = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )
    await upsert_ai_provider_creds(
        p, cleaned, enabled=enabled, updated_by=updated_by,
    )
    await log_audit(
        agent_id=updated_by,
        action="ai_provider.upsert",
        status="success",
        details={
            "provider": p,
            "enabled": enabled,
            "fields": sorted(cleaned.keys()),
            "via": "dashboard",
        },
    )
    _log.info(
        "dashboard ai-provider upsert provider=%s enabled=%s by=%s",
        p, enabled, updated_by,
    )
    return RedirectResponse(
        url=f"/proxy/ai-providers?saved={p}",
        status_code=303,
    )


@router.post("/{provider}/delete")
async def delete(request: Request, provider: str) -> RedirectResponse:
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(403, "csrf token mismatch")

    p = provider.lower()
    if p not in PROVIDERS:
        raise HTTPException(404, f"unknown provider {provider!r}")
    deleted = await delete_ai_provider_creds(p)
    if deleted:
        updated_by = (
            getattr(session, "principal_id", None)
            or getattr(session, "username", None)
            or "dashboard-admin"
        )
        await log_audit(
            agent_id=updated_by,
            action="ai_provider.delete",
            status="success",
            details={"provider": p, "via": "dashboard"},
        )
        _log.info("dashboard ai-provider delete provider=%s by=%s",
                  p, updated_by)
    return RedirectResponse(
        url=f"/proxy/ai-providers?deleted={p}",
        status_code=303,
    )


@router.post("/{provider}/toggle")
async def toggle(
    request: Request,
    provider: str,
    enabled: bool = Form(...),
) -> RedirectResponse:
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(403, "csrf token mismatch")

    p = provider.lower()
    if p not in PROVIDERS:
        raise HTTPException(404, f"unknown provider {provider!r}")
    changed = await set_ai_provider_enabled(p, enabled)
    if changed:
        updated_by = (
            getattr(session, "principal_id", None)
            or getattr(session, "username", None)
            or "dashboard-admin"
        )
        await log_audit(
            agent_id=updated_by,
            action=("ai_provider.enable" if enabled
                    else "ai_provider.disable"),
            status="success",
            details={"provider": p, "via": "dashboard"},
        )
    return RedirectResponse(
        url=f"/proxy/ai-providers?toggled={p}",
        status_code=303,
    )


@router.post("/{provider}/test", response_class=HTMLResponse)
async def test(request: Request, provider: str) -> HTMLResponse:
    """HTMX endpoint — returns a small fragment with the probe result."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(403, "csrf token mismatch")

    p = provider.lower()
    if p not in PROVIDERS:
        raise HTTPException(404, f"unknown provider {provider!r}")

    row = await get_ai_provider_creds(p)
    if row is None:
        return HTMLResponse(
            f"<div class='text-red-400 text-xs'>Provider <code>{p}</code> "
            "is not configured.</div>",
            status_code=400,
        )
    creds = dict(row["creds"] or {})

    started = time.perf_counter()
    # We deliberately re-import the live probe from the admin module to
    # share the implementation; the dashboard call sidesteps the
    # ``X-Admin-Secret`` because the dashboard already authenticated
    # the operator via ``require_login``.
    from mcp_proxy.admin.ai_providers import _live_probe
    try:
        result = await _live_probe(p, creds)
    except Exception as exc:  # pragma: no cover — defensive
        _log.warning("dashboard test failed provider=%s err=%s", p, exc)
        return HTMLResponse(
            f"<div class='text-red-400 text-xs'>Probe error: "
            f"{type(exc).__name__}: {exc}</div>",
            status_code=200,
        )
    elapsed_ms = int((time.perf_counter() - started) * 1000)

    if result.status == "ok":
        sample = ", ".join(result.sample_models[:3]) or "—"
        return HTMLResponse(
            f"<div class='text-emerald-400 text-xs'>"
            f"OK · {elapsed_ms} ms · sample: <span class='font-mono'>"
            f"{sample}</span></div>",
        )
    if result.status == "unsupported":
        return HTMLResponse(
            f"<div class='text-amber-400 text-xs'>{result.detail}</div>",
        )
    return HTMLResponse(
        f"<div class='text-red-400 text-xs'>FAIL · {elapsed_ms} ms · "
        f"{(result.detail or 'unknown error')[:200]}</div>",
    )


@router.get("/{provider}/ollama-models", response_class=HTMLResponse)
async def ollama_models(request: Request, provider: str) -> HTMLResponse:
    """Dashboard helper — shows the live model list for an Ollama row."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if provider.lower() != "ollama":
        raise HTTPException(404, "this endpoint is Ollama-only")
    row = await get_ai_provider_creds("ollama")
    if row is None:
        return HTMLResponse(
            "<div class='text-gray-500 text-xs'>Save the base URL first.</div>",
        )
    api_base = row["creds"].get("api_base", "")
    models = await fetch_ollama_models(api_base, timeout_s=2.0)
    if not models:
        return HTMLResponse(
            f"<div class='text-amber-400 text-xs'>No models reachable at "
            f"<code>{api_base}/api/tags</code>.</div>",
        )
    items = "".join(
        f"<li class='font-mono text-xs text-gray-300'>{m}</li>"
        for m in models
    )
    return HTMLResponse(
        f"<ul class='space-y-1 mt-2'>{items}</ul>",
    )
