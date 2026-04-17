"""Dashboard CRUD for ADR-007 Phase 1 — local_mcp_resources + bindings.

Admin UI for the two tables deployed by PR #1 (schema) and populated
at startup by PR #2 (loader). Any mutation here triggers
``reload_resources()`` so the aggregated MCP endpoint (PR #3) reflects
the new state without a proxy restart.

Kept in a dedicated module — not merged into ``dashboard/router.py`` —
matching the policies_local.py (PR #136) layout for patch-fighting.
Wired in ``main.py`` via ``include_router``.
"""
from __future__ import annotations

import json
import logging
import pathlib
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mcp_proxy.config import get_settings
from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
    verify_csrf,
)
from mcp_proxy.db import get_db, log_audit
from mcp_proxy.spiffe import InvalidRecipient, build_resource_spiffe
from mcp_proxy.tools.registry import tool_registry
from mcp_proxy.tools.resource_loader import reload_resources

_log = logging.getLogger("mcp_proxy.dashboard.mcp_resources")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

router = APIRouter(prefix="/proxy/backends", tags=["dashboard-backends"])

# Legacy redirect — keep old /proxy/mcp-resources path working for existing
# bookmarks and audit-log links that reference it.
_legacy_router = APIRouter()


@_legacy_router.get("/proxy/mcp-resources", include_in_schema=False)
async def _legacy_redirect_root() -> RedirectResponse:
    return RedirectResponse(url="/proxy/backends", status_code=301)

_ALLOWED_AUTH_TYPES = {"none", "bearer", "api_key", "mtls"}
# Matches mcp_proxy.spiffe._PATH_COMPONENT_RE so a resource name always
# round-trips through build_resource_spiffe / parse_resource_spiffe.
_NAME_RE = re.compile(r"^[a-zA-Z0-9\-_\.]+$")


def _ctx(request: Request, session: ProxyDashboardSession, **kwargs) -> dict:
    return {
        "request": request,
        "session": session,
        "csrf_token": session.csrf_token,
        "active": "backends",
        **kwargs,
    }


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_allowed_domains(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"invalid allowed_domains JSON: {exc}",
        ) from exc
    if not isinstance(parsed, list):
        raise HTTPException(
            status_code=400,
            detail="allowed_domains must be a JSON array",
        )
    return [str(d) for d in parsed]


def _validate_endpoint_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="endpoint_url must start with http:// or https://",
        )
    return url


def _validate_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    if not _NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail="name must match [a-zA-Z0-9._-]+",
        )
    return name


def _validate_auth_type(auth_type: str) -> str:
    if auth_type not in _ALLOWED_AUTH_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"auth_type must be one of {sorted(_ALLOWED_AUTH_TYPES)}",
        )
    return auth_type


async def _list_resources(trust_domain: str) -> list[dict]:
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                """
                SELECT r.resource_id, r.org_id, r.name, r.description,
                       r.endpoint_url, r.auth_type, r.auth_secret_ref,
                       r.required_capability, r.allowed_domains, r.enabled,
                       r.created_at, r.updated_at,
                       COALESCE(SUM(CASE WHEN b.revoked_at IS NULL THEN 1 ELSE 0 END), 0) AS active_count,
                       COUNT(b.binding_id) AS total_count
                  FROM local_mcp_resources r
                  LEFT JOIN local_agent_resource_bindings b
                    ON b.resource_id = r.resource_id
                 GROUP BY r.resource_id
                 ORDER BY r.created_at DESC
                """
            )
        )).mappings().all()

    out: list[dict] = []
    for r in rows:
        entry = dict(r)
        try:
            entry["spiffe_uri"] = build_resource_spiffe(
                trust_domain=trust_domain,
                org=entry["org_id"] or "",
                resource_name=entry["name"],
            )
        except InvalidRecipient:
            entry["spiffe_uri"] = None
        out.append(entry)
    return out


async def _list_bindings_by_resource() -> dict[str, list[dict]]:
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                """
                SELECT binding_id, agent_id, resource_id, org_id,
                       granted_by, granted_at, revoked_at
                  FROM local_agent_resource_bindings
                 ORDER BY granted_at DESC
                """
            )
        )).mappings().all()
    grouped: dict[str, list[dict]] = {}
    for r in rows:
        grouped.setdefault(r["resource_id"], []).append(dict(r))
    return grouped


async def _list_bindable_agents() -> list[dict]:
    """UNION of internal_agents + local_agents active, for the binding dropdown."""
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                """
                SELECT agent_id, display_name, 'internal' AS source
                  FROM internal_agents WHERE is_active = 1
                UNION ALL
                SELECT agent_id, display_name, 'local' AS source
                  FROM local_agents WHERE is_active = 1
                 ORDER BY agent_id
                """
            )
        )).mappings().all()
    return [dict(r) for r in rows]


async def _reload_registry_safe() -> None:
    try:
        await reload_resources(tool_registry)
    except Exception:
        _log.exception("Failed to hot-reload MCP resources registry")


# ── Pages ────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def resources_list(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    settings = get_settings()
    resources = await _list_resources(settings.trust_domain)
    bindings_by_rid = await _list_bindings_by_resource()
    bindable = await _list_bindable_agents()

    return templates.TemplateResponse("mcp_resources.html", _ctx(
        request, session,
        resources=resources,
        bindings_by_rid=bindings_by_rid,
        bindable_agents=bindable,
        default_org_id=settings.org_id or "",
        trust_domain=settings.trust_domain,
    ))


@router.post("/create")
async def resources_create(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    name = _validate_name(str(form.get("name", "")))
    description = str(form.get("description", "")).strip() or None
    endpoint_url = _validate_endpoint_url(str(form.get("endpoint_url", "")))
    auth_type = _validate_auth_type(str(form.get("auth_type", "none")).strip())
    auth_secret_ref = str(form.get("auth_secret_ref", "")).strip() or None
    required_capability = str(form.get("required_capability", "")).strip() or None
    allowed_domains = _parse_allowed_domains(str(form.get("allowed_domains", "")))
    org_id = str(form.get("org_id", "")).strip() or None
    enabled = 1 if form.get("enabled") in ("1", "true", "on") else 0

    resource_id = str(uuid.uuid4())
    ts = _iso_now()
    try:
        async with get_db() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO local_mcp_resources (
                        resource_id, org_id, name, description, endpoint_url,
                        auth_type, auth_secret_ref, required_capability,
                        allowed_domains, enabled, created_at, updated_at
                    ) VALUES (
                        :rid, :org, :name, :description, :endpoint_url,
                        :auth_type, :auth_secret_ref, :required_capability,
                        :allowed_domains, :enabled, :ts, :ts
                    )
                    """
                ),
                {
                    "rid": resource_id,
                    "org": org_id,
                    "name": name,
                    "description": description,
                    "endpoint_url": endpoint_url,
                    "auth_type": auth_type,
                    "auth_secret_ref": auth_secret_ref,
                    "required_capability": required_capability,
                    "allowed_domains": json.dumps(
                        allowed_domains, separators=(",", ":"), sort_keys=True,
                    ),
                    "enabled": enabled,
                    "ts": ts,
                },
            )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail=f"resource name '{name}' already exists in this org",
        ) from exc

    await _reload_registry_safe()
    await log_audit(
        agent_id="admin",
        action="mcp_resource.create",
        status="success",
        detail=f"resource_id={resource_id} name={name} enabled={enabled}",
    )
    return RedirectResponse(url="/proxy/backends", status_code=303)


@router.post("/{resource_id}/update")
async def resources_update(resource_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    description = str(form.get("description", "")).strip() or None
    endpoint_url = _validate_endpoint_url(str(form.get("endpoint_url", "")))
    auth_type = _validate_auth_type(str(form.get("auth_type", "none")).strip())
    auth_secret_ref = str(form.get("auth_secret_ref", "")).strip() or None
    required_capability = str(form.get("required_capability", "")).strip() or None
    allowed_domains = _parse_allowed_domains(str(form.get("allowed_domains", "")))

    async with get_db() as conn:
        await conn.execute(
            text(
                """
                UPDATE local_mcp_resources
                   SET description = :description,
                       endpoint_url = :endpoint_url,
                       auth_type = :auth_type,
                       auth_secret_ref = :auth_secret_ref,
                       required_capability = :required_capability,
                       allowed_domains = :allowed_domains,
                       updated_at = :ts
                 WHERE resource_id = :rid
                """
            ),
            {
                "rid": resource_id,
                "description": description,
                "endpoint_url": endpoint_url,
                "auth_type": auth_type,
                "auth_secret_ref": auth_secret_ref,
                "required_capability": required_capability,
                "allowed_domains": json.dumps(
                    allowed_domains, separators=(",", ":"), sort_keys=True,
                ),
                "ts": _iso_now(),
            },
        )

    await _reload_registry_safe()
    await log_audit(
        agent_id="admin",
        action="mcp_resource.update",
        status="success",
        detail=f"resource_id={resource_id}",
    )
    return RedirectResponse(url="/proxy/backends", status_code=303)


@router.post("/{resource_id}/toggle")
async def resources_toggle(resource_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    async with get_db() as conn:
        await conn.execute(
            text(
                """
                UPDATE local_mcp_resources
                   SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END,
                       updated_at = :ts
                 WHERE resource_id = :rid
                """
            ),
            {"rid": resource_id, "ts": _iso_now()},
        )

    await _reload_registry_safe()
    await log_audit(
        agent_id="admin",
        action="mcp_resource.toggle",
        status="success",
        detail=f"resource_id={resource_id}",
    )
    return RedirectResponse(url="/proxy/backends", status_code=303)


@router.post("/{resource_id}/delete")
async def resources_delete(resource_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    async with get_db() as conn:
        # Cascade bindings first (no physical FK on local_* tables).
        await conn.execute(
            text("DELETE FROM local_agent_resource_bindings WHERE resource_id = :rid"),
            {"rid": resource_id},
        )
        await conn.execute(
            text("DELETE FROM local_mcp_resources WHERE resource_id = :rid"),
            {"rid": resource_id},
        )

    await _reload_registry_safe()
    await log_audit(
        agent_id="admin",
        action="mcp_resource.delete",
        status="success",
        detail=f"resource_id={resource_id}",
    )
    return RedirectResponse(url="/proxy/backends", status_code=303)


# ── Bindings ─────────────────────────────────────────────────────────

@router.post("/bindings/create")
async def bindings_create(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    agent_id = str(form.get("agent_id", "")).strip()
    resource_id = str(form.get("resource_id", "")).strip()
    if not agent_id or not resource_id:
        raise HTTPException(
            status_code=400,
            detail="agent_id and resource_id are required",
        )

    # Look up the resource's org_id so the binding row denormalizes it.
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT org_id FROM local_mcp_resources WHERE resource_id = :rid"),
            {"rid": resource_id},
        )).first()
        if row is None:
            raise HTTPException(status_code=404, detail="resource not found")
        org_id = row[0]

        binding_id = str(uuid.uuid4())
        try:
            await conn.execute(
                text(
                    """
                    INSERT INTO local_agent_resource_bindings (
                        binding_id, agent_id, resource_id, org_id,
                        granted_by, granted_at, revoked_at
                    ) VALUES (
                        :bid, :aid, :rid, :org,
                        'admin', :ts, NULL
                    )
                    """
                ),
                {
                    "bid": binding_id,
                    "aid": agent_id,
                    "rid": resource_id,
                    "org": org_id,
                    "ts": _iso_now(),
                },
            )
        except IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="binding already exists for this agent+resource pair",
            ) from exc

    await log_audit(
        agent_id="admin",
        action="mcp_binding.create",
        status="success",
        detail=f"binding_id={binding_id} agent={agent_id} resource={resource_id}",
    )
    return RedirectResponse(url="/proxy/backends", status_code=303)


@router.post("/bindings/{binding_id}/revoke")
async def bindings_revoke(binding_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    async with get_db() as conn:
        await conn.execute(
            text(
                """
                UPDATE local_agent_resource_bindings
                   SET revoked_at = :ts
                 WHERE binding_id = :bid
                """
            ),
            {"bid": binding_id, "ts": _iso_now()},
        )
    await log_audit(
        agent_id="admin",
        action="mcp_binding.revoke",
        status="success",
        detail=f"binding_id={binding_id}",
    )
    return RedirectResponse(url="/proxy/backends", status_code=303)


@router.post("/bindings/{binding_id}/reapprove")
async def bindings_reapprove(binding_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    async with get_db() as conn:
        await conn.execute(
            text(
                """
                UPDATE local_agent_resource_bindings
                   SET revoked_at = NULL
                 WHERE binding_id = :bid
                """
            ),
            {"bid": binding_id},
        )
    await log_audit(
        agent_id="admin",
        action="mcp_binding.reapprove",
        status="success",
        detail=f"binding_id={binding_id}",
    )
    return RedirectResponse(url="/proxy/backends", status_code=303)


@router.post("/bindings/{binding_id}/delete")
async def bindings_delete(binding_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    async with get_db() as conn:
        await conn.execute(
            text("DELETE FROM local_agent_resource_bindings WHERE binding_id = :bid"),
            {"bid": binding_id},
        )
    await log_audit(
        agent_id="admin",
        action="mcp_binding.delete",
        status="success",
        detail=f"binding_id={binding_id}",
    )
    return RedirectResponse(url="/proxy/backends", status_code=303)
