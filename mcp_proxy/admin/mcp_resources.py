"""Proxy admin JSON API for MCP resources + bindings.

Complements ``mcp_proxy/dashboard/mcp_resources.py`` (HTML form-based).
The Connector Desktop uses these endpoints to let users register MCP
servers and bind agents without leaving the Connector UI — same flow
the enrollment screen already provides for agents (ADR-009 sandbox).

Auth: ``X-Admin-Secret`` — same contract as ``/v1/admin/mastio-pubkey``.
Callers pass the Mastio admin secret in-process; the Connector prompts
for it the first time and keeps it in memory (not on disk).
"""
from __future__ import annotations

import hmac
import json
import logging
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mcp_proxy.config import get_settings
from mcp_proxy.db import get_db, log_audit
from mcp_proxy.tools.resource_loader import reload_resources


_log = logging.getLogger("mcp_proxy.admin.mcp_resources")

router = APIRouter(prefix="/v1/admin/mcp-resources", tags=["admin"])


_ALLOWED_AUTH_TYPES = {"none", "bearer", "api_key", "mtls"}
_NAME_RE = re.compile(r"^[a-zA-Z0-9\-_\.]+$")


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_name(name: str) -> str:
    name = name.strip()
    if not name or not _NAME_RE.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="name: letters, digits, dash, underscore, dot only",
        )
    if len(name) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="name: max 64 chars",
        )
    return name


def _validate_endpoint_url(url: str) -> str:
    url = url.strip()
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="endpoint_url must start with http:// or https://",
        )
    return url


def _validate_auth_type(auth_type: str) -> str:
    auth_type = auth_type.strip() or "none"
    if auth_type not in _ALLOWED_AUTH_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"auth_type: must be one of {sorted(_ALLOWED_AUTH_TYPES)}",
        )
    return auth_type


# ── Resources ───────────────────────────────────────────────────────────

class MCPResourceCreate(BaseModel):
    name: str
    endpoint_url: str
    description: str | None = None
    auth_type: str = "none"
    auth_secret_ref: str | None = None
    required_capability: str | None = None
    allowed_domains: list[str] = Field(default_factory=list)
    org_id: str | None = None
    enabled: bool = True


class MCPResourceOut(BaseModel):
    resource_id: str
    name: str
    endpoint_url: str
    description: str | None
    auth_type: str
    required_capability: str | None
    enabled: bool
    org_id: str | None
    created_at: str


@router.get(
    "",
    response_model=list[MCPResourceOut],
    dependencies=[Depends(_require_admin_secret)],
)
async def list_resources():
    """Return MCP resources registered on this proxy."""
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                """
                SELECT resource_id, name, endpoint_url, description, auth_type,
                       required_capability, enabled, org_id, created_at
                  FROM local_mcp_resources
                 ORDER BY created_at DESC
                """
            )
        )).mappings().all()
    return [
        MCPResourceOut(
            resource_id=r["resource_id"],
            name=r["name"],
            endpoint_url=r["endpoint_url"],
            description=r["description"],
            auth_type=r["auth_type"],
            required_capability=r["required_capability"],
            enabled=bool(r["enabled"]),
            org_id=r["org_id"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@router.post(
    "",
    response_model=MCPResourceOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin_secret)],
)
async def create_resource(body: MCPResourceCreate):
    name = _validate_name(body.name)
    endpoint_url = _validate_endpoint_url(body.endpoint_url)
    auth_type = _validate_auth_type(body.auth_type)
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
                    "org": body.org_id,
                    "name": name,
                    "description": body.description,
                    "endpoint_url": endpoint_url,
                    "auth_type": auth_type,
                    "auth_secret_ref": body.auth_secret_ref,
                    "required_capability": body.required_capability,
                    "allowed_domains": json.dumps(
                        body.allowed_domains, separators=(",", ":"), sort_keys=True,
                    ),
                    "enabled": 1 if body.enabled else 0,
                    "ts": ts,
                },
            )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"resource name '{name}' already exists in this org",
        ) from exc

    try:
        await reload_resources()
    except Exception as exc:  # defensive
        _log.warning("reload_resources failed after create: %s", exc)

    await log_audit(
        agent_id="admin",
        action="mcp_resource.create",
        status="success",
        detail=f"api=json resource_id={resource_id} name={name}",
    )

    return MCPResourceOut(
        resource_id=resource_id,
        name=name,
        endpoint_url=endpoint_url,
        description=body.description,
        auth_type=auth_type,
        required_capability=body.required_capability,
        enabled=body.enabled,
        org_id=body.org_id,
        created_at=ts,
    )


@router.delete(
    "/{resource_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_require_admin_secret)],
)
async def delete_resource(resource_id: str):
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT resource_id FROM local_mcp_resources WHERE resource_id = :rid"),
            {"rid": resource_id},
        )).first()
        if row is None:
            raise HTTPException(status_code=404, detail="resource not found")

        # Cascade bindings (no physical FK on local_* tables).
        await conn.execute(
            text("DELETE FROM local_agent_resource_bindings WHERE resource_id = :rid"),
            {"rid": resource_id},
        )
        await conn.execute(
            text("DELETE FROM local_mcp_resources WHERE resource_id = :rid"),
            {"rid": resource_id},
        )

    try:
        await reload_resources()
    except Exception as exc:
        _log.warning("reload_resources failed after delete: %s", exc)

    await log_audit(
        agent_id="admin",
        action="mcp_resource.delete",
        status="success",
        detail=f"api=json resource_id={resource_id}",
    )


# ── Bindings ────────────────────────────────────────────────────────────

class MCPBindingCreate(BaseModel):
    agent_id: str
    resource_id: str
    # ADR-020 — typed principal. ``"agent"`` is the legacy default and
    # the only value any pre-ADR-020 caller emits, so the field stays
    # optional and defaults to ``"agent"``. The Frontdesk admin UI
    # passes ``"user"`` when binding a user principal to a resource.
    principal_type: str = Field("agent", pattern=r"^(agent|user|workload)$")


class MCPBindingOut(BaseModel):
    binding_id: str
    agent_id: str
    principal_type: str
    resource_id: str
    org_id: str | None
    granted_at: str
    revoked_at: str | None


@router.post(
    "/bindings",
    response_model=MCPBindingOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin_secret)],
)
async def create_binding(body: MCPBindingCreate):
    agent_id = body.agent_id.strip()
    resource_id = body.resource_id.strip()
    principal_type = body.principal_type.strip()
    if not agent_id or not resource_id:
        raise HTTPException(
            status_code=400, detail="agent_id and resource_id are required",
        )

    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT org_id FROM local_mcp_resources WHERE resource_id = :rid"),
            {"rid": resource_id},
        )).first()
        if row is None:
            raise HTTPException(status_code=404, detail="resource not found")
        org_id = row[0]

        binding_id = str(uuid.uuid4())
        ts = _iso_now()
        try:
            await conn.execute(
                text(
                    """
                    INSERT INTO local_agent_resource_bindings (
                        binding_id, agent_id, principal_type, resource_id,
                        org_id, granted_by, granted_at, revoked_at
                    ) VALUES (
                        :bid, :aid, :pt, :rid,
                        :org, 'admin', :ts, NULL
                    )
                    """
                ),
                {
                    "bid": binding_id,
                    "aid": agent_id,
                    "pt": principal_type,
                    "rid": resource_id,
                    "org": org_id,
                    "ts": ts,
                },
            )
        except IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail=(
                    "binding already exists for this principal+resource pair"
                ),
            ) from exc

    await log_audit(
        agent_id="admin",
        action="mcp_binding.create",
        status="success",
        detail=(
            f"api=json binding_id={binding_id} principal_type={principal_type} "
            f"agent={agent_id} resource={resource_id}"
        ),
    )

    return MCPBindingOut(
        binding_id=binding_id,
        agent_id=agent_id,
        principal_type=principal_type,
        resource_id=resource_id,
        org_id=org_id,
        granted_at=ts,
        revoked_at=None,
    )


@router.delete(
    "/bindings/{binding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_require_admin_secret)],
)
async def revoke_binding(binding_id: str):
    """Soft-delete: set ``revoked_at`` to the current timestamp."""
    ts = _iso_now()
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                UPDATE local_agent_resource_bindings
                   SET revoked_at = :ts
                 WHERE binding_id = :bid AND revoked_at IS NULL
                """
            ),
            {"bid": binding_id, "ts": ts},
        )
        if result.rowcount == 0:
            raise HTTPException(
                status_code=404, detail="binding not found or already revoked",
            )
    await log_audit(
        agent_id="admin",
        action="mcp_binding.revoke",
        status="success",
        detail=f"api=json binding_id={binding_id}",
    )
