"""Admin-side read-only audit log endpoint.

ADR-025 Phase 4 — exposes ``GET /admin/audit`` so the admin UI (Phase 5)
and external scripts can review recent local-auth events. Gated by the
``X-Admin-Secret`` header which is compared timing-safe against the
``CULLIS_CONNECTOR_ADMIN_SECRET`` environment variable. The router does
**not** mount itself into ``cullis_connector.web``; integration in
production lives in Phase 5 (admin UI), and tests mount it via a
fixture-local FastAPI app.
"""
from __future__ import annotations

import hmac
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel

from cullis_connector.identity.audit import LocalAuditLog, query_audit

_log = logging.getLogger("cullis_connector.admin.audit")

ADMIN_SECRET_ENV = "CULLIS_CONNECTOR_ADMIN_SECRET"
ADMIN_SECRET_HEADER = "X-Admin-Secret"


# ── Auth dep ──────────────────────────────────────────────────────────────


def _expected_admin_secret() -> str | None:
    """Read the admin secret from env at request time (not import time).

    Tests can override via ``monkeypatch.setenv`` before issuing the
    request, and operators can rotate the secret without restarting
    the FastAPI app.
    """
    value = os.environ.get(ADMIN_SECRET_ENV, "").strip()
    return value or None


def _require_admin_secret(
    x_admin_secret: str | None = Header(default=None, alias=ADMIN_SECRET_HEADER),
) -> None:
    expected = _expected_admin_secret()
    if expected is None:
        # No secret configured — refuse all requests rather than open
        # the endpoint by default. Operator must set the env var.
        raise HTTPException(status_code=403, detail="admin secret not configured")
    if not x_admin_secret or not hmac.compare_digest(x_admin_secret, expected):
        raise HTTPException(status_code=403, detail="invalid admin secret")


# ── config_dir resolution ─────────────────────────────────────────────────


def _config_dir_from_request(request: Request) -> Path:
    """Resolve the active Connector config directory.

    The router reads ``request.app.state.connector_config_dir`` when
    set (the integration that mounts the router is responsible for
    populating it), and falls back to the
    ``CULLIS_CONNECTOR_CONFIG_DIR`` env var. Raises 500 if neither is
    available — tests mount the router with the state attribute set.
    """
    config_dir = getattr(request.app.state, "connector_config_dir", None)
    if config_dir is None:
        env_value = os.environ.get("CULLIS_CONNECTOR_CONFIG_DIR", "").strip()
        if env_value:
            config_dir = env_value
    if config_dir is None:
        raise HTTPException(
            status_code=500,
            detail="connector config_dir is not configured for this app",
        )
    return Path(config_dir)


# ── Schemas ───────────────────────────────────────────────────────────────


class AuditEntry(BaseModel):
    id: int
    ts: str
    ip: str | None
    user_name: str | None
    action: str
    status: str
    detail: str | None


class AuditListResponse(BaseModel):
    entries: list[AuditEntry]
    total: int


def _row_to_schema(row: LocalAuditLog) -> AuditEntry:
    return AuditEntry(
        id=row.id,
        ts=row.ts,
        ip=row.ip,
        user_name=row.user_name,
        action=row.action,
        status=row.status,
        detail=row.detail,
    )


# ── Router ────────────────────────────────────────────────────────────────


router = APIRouter(prefix="/admin", tags=["admin-audit"])


@router.get(
    "/audit",
    response_model=AuditListResponse,
    dependencies=[Depends(_require_admin_secret)],
)
async def list_audit(
    request: Request,
    since: str | None = Query(default=None, description="ISO-8601 UTC lower bound"),
    user_name: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> AuditListResponse:
    config_dir = _config_dir_from_request(request)

    since_dt: datetime | None = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"invalid 'since' value: {exc}"
            ) from None

    rows = await query_audit(
        config_dir,
        since=since_dt,
        user_name=user_name,
        action=action,
        limit=limit,
    )
    entries = [_row_to_schema(r) for r in rows]
    return AuditListResponse(entries=entries, total=len(entries))


__all__: list[Any] = ["router", "ADMIN_SECRET_ENV", "ADMIN_SECRET_HEADER"]
