"""Mastio admin API for workload principals (ADR-020 / ADR-019).

Frontdesk shared-mode is the canonical workload: one container that
hosts N user principals via SSO. Workloads stay intra-org by design —
they never federate, and the Court federation registry has no view of
them. This API powers the dashboard's Workloads tab on the *local*
Mastio admin only.

Endpoints:
- POST ``/v1/admin/workloads``    create a workload row (idempotent)
- GET  ``/v1/admin/workloads``    list, optional filter on runtime_status / q

Auth: ``X-Admin-Secret``.
"""
from __future__ import annotations

import hmac
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from mcp_proxy.config import get_settings
from mcp_proxy.db import get_db


_log = logging.getLogger("mcp_proxy.admin.workloads")

router = APIRouter(prefix="/v1/admin/workloads", tags=["admin"])


_VALID_STATUS = ("running", "stopped", "unhealthy", "unknown")


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


class WorkloadCreateRequest(BaseModel):
    workload_name: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    display_name: str = Field("", max_length=256)
    image_digest: Optional[str] = Field(None, max_length=128)
    runtime_status: str = Field("unknown")


class WorkloadOut(BaseModel):
    principal_id: str
    workload_name: str
    display_name: Optional[str]
    image_digest: Optional[str]
    runtime_status: str
    hosted_principals_count: int
    hosted_principals_sample: list[str]
    last_active: Optional[str]
    created_at: str


class WorkloadListResponse(BaseModel):
    workloads: list[WorkloadOut]
    total: int


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _principal_id(org_id: str, workload_name: str) -> str:
    return f"{org_id}::workload::{workload_name}"


async def _hosted_principals(
    conn, org_id: str,
) -> tuple[int, list[str]]:
    """Return (count, sample) of user principals on this Mastio.

    The current shared-mode Frontdesk hosts every active user under
    its single workload, so the dashboard view shows the count of
    users this Mastio knows about as the workload's hosted count.
    A future revision may track explicit container → user binding;
    for now this matches the demo's mental model.
    """
    # Plain ``ORDER BY created_at DESC`` keeps the SQL portable across
    # SQLite (sandbox) + Postgres (prod) without depending on
    # ``NULLS LAST``.
    rows = (await conn.execute(
        text(
            "SELECT principal_id FROM local_user_principals "
            " ORDER BY created_at DESC LIMIT 5"
        ),
    )).mappings().all()
    sample = [r["principal_id"] for r in rows]
    total = (await conn.execute(
        text("SELECT COUNT(*) AS n FROM local_user_principals"),
    )).mappings().first()
    return int(total["n"] if total else 0), sample


@router.post(
    "",
    response_model=WorkloadOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin_secret)],
)
async def create_workload(
    body: WorkloadCreateRequest, request: Request,
) -> WorkloadOut:
    if body.runtime_status not in _VALID_STATUS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"runtime_status must be one of {_VALID_STATUS}",
        )
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None or not getattr(mgr, "ca_loaded", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent manager not initialized — Org CA not loaded",
        )
    pid = _principal_id(mgr.org_id, body.workload_name)
    now = _now_iso()
    async with get_db() as conn:
        existing = (await conn.execute(
            text(
                "SELECT principal_id, workload_name, display_name, "
                "       image_digest, runtime_status, "
                "       created_at, last_active_at "
                "  FROM local_workload_principals "
                " WHERE principal_id = :pid"
            ),
            {"pid": pid},
        )).mappings().first()
        if existing is None:
            await conn.execute(
                text(
                    """
                    INSERT INTO local_workload_principals (
                        principal_id, workload_name, display_name,
                        image_digest, runtime_status, created_at
                    ) VALUES (
                        :pid, :wname, :disp, :img, :status, :now
                    )
                    """
                ),
                {
                    "pid": pid, "wname": body.workload_name,
                    "disp": body.display_name or None,
                    "img": body.image_digest,
                    "status": body.runtime_status, "now": now,
                },
            )
            count, sample = await _hosted_principals(conn, mgr.org_id)
            return WorkloadOut(
                principal_id=pid,
                workload_name=body.workload_name,
                display_name=body.display_name or None,
                image_digest=body.image_digest,
                runtime_status=body.runtime_status,
                hosted_principals_count=count,
                hosted_principals_sample=sample,
                last_active=None,
                created_at=now,
            )
        count, sample = await _hosted_principals(conn, mgr.org_id)
        return WorkloadOut(
            principal_id=existing["principal_id"],
            workload_name=existing["workload_name"],
            display_name=existing["display_name"],
            image_digest=existing["image_digest"],
            runtime_status=existing["runtime_status"],
            hosted_principals_count=count,
            hosted_principals_sample=sample,
            last_active=existing["last_active_at"],
            created_at=existing["created_at"],
        )


@router.get(
    "",
    response_model=WorkloadListResponse,
    dependencies=[Depends(_require_admin_secret)],
)
async def list_workloads(
    runtime_status: Optional[str] = Query(None),
    q: Optional[str] = Query(None, max_length=128),
    limit: int = Query(200, ge=1, le=500),
) -> WorkloadListResponse:
    if runtime_status is not None and runtime_status not in _VALID_STATUS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"runtime_status must be one of {_VALID_STATUS}",
        )
    sql = (
        "SELECT principal_id, workload_name, display_name, image_digest, "
        "       runtime_status, created_at, last_active_at "
        "  FROM local_workload_principals "
    )
    where: list[str] = []
    params: dict[str, object] = {"limit": limit}
    if runtime_status is not None:
        where.append("runtime_status = :status")
        params["status"] = runtime_status
    if q:
        where.append(
            "(LOWER(workload_name) LIKE :q OR "
            " LOWER(COALESCE(display_name, '')) LIKE :q)"
        )
        params["q"] = f"%{q.lower()}%"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT :limit"
    async with get_db() as conn:
        rows = (await conn.execute(text(sql), params)).mappings().all()
        count, sample = await _hosted_principals(conn, "")
    items = [
        WorkloadOut(
            principal_id=r["principal_id"],
            workload_name=r["workload_name"],
            display_name=r["display_name"],
            image_digest=r["image_digest"],
            runtime_status=r["runtime_status"],
            hosted_principals_count=count,
            hosted_principals_sample=sample,
            last_active=r["last_active_at"],
            created_at=r["created_at"],
        )
        for r in rows
    ]
    return WorkloadListResponse(workloads=items, total=len(items))
