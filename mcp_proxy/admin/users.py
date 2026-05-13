"""Mastio admin API for user principals.

Pairs with ``mcp_proxy/admin/agents.py`` and ``mcp_proxy/admin/mcp_resources.py``.
Lets an org admin pre-create a user-principal row so the dashboard's
Users tab renders before the user has touched the Frontdesk SSO flow.
The CSR signing path on ``/v1/principals/csr`` upserts into the same
table on every signature, so a user that *does* go through SSO first
shows up automatically.

Endpoints:
- POST ``/v1/admin/users``   create a principal row (idempotent on conflict)
- GET  ``/v1/admin/users``   list, optionally filtered by reach / surface / q

Auth: ``X-Admin-Secret`` (same contract as ``/v1/admin/agents``).
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


_log = logging.getLogger("mcp_proxy.admin.users")

router = APIRouter(prefix="/v1/admin/users", tags=["admin"])


# ── auth ────────────────────────────────────────────────────────────────


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


# ── models ──────────────────────────────────────────────────────────────


_VALID_REACH = ("intra", "cross", "both")


class UserCreateRequest(BaseModel):
    user_name: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    display_name: str = Field("", max_length=256)
    reach: str = Field("intra")
    surface: Optional[str] = Field(None, max_length=64)


class UserOut(BaseModel):
    principal_id: str
    user_name: str
    display_name: Optional[str]
    reach: str
    surface: Optional[str]
    last_active: Optional[str]
    created_at: str


class UserListResponse(BaseModel):
    users: list[UserOut]
    total: int


# ── helpers ─────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _principal_id(org_id: str, user_name: str) -> str:
    # Display form used by the SPA. Slash-form (the canonical
    # ``<td>/<org>/user/<name>``) is internal-only; the dashboard speaks
    # the ``::``-separated short id.
    return f"{org_id}::user::{user_name}"


# ── endpoints ───────────────────────────────────────────────────────────


@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin_secret)],
)
async def create_user(
    body: UserCreateRequest, request: Request,
) -> UserOut:
    """Insert (or no-op on duplicate) a user-principal row.

    Idempotent: re-posting the same ``user_name`` returns 201 with the
    existing row; ``display_name`` / ``reach`` / ``surface`` are *not*
    overwritten on conflict so admin pre-population can't blow away
    a row a real Frontdesk SSO touch already filled in.
    """
    if body.reach not in _VALID_REACH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"reach must be one of {_VALID_REACH}",
        )
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None or not getattr(mgr, "ca_loaded", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent manager not initialized — Org CA not loaded",
        )
    pid = _principal_id(mgr.org_id, body.user_name)
    now = _now_iso()
    async with get_db() as conn:
        existing = (await conn.execute(
            text(
                "SELECT principal_id, user_name, display_name, reach, "
                "       surface, created_at, last_active_at "
                "  FROM local_user_principals WHERE principal_id = :pid"
            ),
            {"pid": pid},
        )).mappings().first()
        if existing is None:
            await conn.execute(
                text(
                    """
                    INSERT INTO local_user_principals (
                        principal_id, user_name, display_name,
                        reach, surface, created_at
                    ) VALUES (
                        :pid, :uname, :disp, :reach, :surface, :now
                    )
                    """
                ),
                {
                    "pid": pid,
                    "uname": body.user_name,
                    "disp": body.display_name or None,
                    "reach": body.reach,
                    "surface": body.surface,
                    "now": now,
                },
            )
            return UserOut(
                principal_id=pid,
                user_name=body.user_name,
                display_name=body.display_name or None,
                reach=body.reach,
                surface=body.surface,
                last_active=None,
                created_at=now,
            )
        return UserOut(
            principal_id=existing["principal_id"],
            user_name=existing["user_name"],
            display_name=existing["display_name"],
            reach=existing["reach"],
            surface=existing["surface"],
            last_active=existing["last_active_at"],
            created_at=existing["created_at"],
        )


@router.get(
    "",
    response_model=UserListResponse,
    dependencies=[Depends(_require_admin_secret)],
)
async def list_users(
    reach: Optional[str] = Query(None),
    surface: Optional[str] = Query(None),
    q: Optional[str] = Query(None, max_length=128),
    limit: int = Query(200, ge=1, le=500),
) -> UserListResponse:
    if reach is not None and reach not in _VALID_REACH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"reach must be one of {_VALID_REACH}",
        )
    sql = (
        "SELECT principal_id, user_name, display_name, reach, surface, "
        "       created_at, last_active_at "
        "  FROM local_user_principals "
    )
    where: list[str] = []
    params: dict[str, object] = {"limit": limit}
    if reach is not None:
        where.append("reach = :reach")
        params["reach"] = reach
    if surface is not None:
        where.append("surface = :surface")
        params["surface"] = surface
    if q:
        where.append(
            "(LOWER(user_name) LIKE :q OR "
            " LOWER(COALESCE(display_name, '')) LIKE :q)"
        )
        params["q"] = f"%{q.lower()}%"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT :limit"
    async with get_db() as conn:
        rows = (await conn.execute(text(sql), params)).mappings().all()
    items = [
        UserOut(
            principal_id=r["principal_id"],
            user_name=r["user_name"],
            display_name=r["display_name"],
            reach=r["reach"],
            surface=r["surface"],
            last_active=r["last_active_at"],
            created_at=r["created_at"],
        )
        for r in rows
    ]
    return UserListResponse(users=items, total=len(items))


@router.post(
    "/{user_name}/reset-tofu-pin",
    dependencies=[Depends(_require_admin_secret)],
)
async def reset_tofu_pin(user_name: str, request: Request) -> dict:
    """Clear the TOFU-pinned pubkey for a user principal.

    Mirror of the dashboard Danger Zone button. Scripted recovery
    path for the v0.1 keystore-loss case (Connector wiped its
    on-disk keypair, pre-PR #656 Mastio kept user keys in-memory
    and lost the pin on restart). Cert thumbprint is left alone —
    only the SPKI hash is the load-bearing TOFU identifier.

    Audit chain captures the reset with ``action=reset_tofu_pin``
    and ``operator=admin-secret`` so an attacker who flips a real
    user's pin to their own pubkey is recoverable forensically.

    Returns:
        ``200`` ``{"principal_id": ..., "cleared": true}`` on success.
        ``404`` when principal_id missing OR the pin was already NULL
        (idempotent caller can treat both as "nothing to do").
    """
    if not user_name or len(user_name) > 64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid user_name",
        )
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None or not getattr(mgr, "ca_loaded", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent manager not initialized — Org CA not loaded",
        )
    pid = _principal_id(mgr.org_id, user_name)

    from mcp_proxy.db import clear_user_principal_pubkey_thumbprint, log_audit
    cleared = await clear_user_principal_pubkey_thumbprint(pid)
    if not cleared:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="principal not found or pin already cleared",
        )

    try:
        await log_audit(
            agent_id=pid,
            action="reset_tofu_pin",
            status="success",
            details={
                "operator": "admin-secret",
                "user_name": user_name,
            },
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "reset_tofu_pin: audit append failed for %s: %s", pid, exc,
        )

    return {"principal_id": pid, "cleared": True}


# ── populator helper ────────────────────────────────────────────────────


async def upsert_from_csr(
    *,
    principal_id: str,
    org_id: str,
    cert_thumbprint: str,
    pubkey_thumbprint: Optional[str] = None,
    surface_hint: Optional[str] = None,
) -> None:
    """Called by the CSR sign endpoint after a successful signature.

    Idempotent insert (conflict → update last_active_at + cert_thumbprint
    only). The caller hands in the canonical 4-component principal_id;
    we re-key it to the ``::`` short form used by the dashboard.

    ``pubkey_thumbprint`` is the SHA-256 of the principal keypair's
    SPKI DER. It is the TOFU stable identifier (CRIT-1 fix): set on
    INSERT and on first refresh of a legacy row that still has NULL,
    but **never overwritten** once non-NULL. The CSR signer enforces
    pubkey-match before reaching this function on subsequent calls,
    so by the time we get here either the thumb agrees with the
    stored value or we're populating it for the first time.

    Errors are swallowed and logged for the dashboard surface: the
    registry table is best-effort UI metadata, never a blocker for
    the underlying CSR signing flow. The pubkey pin is critical
    enough that the CSR signer-side TOFU check (in
    ``principals_csr.sign_user_csr``) is the load-bearing defence;
    this helper just persists the pin on the happy path.
    """
    try:
        # Convert <td>/<org>/user/<name> → <org>::user::<name>.
        parts = principal_id.split("/")
        if len(parts) != 4 or parts[2] != "user":
            return
        user_name = parts[3]
        pid = _principal_id(org_id, user_name)
        now = _now_iso()
        async with get_db() as conn:
            existing = (await conn.execute(
                text(
                    "SELECT principal_id FROM local_user_principals "
                    " WHERE principal_id = :pid"
                ),
                {"pid": pid},
            )).first()
            if existing is None:
                await conn.execute(
                    text(
                        """
                        INSERT INTO local_user_principals (
                            principal_id, user_name, display_name,
                            reach, surface, cert_thumbprint,
                            pubkey_thumbprint,
                            created_at, last_active_at
                        ) VALUES (
                            :pid, :uname, NULL,
                            'intra', :surface, :thumb,
                            :pubkey,
                            :now, :now
                        )
                        """
                    ),
                    {
                        "pid": pid, "uname": user_name,
                        "surface": surface_hint, "thumb": cert_thumbprint,
                        "pubkey": pubkey_thumbprint,
                        "now": now,
                    },
                )
            else:
                # Update cert_thumbprint (rotational, every CSR refresh)
                # and last_active. Pubkey_thumbprint is set ONLY when
                # currently NULL (legacy backfill); never overwritten
                # — that would defeat the TOFU contract.
                await conn.execute(
                    text(
                        """
                        UPDATE local_user_principals
                           SET cert_thumbprint = :thumb,
                               last_active_at  = :now,
                               surface = COALESCE(surface, :surface),
                               pubkey_thumbprint = COALESCE(
                                   pubkey_thumbprint, :pubkey
                               )
                         WHERE principal_id = :pid
                        """
                    ),
                    {
                        "pid": pid, "thumb": cert_thumbprint,
                        "pubkey": pubkey_thumbprint,
                        "surface": surface_hint, "now": now,
                    },
                )
    except Exception as exc:  # noqa: BLE001 — best-effort telemetry
        _log.warning(
            "upsert_from_csr failed for %s: %s", principal_id, exc,
        )
