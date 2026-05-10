"""Mastio admin API for user principals.

Pairs with ``mcp_proxy/admin/agents.py`` and ``mcp_proxy/admin/mcp_resources.py``.
Lets an org admin pre-create a user-principal row so the dashboard's
Users tab renders before the user has touched the Frontdesk SSO flow.
The CSR signing path on ``/v1/principals/csr`` upserts into the same
table on every signature, so a user that *does* go through SSO first
shows up automatically.

Endpoints:
- POST   ``/v1/admin/users``                              create / upsert
- GET    ``/v1/admin/users``                              list
- POST   ``/v1/admin/users/{principal_id}/reset-password``  rotate password
- POST   ``/v1/admin/users/{principal_id}/deactivate``    block sign-in
- POST   ``/v1/admin/users/{principal_id}/reactivate``    re-allow sign-in
- DELETE ``/v1/admin/users/{principal_id}``               purge row

Auth: ``X-Admin-Secret`` (same contract as ``/v1/admin/agents``).

AD-style password layer (migration 0026): when ``password`` is supplied
on create or via reset-password the row gets a bcrypt hash + the
``must_change_password`` flag, mirroring how a domain admin hands an
employee a one-time credential. The ``/v1/principals/password-login``
endpoint validates the hash and mints a DPoP-bound JWT the client then
spends on ``/v1/principals/csr`` to obtain its cert. Rows that never
receive a password (today's SSO-upsert path) keep ``password_hash``
NULL and are unaffected.
"""
from __future__ import annotations

import asyncio
import hmac
import logging
from datetime import datetime, timezone
from typing import Optional

import bcrypt
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
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


class UserCreateRequest(BaseModel):
    user_name: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    display_name: str = Field("", max_length=256)
    reach: str = Field("intra")
    surface: Optional[str] = Field(None, max_length=64)
    # AD-style: admin types the initial password. NULL leaves the row in
    # SSO-only mode (today's behaviour). When supplied, the row is forced
    # into "must change password at first login" so the admin's choice is
    # never the long-lived secret.
    password: Optional[str] = Field(
        None, min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH,
    )


class PasswordResetRequest(BaseModel):
    new_password: str = Field(
        ..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH,
    )


class UserOut(BaseModel):
    principal_id: str
    user_name: str
    display_name: Optional[str]
    reach: str
    surface: Optional[str]
    last_active: Optional[str]
    created_at: str
    has_password: bool = False
    must_change_password: bool = False
    disabled: bool = False


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


def _hash_password_sync(plain: str) -> str:
    return bcrypt.hashpw(
        plain.encode("utf-8"), bcrypt.gensalt(rounds=12),
    ).decode("utf-8")


def _check_password_sync(plain: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain.encode("utf-8"), stored_hash.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


async def hash_password(plain: str) -> str:
    return await asyncio.to_thread(_hash_password_sync, plain)


async def verify_password(plain: str, stored_hash: str) -> bool:
    if not isinstance(plain, str) or not plain:
        return False
    if not isinstance(stored_hash, str) or not stored_hash:
        return False
    return await asyncio.to_thread(_check_password_sync, plain, stored_hash)


def _row_to_userout(row) -> "UserOut":
    return UserOut(
        principal_id=row["principal_id"],
        user_name=row["user_name"],
        display_name=row["display_name"],
        reach=row["reach"],
        surface=row["surface"],
        last_active=row["last_active_at"],
        created_at=row["created_at"],
        has_password=bool(row["password_hash"]),
        must_change_password=bool(row["must_change_password"]),
        disabled=bool(row["disabled"]),
    )


# Centralised SELECT list — keeps every read path returning the same
# shape, which the dashboard + endpoints below all depend on.
_SELECT_COLS = (
    "principal_id, user_name, display_name, reach, surface, "
    "created_at, last_active_at, password_hash, "
    "must_change_password, disabled"
)


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

    Idempotent on user_name: re-posting the same name returns 201 with
    the existing row; ``display_name`` / ``reach`` / ``surface`` are
    *not* overwritten so a real Frontdesk SSO touch can't be blown away
    by admin pre-population. If ``password`` is supplied AND the row had
    no password yet, it is set + ``must_change_password`` flipped to
    True. Re-issuing a password through this endpoint on a row that
    already has one is rejected — admins must use the explicit
    ``/reset-password`` action so password rotation is auditable.
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
    pw_hash = await hash_password(body.password) if body.password else None
    async with get_db() as conn:
        existing = (await conn.execute(
            text(f"SELECT {_SELECT_COLS} FROM local_user_principals "
                 "WHERE principal_id = :pid"),
            {"pid": pid},
        )).mappings().first()
        if existing is None:
            await conn.execute(
                text(
                    """
                    INSERT INTO local_user_principals (
                        principal_id, user_name, display_name,
                        reach, surface, created_at,
                        password_hash, must_change_password, disabled,
                        password_updated_at
                    ) VALUES (
                        :pid, :uname, :disp, :reach, :surface, :now,
                        :pw, :mcp, :dis, :pwnow
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
                    "pw": pw_hash,
                    "mcp": bool(pw_hash),
                    "dis": bool(False),
                    "pwnow": now if pw_hash else None,
                },
            )
            row = (await conn.execute(
                text(f"SELECT {_SELECT_COLS} FROM local_user_principals "
                     "WHERE principal_id = :pid"),
                {"pid": pid},
            )).mappings().first()
            return _row_to_userout(row)

        # Row exists — handle password top-up only if the row has no
        # hash yet (admin filling in credentials post-SSO bootstrap).
        if pw_hash and not existing["password_hash"]:
            await conn.execute(
                text(
                    """
                    UPDATE local_user_principals
                       SET password_hash         = :pw,
                           must_change_password  = :mcp,
                           password_updated_at   = :pwnow
                     WHERE principal_id = :pid
                    """
                ),
                {
                    "pid": pid,
                    "pw": pw_hash,
                    "mcp": bool(True),
                    "pwnow": now,
                },
            )
            row = (await conn.execute(
                text(f"SELECT {_SELECT_COLS} FROM local_user_principals "
                     "WHERE principal_id = :pid"),
                {"pid": pid},
            )).mappings().first()
            return _row_to_userout(row)

        if pw_hash and existing["password_hash"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "user already has a password — use "
                    "/v1/admin/users/{principal_id}/reset-password"
                ),
            )
        return _row_to_userout(existing)


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
    sql = f"SELECT {_SELECT_COLS} FROM local_user_principals "
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
    items = [_row_to_userout(r) for r in rows]
    return UserListResponse(users=items, total=len(items))


@router.post(
    "/{principal_id}/reset-password",
    response_model=UserOut,
    dependencies=[Depends(_require_admin_secret)],
)
async def reset_password(
    principal_id: str, body: PasswordResetRequest,
) -> UserOut:
    """Force-set a new password and re-arm ``must_change_password``.

    Used when the employee forgot the password or the admin wants to
    rotate the credential. Always re-arms the change-on-first-login
    flag so the admin's typed value is never long-lived.
    """
    pw_hash = await hash_password(body.new_password)
    now = _now_iso()
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                UPDATE local_user_principals
                   SET password_hash         = :pw,
                       must_change_password  = :mcp,
                       password_updated_at   = :now
                 WHERE principal_id = :pid
                """
            ),
            {
                "pid": principal_id,
                "pw": pw_hash,
                "mcp": bool(True),
                "now": now,
            },
        )
        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="user principal not found",
            )
        row = (await conn.execute(
            text(f"SELECT {_SELECT_COLS} FROM local_user_principals "
                 "WHERE principal_id = :pid"),
            {"pid": principal_id},
        )).mappings().first()
    _log.info("admin reset password for principal_id=%s", principal_id)
    return _row_to_userout(row)


@router.post(
    "/{principal_id}/deactivate",
    response_model=UserOut,
    dependencies=[Depends(_require_admin_secret)],
)
async def deactivate_user(principal_id: str) -> UserOut:
    """Block sign-in without deleting the audit history.

    Sets ``disabled=True``. The login endpoint refuses disabled rows;
    existing certs remain on disk but cannot be re-issued nor re-bound
    to a fresh DPoP key (the JWT mint path checks the same flag).
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "UPDATE local_user_principals SET disabled = :dis "
                " WHERE principal_id = :pid"
            ),
            {"pid": principal_id, "dis": bool(True)},
        )
        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="user principal not found",
            )
        row = (await conn.execute(
            text(f"SELECT {_SELECT_COLS} FROM local_user_principals "
                 "WHERE principal_id = :pid"),
            {"pid": principal_id},
        )).mappings().first()
    _log.info("admin deactivated principal_id=%s", principal_id)
    return _row_to_userout(row)


@router.post(
    "/{principal_id}/reactivate",
    response_model=UserOut,
    dependencies=[Depends(_require_admin_secret)],
)
async def reactivate_user(principal_id: str) -> UserOut:
    """Inverse of ``deactivate_user``."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "UPDATE local_user_principals SET disabled = :dis "
                " WHERE principal_id = :pid"
            ),
            {"pid": principal_id, "dis": bool(False)},
        )
        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="user principal not found",
            )
        row = (await conn.execute(
            text(f"SELECT {_SELECT_COLS} FROM local_user_principals "
                 "WHERE principal_id = :pid"),
            {"pid": principal_id},
        )).mappings().first()
    _log.info("admin reactivated principal_id=%s", principal_id)
    return _row_to_userout(row)


@router.delete(
    "/{principal_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_require_admin_secret)],
)
async def delete_user(principal_id: str) -> None:
    """Purge the directory row.

    Intentionally narrow: this only drops the Mastio-side display row.
    Issued certs continue to live in the audit chain; the admin can
    still reconcile against past activity by principal_id. If the row
    doesn't exist we return 204 anyway — DELETE is idempotent.
    """
    async with get_db() as conn:
        await conn.execute(
            text(
                "DELETE FROM local_user_principals WHERE principal_id = :pid"
            ),
            {"pid": principal_id},
        )
    _log.info("admin deleted principal_id=%s", principal_id)


# ── populator helper ────────────────────────────────────────────────────


async def upsert_from_csr(
    *,
    principal_id: str,
    org_id: str,
    cert_thumbprint: str,
    surface_hint: Optional[str] = None,
) -> None:
    """Called by the CSR sign endpoint after a successful signature.

    Idempotent insert (conflict → update last_active_at + cert_thumbprint
    only). The caller hands in the canonical 4-component principal_id;
    we re-key it to the ``::`` short form used by the dashboard.

    Errors are swallowed and logged: the registry table is best-effort
    UI metadata, never a blocker for the underlying CSR signing flow.
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
                            created_at, last_active_at,
                            must_change_password, disabled
                        ) VALUES (
                            :pid, :uname, NULL,
                            'intra', :surface, :thumb,
                            :now, :now,
                            :mcp, :dis
                        )
                        """
                    ),
                    {
                        "pid": pid, "uname": user_name,
                        "surface": surface_hint, "thumb": cert_thumbprint,
                        "now": now,
                        "mcp": bool(False), "dis": bool(False),
                    },
                )
            else:
                await conn.execute(
                    text(
                        """
                        UPDATE local_user_principals
                           SET cert_thumbprint = :thumb,
                               last_active_at  = :now,
                               surface = COALESCE(surface, :surface)
                         WHERE principal_id = :pid
                        """
                    ),
                    {
                        "pid": pid, "thumb": cert_thumbprint,
                        "surface": surface_hint, "now": now,
                    },
                )
    except Exception as exc:  # noqa: BLE001 — best-effort telemetry
        _log.warning(
            "upsert_from_csr failed for %s: %s", principal_id, exc,
        )
