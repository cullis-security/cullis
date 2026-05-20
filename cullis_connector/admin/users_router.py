"""Admin API for local user provisioning — ADR-025 Phase 1.

Endpoints:

- ``POST   /admin/users``                          create user (201/400/409)
- ``GET    /admin/users``                          list users (200)
- ``DELETE /admin/users/{user_name}``              delete user (204/404)
- ``POST   /admin/users/{user_name}/reset-password`` admin reset (200/404)

All routes are gated by ``X-Admin-Secret`` — see
``cullis_connector/admin/auth.py``. The router is only mounted when
``AUTH_MODE=local`` (the FrontDesk shared-mode default).

The router pulls ``connector_config`` off the FastAPI ``app.state``
the same way the rest of ``cullis_connector/web.py`` does, so test
harnesses that call ``build_app(cfg)`` get an isolated users.db per
test without any monkey-patching.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from cullis_connector.admin.auth import _require_admin_secret
from cullis_connector.identity.users import (
    User,
    create_user,
    delete_user,
    get_user_by_name,
    list_users,
    reset_password,
)
from cullis_connector.identity.users_db import get_users_session

_log = logging.getLogger("cullis_connector.admin.users_router")


router = APIRouter(
    prefix="/admin/users",
    tags=["admin", "users"],
    dependencies=[Depends(_require_admin_secret)],
)


# ── request / response models ───────────────────────────────────────────


class CreateUserRequest(BaseModel):
    user_name: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    password: str = Field(..., min_length=8)
    must_change_password: bool = True
    display_name: str = Field("", max_length=256)


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8)


class UserOut(BaseModel):
    user_name: str
    display_name: str
    must_change_password: bool
    created_at: str
    password_changed_at: Optional[str] = None
    disabled: bool = False


class UserListResponse(BaseModel):
    users: list[UserOut]
    total: int


class ResetPasswordResponse(BaseModel):
    user_name: str
    must_change_password: bool


def _to_out(user: User) -> UserOut:
    return UserOut(
        user_name=user.user_name,
        display_name=user.display_name,
        must_change_password=user.must_change_password,
        created_at=user.created_at,
        password_changed_at=user.password_changed_at,
        disabled=user.disabled,
    )


# ── helpers ─────────────────────────────────────────────────────────────


def _config_dir(request: Request):
    config = getattr(request.app.state, "connector_config", None)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="connector_config not bound on app.state",
        )
    return config.config_dir


# ── endpoints ───────────────────────────────────────────────────────────


@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_user_endpoint(
    body: CreateUserRequest, request: Request,
) -> UserOut:
    """Create a local user. 409 on duplicate, 400 on bad regex / weak password."""
    config_dir = _config_dir(request)
    try:
        async with get_users_session(config_dir) as session:
            user = await create_user(
                session,
                name=body.user_name,
                password=body.password,
                must_change=body.must_change_password,
                display_name=body.display_name,
            )
        # NEVER log the password — only the username + result.
        _log.info(
            "admin: created local user user_name=%s must_change=%s",
            user.user_name, user.must_change_password,
        )
        return _to_out(user)
    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"user_name {body.user_name!r} already exists",
        )
    except ValueError as exc:
        # Surfaced from username/password validators.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get("", response_model=UserListResponse)
async def list_users_endpoint(
    request: Request,
    q: str = Query("", max_length=128),
    disabled: Optional[bool] = Query(None),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> UserListResponse:
    config_dir = _config_dir(request)
    async with get_users_session(config_dir) as session:
        users = await list_users(
            session, q=q, disabled=disabled, limit=limit, offset=offset,
        )
    items = [_to_out(u) for u in users]
    return UserListResponse(users=items, total=len(items))


@router.delete(
    "/{user_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_user_endpoint(
    user_name: str, request: Request,
) -> Response:
    config_dir = _config_dir(request)
    async with get_users_session(config_dir) as session:
        ok = await delete_user(session, user_name)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"user_name {user_name!r} not found",
        )
    _log.info("admin: deleted local user user_name=%s", user_name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{user_name}/reset-password",
    response_model=ResetPasswordResponse,
)
async def reset_password_endpoint(
    user_name: str, body: ResetPasswordRequest, request: Request,
) -> ResetPasswordResponse:
    """Admin-driven password reset.

    Sets a new temporary password and forces ``must_change_password=True``
    so the user is prompted to change it on first login. Phase 5's SPA
    flow consumes this endpoint from the admin Users tab.
    """
    config_dir = _config_dir(request)
    try:
        async with get_users_session(config_dir) as session:
            ok = await reset_password(
                session, user_name, body.new_password,
            )
            if not ok:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"user_name {user_name!r} not found",
                )
            user = await get_user_by_name(session, user_name)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    # Defensive — get_user_by_name should succeed since reset_password
    # returned True, but guard anyway so the response model is clean.
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"user_name {user_name!r} not found",
        )
    _log.info(
        "admin: reset password user_name=%s must_change=%s",
        user.user_name, user.must_change_password,
    )
    return ResetPasswordResponse(
        user_name=user.user_name,
        must_change_password=user.must_change_password,
    )
