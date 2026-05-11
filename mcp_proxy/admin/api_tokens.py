"""Admin API for user API tokens (ADR-027 Phase 1, PR 3).

Mint, list, and revoke ``culk_*`` tokens via Bearer ``X-Admin-Secret``.
This is the scripted path (curl / Terraform / CI) that unblocks the
"point LibreChat at Cullis Mastio" pattern without forcing the admin
through the browser dashboard. The dashboard UI (PR 4) wraps the same
audit + DB writes.

Endpoints:

  POST   /v1/admin/api-tokens
         Mint a token for ``principal_id`` with ``label`` + optional
         ``scope_providers``, ``scope_paths``, ``expires_at``. Response
         shows the cleartext token ONE TIME. Subsequent reads see only
         ``token_last4``.

  GET    /v1/admin/api-tokens?principal_id=<pid>&include_revoked=<bool>
         List token metadata. ``principal_id`` filter is optional;
         omitting it returns all tokens across all users (admin-wide
         dashboard view). ``include_revoked`` defaults to false.

  GET    /v1/admin/api-tokens/{token_id}
         Single-row fetch. Returns 404 if unknown.

  DELETE /v1/admin/api-tokens/{token_id}
         Mark revoked. Idempotent — returns 204 even when the token
         was already revoked, so retried Terraform / CI jobs don't
         flap. The audit row distinguishes "new revoke" from "no-op".

Auth: ``X-Admin-Secret`` header. Same contract as
``mcp_proxy/admin/ai_providers.py`` and ``mcp_proxy/admin/users.py``.

Audit: every mutation writes a row to the hash-chained ``audit_log``
table. Mint logs ``api_token.mint`` with the new ``token_id`` and
``principal_id`` (never the cleartext). Revoke logs ``api_token.revoke``
with the token_id + an ``effective`` flag distinguishing the
first-time revoke from the idempotent retry.
"""
from __future__ import annotations

import hmac
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from mcp_proxy.config import get_settings
from mcp_proxy.db import (
    get_user_api_token,
    list_user_api_tokens,
    log_audit,
    mint_user_api_token,
    revoke_user_api_token,
)

_log = logging.getLogger("mcp_proxy.admin.api_tokens")

router = APIRouter(prefix="/v1/admin/api-tokens", tags=["admin"])


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


class MintRequest(BaseModel):
    principal_id: str = Field(..., min_length=1, max_length=256)
    label: str = Field(..., min_length=1, max_length=128)
    # Empty list = no restriction. Validation of provider names against
    # the catalog is intentionally not enforced here — the token may
    # outlive any specific provider configuration, and ``scope_providers``
    # is a hint for the policy layer, not a hard ACL today.
    scope_providers: list[str] = Field(default_factory=list)
    # Default applied by the DB helper when omitted (``["/v1/*"]``).
    scope_paths: Optional[list[str]] = None
    # ISO-8601 UTC, e.g. ``2026-08-11T00:00:00Z``. Null means never expire.
    expires_at: Optional[str] = Field(None, max_length=64)
    # The admin can pass an explicit ``created_by`` (e.g. an audit
    # identifier for a Terraform run); when omitted we record the
    # static string ``"admin-secret"`` since the X-Admin-Secret auth
    # does not carry a principal identity.
    created_by: Optional[str] = Field(None, max_length=256)


class MintResponse(BaseModel):
    """Mint response surface. ``token`` field present ONLY here."""
    id: str
    principal_id: str
    label: str
    token: str
    token_last4: str
    scope_providers: list[str]
    scope_paths: list[str]
    created_at: str
    created_by: str
    expires_at: Optional[str]


class TokenMeta(BaseModel):
    """Public token row shape — no ``token`` cleartext, no ``token_hash``."""
    id: str
    principal_id: str
    label: str
    token_last4: str
    scope_providers: list[str]
    scope_paths: list[str]
    created_at: str
    created_by: str
    last_used_at: Optional[str]
    last_used_ip: Optional[str]
    expires_at: Optional[str]
    revoked_at: Optional[str]
    revoked_by: Optional[str]


class ListResponse(BaseModel):
    tokens: list[TokenMeta]
    total: int


# ── endpoints ───────────────────────────────────────────────────────────


@router.post(
    "",
    response_model=MintResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin_secret)],
)
async def mint_token(body: MintRequest) -> MintResponse:
    """Issue a new ``culk_*`` token for the given user principal.

    The cleartext ``token`` field in the response is the ONLY time it
    will be returned. The caller must capture it now; subsequent reads
    expose only ``token_last4``.
    """
    created_by = body.created_by or "admin-secret"
    try:
        minted = await mint_user_api_token(
            principal_id=body.principal_id,
            label=body.label,
            created_by=created_by,
            scope_providers=body.scope_providers,
            scope_paths=body.scope_paths,
            expires_at=body.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    await log_audit(
        agent_id=created_by,
        action="api_token.mint",
        status="success",
        details={
            "event": "api_token.mint",
            "token_id": minted["id"],
            "principal_id": minted["principal_id"],
            "label": minted["label"],
            "scope_providers": minted["scope_providers"],
            "scope_paths": minted["scope_paths"],
            "expires_at": minted["expires_at"],
        },
    )
    _log.info(
        "api-token mint id=%s principal=%s label=%s scope_providers=%s expires=%s by=%s",
        minted["id"], minted["principal_id"], minted["label"],
        minted["scope_providers"], minted["expires_at"], created_by,
    )
    return MintResponse(**{k: minted[k] for k in MintResponse.model_fields})


@router.get(
    "",
    response_model=ListResponse,
    dependencies=[Depends(_require_admin_secret)],
)
async def list_tokens(
    principal_id: Optional[str] = Query(
        None,
        description=(
            "Filter by user principal_id (e.g. ``orga::user::alice``). "
            "Omit to list across all users (admin-wide view)."
        ),
    ),
    include_revoked: bool = Query(
        False,
        description="When true, includes revoked tokens for audit purposes.",
    ),
) -> ListResponse:
    rows = await list_user_api_tokens(
        principal_id, include_revoked=include_revoked,
    )
    return ListResponse(
        tokens=[TokenMeta(**{k: r.get(k) for k in TokenMeta.model_fields}) for r in rows],
        total=len(rows),
    )


@router.get(
    "/{token_id}",
    response_model=TokenMeta,
    dependencies=[Depends(_require_admin_secret)],
)
async def get_token(token_id: str) -> TokenMeta:
    row = await get_user_api_token(token_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="token not found",
        )
    return TokenMeta(**{k: row.get(k) for k in TokenMeta.model_fields})


@router.delete(
    "/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_require_admin_secret)],
)
async def delete_token(
    token_id: str,
    revoked_by: Optional[str] = Header(
        None,
        alias="X-Revoked-By",
        description=(
            "Audit attribution for the revoke. Defaults to "
            "``admin-secret`` when omitted."
        ),
    ),
) -> None:
    """Revoke a token. Idempotent — returns 204 on already-revoked rows.

    A revoke that hits an unknown ``token_id`` returns 404, distinguishing
    "no-op idempotent" (token already revoked, 204) from "wrong id"
    (404). The caller's retry logic should treat 204 + 404 differently:
    204 = success, 404 = re-check the id.
    """
    row = await get_user_api_token(token_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="token not found",
        )
    by = revoked_by or "admin-secret"
    effective = await revoke_user_api_token(token_id, revoked_by=by)
    await log_audit(
        agent_id=by,
        action="api_token.revoke",
        status="success",
        details={
            "event": "api_token.revoke",
            "token_id": token_id,
            "principal_id": row["principal_id"],
            "effective": effective,
        },
    )
    _log.info(
        "api-token revoke id=%s principal=%s effective=%s by=%s",
        token_id, row["principal_id"], effective, by,
    )
