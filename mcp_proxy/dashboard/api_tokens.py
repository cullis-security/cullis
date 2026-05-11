"""Dashboard mutations for user API tokens (ADR-027 Phase 1, PR 4).

The GET surface is folded into ``user_detail.html`` so the operator
sees tokens inline with the rest of the user's metadata (the rendering
sits in :func:`mcp_proxy.dashboard.router.user_detail_page`, which now
pulls ``api_tokens`` into the template context). This module only
handles the two mutations:

  POST   /proxy/users/{principal_id}/api-tokens/create
         Form-submit from the "Create new token" panel in the API
         Tokens tab. Mints a row, then 303-redirects back to the user
         page with ``?new_token=<cleartext>`` so the template can
         render the one-time "save it now" banner.

  POST   /proxy/users/{principal_id}/api-tokens/{token_id}/revoke
         Form-submit from the per-row Revoke button. 303-redirects
         back to the user page with ``?ok=token+revoked``.

Both routes go through ``require_login`` (cookie session) +
``verify_csrf`` (token tied to the dashboard session), mirroring
``users_reset_password`` and ``users_delete``. The hash-chained audit
log is written by the underlying ``mcp_proxy.db`` helpers — same audit
shape as the admin REST surface in :mod:`mcp_proxy.admin.api_tokens`.
"""
from __future__ import annotations

import logging
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from mcp_proxy.dashboard.session import require_login, verify_csrf
from mcp_proxy.db import (
    get_user_api_token,
    log_audit,
    mint_user_api_token,
    revoke_user_api_token,
)

_log = logging.getLogger("mcp_proxy.dashboard.api_tokens")

router = APIRouter(
    prefix="/proxy/users", tags=["dashboard-api-tokens"],
)


def _back_to_user(principal_id: str, query: str = "") -> RedirectResponse:
    """Redirect back to the user detail page, optionally with a query string."""
    base = f"/proxy/users/{quote(principal_id, safe='')}"
    return RedirectResponse(
        f"{base}?{query}" if query else base,
        status_code=303,
    )


@router.post("/{principal_id:path}/api-tokens/create")
async def create_api_token(
    principal_id: str,
    request: Request,
    label: str = Form(""),
    expires_at: str = Form(""),
    scope_providers: list[str] | None = Form(None),
) -> RedirectResponse:
    """Mint a new culk_ token for ``principal_id`` and redirect back to
    the user detail page with the cleartext as a single-use query param.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return _back_to_user(principal_id, "error=csrf")

    clean_label = (label or "").strip()
    if not clean_label:
        return _back_to_user(principal_id, "token_error=label+is+required")

    clean_expiry: str | None = (expires_at or "").strip() or None
    # The form's <input type="date"> emits ``YYYY-MM-DD``. Promote it to
    # an ISO-8601 UTC timestamp so the DB helper's ``expires_at`` filter
    # (string comparison vs ``datetime.now(UTC).isoformat()``) works.
    if clean_expiry and len(clean_expiry) == 10:
        clean_expiry = f"{clean_expiry}T23:59:59+00:00"

    scope_list = [s.strip() for s in (scope_providers or []) if s.strip()]

    created_by = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )

    try:
        minted = await mint_user_api_token(
            principal_id=principal_id,
            label=clean_label,
            created_by=created_by,
            scope_providers=scope_list,
            expires_at=clean_expiry,
        )
    except ValueError as exc:
        return _back_to_user(
            principal_id,
            f"token_error={quote(str(exc))}",
        )

    await log_audit(
        agent_id=created_by,
        action="api_token.mint",
        status="success",
        details={
            "event": "api_token.mint",
            "source": "dashboard",
            "token_id": minted["id"],
            "principal_id": minted["principal_id"],
            "label": minted["label"],
            "scope_providers": minted["scope_providers"],
            "expires_at": minted["expires_at"],
        },
    )
    _log.info(
        "dashboard mint api-token id=%s principal=%s label=%s by=%s",
        minted["id"], minted["principal_id"], minted["label"], created_by,
    )
    return _back_to_user(
        principal_id,
        f"new_token={quote(minted['token'])}&new_token_label={quote(minted['label'])}",
    )


@router.post("/{principal_id:path}/api-tokens/{token_id}/revoke")
async def revoke_api_token(
    principal_id: str,
    token_id: str,
    request: Request,
) -> RedirectResponse:
    """Mark a token as revoked. Idempotent — re-clicking Revoke on an
    already-revoked row still returns to the user page without error."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return _back_to_user(principal_id, "error=csrf")

    row = await get_user_api_token(token_id)
    if row is None or row["principal_id"] != principal_id:
        return _back_to_user(
            principal_id,
            "token_error=token+not+found+for+this+user",
        )

    revoked_by = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )
    effective = await revoke_user_api_token(token_id, revoked_by=revoked_by)
    await log_audit(
        agent_id=revoked_by,
        action="api_token.revoke",
        status="success",
        details={
            "event": "api_token.revoke",
            "source": "dashboard",
            "token_id": token_id,
            "principal_id": principal_id,
            "effective": effective,
        },
    )
    _log.info(
        "dashboard revoke api-token id=%s principal=%s effective=%s by=%s",
        token_id, principal_id, effective, revoked_by,
    )
    return _back_to_user(principal_id, "ok=token+revoked")
