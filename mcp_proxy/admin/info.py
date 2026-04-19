"""Proxy admin info endpoints (ADR-009 Phase 2).

Machine-readable accessors for bootstrap / CI / sandbox automation. Auth
uses the ``admin_secret`` shared between the proxy and its orchestrator,
so there is no dashboard session involved — intended for calls from
containers like ``sandbox/bootstrap``.
"""
from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel

from mcp_proxy.config import get_settings


router = APIRouter(prefix="/v1/admin", tags=["admin"])


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


class MastioPubkeyResponse(BaseModel):
    """ES256 mastio leaf pubkey, PEM-encoded. ``None`` when the proxy
    hasn't loaded its mastio identity yet (pre-ADR-009 or Org CA not
    attached). Bootstrap scripts must treat ``None`` as "skip pinning"
    and retry once the proxy finishes first-boot."""

    mastio_pubkey: str | None
    org_id: str | None


@router.get(
    "/mastio-pubkey",
    response_model=MastioPubkeyResponse,
    dependencies=[Depends(_require_admin_secret)],
    summary="Return the proxy's mastio ES256 public key in PEM format",
)
async def get_mastio_pubkey(request: Request) -> MastioPubkeyResponse:
    """Return the mastio leaf pubkey pinned at onboarding.

    Used by ``sandbox/bootstrap/bootstrap.py`` to include the
    key in its ``/v1/onboarding/join`` or ``/v1/onboarding/attach`` call
    so the Court can enforce the ADR-009 counter-signature from then on.
    """
    mgr = getattr(request.app.state, "agent_manager", None)
    org_id = getattr(request.app.state, "org_id", None)

    if mgr is None or not getattr(mgr, "mastio_loaded", False):
        return MastioPubkeyResponse(mastio_pubkey=None, org_id=org_id)

    return MastioPubkeyResponse(
        mastio_pubkey=mgr.get_mastio_pubkey_pem(),
        org_id=org_id,
    )
