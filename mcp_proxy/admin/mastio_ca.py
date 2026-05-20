"""Mastio Intermediate CA rotation admin endpoint.

Three-tier PKI hardening (audit 2026-05-18), Phase 4. Exposes
``POST /v1/admin/mastio-ca/rotate`` for operator-driven rotation:

* ``X-Admin-Secret`` header gate (same shared secret as the rest of
  the ``/v1/admin/...`` surface).
* Optional ``?dry_run=true`` to validate + mint in memory without
  persisting or atomic-swapping.
* Audit row ``pki.intermediate_rotated`` (or
  ``pki.intermediate_rotate_dry_run``) on success.

The automatic watcher (``mastio_ca_rotation_watcher`` in
``mcp_proxy.lifespan``) covers the expiry-driven path; this endpoint
covers the on-demand path (operator response to a key-compromise
suspicion, scheduled rotation cadence, post-incident hygiene).
"""
from __future__ import annotations

import hmac
import logging
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from mcp_proxy.config import get_settings

_log = logging.getLogger("mcp_proxy.admin.mastio_ca")

router = APIRouter(prefix="/v1/admin", tags=["admin", "pki"])


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


class RotateMastioCaResponse(BaseModel):
    """Outcome of a Mastio Intermediate CA rotation call."""

    dry_run: bool = Field(
        description="Whether the call was a dry-run (validation only).",
    )
    old_intermediate_cn: str = Field(
        description="Subject CN of the Intermediate that was deprecated.",
    )
    new_intermediate_cn: str = Field(
        description="Subject CN of the freshly-minted Intermediate.",
    )
    new_leaf_kid: Optional[str] = Field(
        default=None,
        description=(
            "kid of the freshly-minted Mastio Leaf under the new "
            "Intermediate (None on dry-run)."
        ),
    )
    grace_days: int = Field(
        description=(
            "Days the deprecated Intermediate stays verifier-accepted "
            "after the swap."
        ),
    )
    continuity_proof: str = Field(
        description=(
            "Base64url-no-pad ECDSA-SHA256 signature of the new "
            "Intermediate cert (DER), produced with the old "
            "Intermediate's private key. Verifiers that pinned the "
            "old Intermediate can audit the rotation trail."
        ),
    )


@router.post(
    "/mastio-ca/rotate",
    response_model=RotateMastioCaResponse,
    summary="Rotate the Mastio Intermediate CA (Phase 4 three-tier hardening)",
)
async def rotate_mastio_ca(
    request: Request,
    dry_run: bool = Query(
        False,
        description=(
            "If true, mint + validate without persisting. Useful to "
            "confirm the Org Root is reachable and the new chain "
            "verifies before committing to a real rotation."
        ),
    ),
    grace_days: int = Query(
        14,
        ge=1,
        le=90,
        description=(
            "Days the deprecated Intermediate stays verifier-valid "
            "after the swap. Default 14, OWASP recommends a window "
            "that comfortably covers the slowest re-fetch interval "
            "of any pinning client (Connector polls hourly)."
        ),
    ),
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> RotateMastioCaResponse:
    """Trigger an Intermediate CA rotation.

    Sequence (see :meth:`AgentManager.rotate_mastio_ca`):

    1. Mint new Intermediate keypair.
    2. Unseal Org Root, sign, scrub.
    3. Build continuity proof with the OLD Intermediate's key.
    4. Stage in ``pki_key_store``.
    5. Re-mint Mastio Leaf under the new Intermediate.
    6. Atomic-swap.
    7. Refresh in-memory caches.

    Failure modes:

    * ``503`` when the Mastio Intermediate is not loaded (sign-halted
      or pre-bootstrap).
    * ``400`` when grace_days is out of bounds (Pydantic-validated).
    * ``500`` when the Org Root cannot be unsealed (KMS provider
      missing the key, master passphrase mismatch).
    """
    _require_admin_secret(x_admin_secret)

    agent_mgr = getattr(request.app.state, "agent_manager", None)
    if agent_mgr is None or not getattr(agent_mgr, "mastio_loaded", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Mastio Intermediate CA not loaded — cannot rotate. "
                "Complete first-boot setup, or recover from sign-halt "
                "via the dashboard before retrying."
            ),
        )

    try:
        result = await agent_mgr.rotate_mastio_ca(
            grace_days=grace_days,
            operator="admin",
            dry_run=dry_run,
        )
    except RuntimeError as exc:
        # KMS unseal failure, missing at-rest master key, missing
        # intermediate cache, etc. Surface as 500 with a redacted detail
        # — the exception text can carry filesystem paths, KMS internal
        # state, sub-exception chains (audit F-B-119).
        from mcp_proxy._http_safety import safe_http_detail
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=safe_http_detail(
                exc,
                public_hint="rotation failed",
                log_context="rotate_mastio_ca",
            ),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return RotateMastioCaResponse(
        dry_run=bool(result.get("dry_run")),
        old_intermediate_cn=result["old_intermediate_cn"],
        new_intermediate_cn=result["new_intermediate_cn"],
        new_leaf_kid=result.get("new_leaf_kid"),
        grace_days=int(result["grace_days"]),
        continuity_proof=result["continuity_proof"],
    )
