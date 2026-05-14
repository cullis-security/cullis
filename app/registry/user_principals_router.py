"""REST endpoints for the user_principals mapping (ADR-021 PR2 + PR4a).

The Cullis Frontdesk Ambassador (PR4b) is the primary caller. Two
phases per user session:

  * Lookup (PR2): ``GET /v1/principals/by-sso`` — given an SSO
    subject, return the principal_id if already provisioned.
  * Provisioning (PR4a): ``POST /v1/principals/csr`` — given a CSR
    built around a fresh KMS-generated public key, return a Mastio-
    signed cert. The Ambassador then attaches it to the KMS and
    registers the (sso, principal_id) mapping via the registry CRUD.

Authentication: ``Depends(get_current_agent)`` DPoP-bound JWT. RBAC:
the caller may only operate on principals in its own ``org_id``.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.db.database import get_db
from app.registry.principals_csr import (
    CsrValidationError,
    parse_principal_id_to_spiffe,
    sign_user_csr,
)
from app.registry.user_principals import (
    UserPrincipalView,
    get_by_sso,
)

_log = logging.getLogger("agent_trust")

router = APIRouter(prefix="/principals", tags=["principals"])


class UserPrincipalResponse(BaseModel):
    """Public projection of a UserPrincipalRecord.

    ``kms_key_handle`` is included because the Ambassador uses it
    for log correlation; it is opaque, not a secret.
    """

    principal_id: str = Field(...)
    org_id: str = Field(...)
    sso_subject: str = Field(...)
    display_name: Optional[str] = Field(default=None)
    cert_thumbprint: Optional[str] = Field(default=None)
    cert_not_after: Optional[datetime] = Field(default=None)
    kms_backend: str = Field(...)
    kms_key_handle: str = Field(...)
    provisioned_at: datetime = Field(...)
    last_active_at: Optional[datetime] = Field(default=None)
    revoked_at: Optional[datetime] = Field(default=None)
    is_active: bool = Field(...)
    is_provisioned: bool = Field(...)


def _to_response(view: UserPrincipalView) -> UserPrincipalResponse:
    return UserPrincipalResponse(
        principal_id=view.principal_id,
        org_id=view.org_id,
        sso_subject=view.sso_subject,
        display_name=view.display_name,
        cert_thumbprint=view.cert_thumbprint,
        cert_not_after=view.cert_not_after,
        kms_backend=view.kms_backend,
        kms_key_handle=view.kms_key_handle,
        provisioned_at=view.provisioned_at,
        last_active_at=view.last_active_at,
        revoked_at=view.revoked_at,
        is_active=view.is_active,
        is_provisioned=view.is_provisioned,
    )


@router.get("/by-sso", response_model=UserPrincipalResponse)
async def lookup_by_sso(
    org: str = Query(..., min_length=1, max_length=128, description="Org id"),
    subject: str = Query(
        ..., min_length=1, max_length=255,
        description="SSO subject (e.g. 'mario@acme.it')",
    ),
    db: AsyncSession = Depends(get_db),
    token: TokenPayload = Depends(get_current_agent),
) -> UserPrincipalResponse:
    """Look up a user principal by SSO subject within an org.

    404 if no mapping exists. 403 if the caller's org differs from
    the requested ``org`` (cross-org SSO lookups are forbidden).
    """
    if token.org != org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cannot look up SSO subjects in a different org",
        )

    view = await get_by_sso(db, org_id=org, sso_subject=subject)
    if view is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no principal mapped to sso_subject={subject!r} in org={org!r}",
        )
    return _to_response(view)


# ── /v1/principals/csr (ADR-021 PR4a) ────────────────────────────────


class CsrSignRequest(BaseModel):
    """Body for ``POST /v1/principals/csr``."""

    principal_id: str = Field(
        ..., min_length=7, max_length=255,
        description="<trust-domain>/<org>/<principal-type>/<name>",
    )
    csr_pem: str = Field(
        ..., min_length=128, max_length=8192,
        description="PEM-encoded CSR; SAN must contain the SPIFFE URI of principal_id",
    )


class CsrSignResponse(BaseModel):
    """Body returned by ``POST /v1/principals/csr``."""

    cert_pem: str
    cert_thumbprint: str = Field(
        ..., description="SHA-256 hex digest of the DER-encoded cert",
    )
    cert_not_after: datetime


@router.post(
    "/csr",
    response_model=CsrSignResponse,
    status_code=status.HTTP_201_CREATED,
)
async def sign_csr(
    body: CsrSignRequest,
    token: TokenPayload = Depends(get_current_agent),
) -> CsrSignResponse:
    """Sign a user-principal CSR with the Mastio broker CA.

    The cert is short-lived (1h, see ``USER_CERT_TTL``). The Ambassador
    refreshes by calling this endpoint again at the next SSO touch.

    Errors:
      - 400 ``CsrValidationError`` — malformed CSR / SAN / weak key /
        SPIFFE id mismatch / bad principal_id format.
      - 403 ``token.org != principal_id_org`` — caller may only mint
        certs for principals in its own org.
    """
    try:
        _spiffe_uri, principal_org = parse_principal_id_to_spiffe(body.principal_id)
    except ValueError as exc:
        # Audit H-IO-2 — log full parse error, return a generic detail.
        _log.warning("principals.csr: invalid principal_id: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid principal_id",
        ) from exc

    if token.org != principal_org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cannot sign a CSR for a principal in a different org",
        )

    # Security review F-001 (security-review-app-2026-05-14.md): the
    # caller must be the org's Ambassador / Frontdesk workload, not a
    # regular agent. Without this gate, any DPoP-authenticated agent
    # in the org could mint a fresh user-principal cert (including
    # ``user/admin``) and present it at ``/auth/token`` with
    # ``principal_type=user`` to bypass the ADR-009 mastio counter-
    # signature and the mTLS gate (auth/router.py:151,
    # auth/mastio_countersig.enforce_on_token_request:118-119).
    # Workload principals are provisioned by the Mastio out-of-band
    # (Ambassador onboarding), so requiring this principal type pins
    # the CSR endpoint to its intended caller.
    principal_type_in_path = body.principal_id.split("/", 3)[2]
    if (
        principal_type_in_path == "user"
        and token.principal_type != "workload"
    ):
        _log.warning(
            "principals.csr: non-workload caller "
            "[caller_agent_id=%s caller_principal_type=%s principal_id=%s] "
            "refused to mint a user-principal cert",
            token.agent_id, token.principal_type, body.principal_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "only a workload principal (Ambassador) may sign a "
                "user-principal CSR"
            ),
        )

    try:
        cert_pem, thumbprint, not_after = await sign_user_csr(
            csr_pem=body.csr_pem,
            principal_id=body.principal_id,
        )
    except CsrValidationError as exc:
        # Audit H-IO-2 — CSR validation errors can echo OpenSSL/cryptography
        # internals (ASN.1, DER, key params); log for ops, return generic.
        _log.warning("principals.csr: CSR validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSR validation failed",
        ) from exc

    _log.info(
        "principals.csr signed principal_id=%s thumbprint=%s not_after=%s",
        body.principal_id, thumbprint, not_after.isoformat(),
    )
    return CsrSignResponse(
        cert_pem=cert_pem,
        cert_thumbprint=thumbprint,
        cert_not_after=not_after,
    )
