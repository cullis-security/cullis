"""ADR-021 PR4a (proxy-side) — POST /v1/principals/csr.

The Frontdesk Connector calls this endpoint at every SSO touch to mint
a fresh user-principal cert. Originally lived on the broker; moved to
the proxy because the org-CA private key (the right signer for these
certs) only exists on the proxy. See ``principals_csr.py`` header for
the full rationale.

Auth: the same DPoP-bound JWT the proxy already issues for the rest of
``/v1/*`` (``get_authenticated_agent``). RBAC: caller may only sign
CSRs for principals in its own org — enforced inside ``sign_user_csr``
against ``AgentManager.org_id``.
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.models import TokenPayload
from mcp_proxy.registry.principals_csr import (
    CsrValidationError,
    parse_principal_id_to_spiffe,
    sign_user_csr,
)

_log = logging.getLogger("mcp_proxy.registry.user_principals_router")

router = APIRouter(prefix="/v1/principals", tags=["principals"])


class CsrSignRequest(BaseModel):
    """Body for ``POST /v1/principals/csr``."""

    principal_id: str = Field(
        ..., min_length=7, max_length=255,
        description="<trust-domain>/<org>/<principal-type>/<name>",
    )
    csr_pem: str = Field(
        ..., min_length=128, max_length=8192,
        description=(
            "PEM-encoded CSR; SAN must contain the SPIFFE URI of "
            "principal_id"
        ),
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
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> CsrSignResponse:
    """Sign a user-principal CSR with the proxy's Org CA.

    Errors:
      - 400 ``CsrValidationError`` — malformed CSR / SAN / weak key /
        SPIFFE id mismatch / bad principal_id format / wrong-org.
      - 403 ``token.org != principal_id_org`` — caller may only mint
        certs for principals in its own org.
      - 503 — proxy has no Org CA loaded yet (broker setup not done).
    """
    try:
        _spiffe_uri, principal_org = parse_principal_id_to_spiffe(
            body.principal_id,
        )
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

    # Security review F-001 (security-review-app-2026-05-14.md): port of
    # the broker-side gate to the proxy sister router. Without this
    # check, any DPoP-authenticated agent in the org could submit a CSR
    # for ``<td>/<org>/user/<anyone>`` (including ``user/admin``) and
    # get a proxy-CA-signed user cert valid for 1h, then present it at
    # ``/auth/token`` with ``principal_type=user`` to bypass the ADR-009
    # countersig + mTLS gates. The fix requires the caller to be a
    # ``principal_type=workload`` (the Ambassador / Frontdesk) for any
    # CSR whose principal_id segment is ``user``. CSRs for ``agent`` and
    # ``workload`` principal-ids stay open to the legacy admin path.
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

    agent_manager = getattr(request.app.state, "agent_manager", None)
    if agent_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "agent_manager not initialised — proxy is still booting"
            ),
        )

    try:
        cert_pem, thumbprint, pubkey_thumb, not_after = await sign_user_csr(
            csr_pem=body.csr_pem,
            principal_id=body.principal_id,
            agent_manager=agent_manager,
        )
    except CsrValidationError as exc:
        # Audit H-IO-2 — CSR validation errors can echo OpenSSL/cryptography
        # internals (ASN.1, DER, key params) and SPIFFE-id mismatch text;
        # log for ops, return generic.
        _log.warning("principals.csr: CSR validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSR validation failed",
        ) from exc
    except RuntimeError as exc:
        # Org CA not loaded — surface to the caller as 503 so their
        # provisioner retries instead of failing the user session.
        # Audit H-IO-2 — log full reason, return a generic detail.
        _log.warning("principals.csr: Org CA unavailable: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Org CA temporarily unavailable",
        ) from exc

    _log.info(
        "principals.csr signed principal_id=%s thumbprint=%s not_after=%s",
        body.principal_id, thumbprint, not_after.isoformat(),
    )
    # Surface the user in the dashboard's Users tab AND pin the TOFU
    # pubkey thumbprint on first signature (CRIT-1 fix). Errors are
    # swallowed inside the helper for the dashboard side, but pubkey
    # pinning happens unconditionally — without it, the cert-auth dep
    # has nothing to compare against on the next request.
    from mcp_proxy.admin.users import upsert_from_csr
    await upsert_from_csr(
        principal_id=body.principal_id,
        org_id=token.org,
        cert_thumbprint=thumbprint,
        pubkey_thumbprint=pubkey_thumb,
    )
    return CsrSignResponse(
        cert_pem=cert_pem,
        cert_thumbprint=thumbprint,
        cert_not_after=not_after,
    )
