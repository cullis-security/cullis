"""ADR-033 Phase 2 — WebAuthn endpoints on ``/v1/principals/{pid}/webauthn``.

Three flows live here:

* Registration. Two-step ceremony, browser-driven via the Connector
  dashboard: ``register/start`` mints options + a challenge, ``register/
  finish`` verifies the attestation and persists the credential.
* Authentication options. ``authenticate/start`` mints options + a
  challenge bound to the principal. The signed assertion that the
  browser returns is forwarded inline with the next session emission
  to ``/v1/principals/connector-login`` and verified there (see
  :mod:`mcp_proxy.auth.user_session`).
* Credential management. List + delete, used by the dashboard's
  /webauthn page so a user can name and revoke their authenticators.

Auth: every endpoint requires the Connector's mTLS cert + DPoP-bound
JWT (``get_authenticated_agent``). The caller's org must match the
``principal_id`` org — a Connector in org A cannot enrol or read
credentials for a principal in org B.
"""
from __future__ import annotations

import base64
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.auth.webauthn import (
    WebAuthnLibraryMissingError,
    WebAuthnVerificationFailedError,
)
from mcp_proxy.auth.webauthn import authentication as wa_auth
from mcp_proxy.auth.webauthn import registration as wa_reg
from mcp_proxy.auth.webauthn import storage as wa_storage
from mcp_proxy.auth.webauthn._lib import is_available as webauthn_available
from mcp_proxy.config import get_settings
from mcp_proxy.db import log_audit
from mcp_proxy.models import TokenPayload
from mcp_proxy.registry.principals_csr import parse_principal_id_to_spiffe

_log = logging.getLogger("mcp_proxy.registry.user_principals_webauthn_router")

router = APIRouter(prefix="/v1/principals", tags=["principals", "webauthn"])

# Audit chain action constants.
_ACTION_REGISTER = "frontdesk_shared_webauthn_credential_registered"
_ACTION_REVOKE = "frontdesk_shared_webauthn_credential_revoked"
_ACTION_REJECTED = "frontdesk_shared_webauthn_verification_rejected"


# ─────────────────────────────────────────────────────────────────────────────
# Request / response models
# ─────────────────────────────────────────────────────────────────────────────


class RegisterStartResponse(BaseModel):
    options: dict
    challenge_b64url: str


class RegisterFinishRequest(BaseModel):
    challenge_b64url: str = Field(..., min_length=8, max_length=256)
    credential: dict = Field(..., description="AttestationResponse JSON from the browser")
    name: str | None = Field(
        None, max_length=128,
        description="Human-friendly label, e.g. \"Yubikey 5C\".",
    )


class RegisterFinishResponse(BaseModel):
    credential_id_b64url: str


class AuthStartResponse(BaseModel):
    options: dict
    challenge_b64url: str


class CredentialView(BaseModel):
    credential_id_b64url: str
    name: str | None
    transports: list[str] | None
    aaguid_hex: str | None
    sign_count: int
    created_at: str
    last_used_at: str | None


class CredentialList(BaseModel):
    credentials: list[CredentialView]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _require_webauthn_available() -> None:
    """Reject the call early if the optional library is missing."""
    if not webauthn_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "webauthn package not installed; install the [webauthn] "
                "extra on the Mastio image to enable Phase 2 endpoints."
            ),
        )


def _enforce_same_org(principal_id: str, token: TokenPayload) -> None:
    """Refuse the call when the caller is in a different org than the principal."""
    try:
        _spiffe_uri, principal_org = parse_principal_id_to_spiffe(principal_id)
    except ValueError as exc:
        _log.warning("webauthn: invalid principal_id %r: %s", principal_id, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid principal_id",
        ) from exc
    caller_org = getattr(token, "org", None)
    if caller_org and caller_org != principal_org:
        _log.warning(
            "webauthn: cross-org refused (caller=%s principal_org=%s)",
            caller_org, principal_org,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="caller org does not own this principal",
        )


def _expected_origins() -> list[str]:
    settings = get_settings()
    raw = (settings.webauthn_expected_origin or "").strip()
    if raw:
        return [origin.strip() for origin in raw.split(",") if origin.strip()]
    if settings.webauthn_rp_id:
        return [f"https://{settings.webauthn_rp_id}"]
    return []


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{principal_id:path}/webauthn/register/start",
    response_model=RegisterStartResponse,
)
async def register_start(
    principal_id: str,
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> RegisterStartResponse:
    _require_webauthn_available()
    _enforce_same_org(principal_id, token)

    settings = get_settings()
    existing = await wa_storage.load_credentials_for_principal(principal_id)
    user_name = principal_id.split("/")[-1] or principal_id

    try:
        options = wa_reg.generate_options(
            rp_id=settings.webauthn_rp_id,
            rp_name=settings.webauthn_rp_name,
            principal_id=principal_id,
            user_name=user_name,
            display_name=None,
            existing_credentials=[c.credential_id for c in existing],
        )
    except WebAuthnLibraryMissingError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    await wa_storage.get_challenge_store().put(
        principal_id=principal_id,
        ceremony="register",
        value=options.challenge_b64url,
        ttl=settings.webauthn_challenge_ttl_seconds,
    )
    return RegisterStartResponse(
        options=options.options_json,
        challenge_b64url=options.challenge_b64url,
    )


@router.post(
    "/{principal_id:path}/webauthn/register/finish",
    response_model=RegisterFinishResponse,
)
async def register_finish(
    principal_id: str,
    body: RegisterFinishRequest,
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> RegisterFinishResponse:
    _require_webauthn_available()
    _enforce_same_org(principal_id, token)

    issued = await wa_storage.get_challenge_store().take(
        principal_id=principal_id,
        ceremony="register",
    )
    if issued is None or issued != body.challenge_b64url:
        await _audit_rejected(
            agent_id=token.agent_id,
            principal_id=principal_id,
            ceremony="register",
            reason="challenge_mismatch_or_expired",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="registration challenge expired or already consumed",
        )

    try:
        verified = wa_reg.verify_response(
            rp_id=get_settings().webauthn_rp_id,
            expected_origins=_expected_origins(),
            expected_challenge_b64url=body.challenge_b64url,
            credential_response=body.credential,
        )
    except WebAuthnVerificationFailedError as exc:
        await _audit_rejected(
            agent_id=token.agent_id,
            principal_id=principal_id,
            ceremony="register",
            reason=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    await wa_storage.save_credential(
        principal_id=principal_id,
        credential_id=verified.credential_id,
        credential_public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        aaguid=verified.aaguid,
        transports=verified.transports,
        name=body.name,
    )
    await log_audit(
        token.agent_id,
        _ACTION_REGISTER,
        "info",
        details={
            "principal_id": principal_id,
            "credential_id_b64url": _b64url(verified.credential_id),
            "aaguid_hex": verified.aaguid.hex() if verified.aaguid else None,
            "transports": verified.transports,
            "name": body.name,
        },
    )
    return RegisterFinishResponse(
        credential_id_b64url=_b64url(verified.credential_id),
    )


@router.post(
    "/{principal_id:path}/webauthn/authenticate/start",
    response_model=AuthStartResponse,
)
async def authenticate_start(
    principal_id: str,
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> AuthStartResponse:
    _require_webauthn_available()
    _enforce_same_org(principal_id, token)

    settings = get_settings()
    records = await wa_storage.load_credential_records_for_verification(principal_id)
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no WebAuthn credentials registered for this principal",
        )

    try:
        options = wa_auth.generate_options(
            rp_id=settings.webauthn_rp_id,
            allowed_credentials=records,
        )
    except WebAuthnVerificationFailedError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    await wa_storage.get_challenge_store().put(
        principal_id=principal_id,
        ceremony="authenticate",
        value=options.challenge_b64url,
        ttl=settings.webauthn_challenge_ttl_seconds,
    )
    return AuthStartResponse(
        options=options.options_json,
        challenge_b64url=options.challenge_b64url,
    )


@router.get(
    "/{principal_id:path}/webauthn/credentials",
    response_model=CredentialList,
)
async def list_credentials(
    principal_id: str,
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> CredentialList:
    _enforce_same_org(principal_id, token)
    rows = await wa_storage.load_credentials_for_principal(principal_id)
    out: list[CredentialView] = []
    for row in rows:
        out.append(
            CredentialView(
                credential_id_b64url=_b64url(row.credential_id),
                name=row.name,
                transports=row.transports,
                aaguid_hex=row.aaguid.hex() if row.aaguid else None,
                sign_count=row.sign_count,
                created_at=row.created_at,
                last_used_at=row.last_used_at,
            )
        )
    return CredentialList(credentials=out)


@router.delete(
    "/{principal_id:path}/webauthn/credentials/{credential_id_b64url}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_credential(
    principal_id: str,
    credential_id_b64url: str,
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> None:
    _enforce_same_org(principal_id, token)
    try:
        credential_id = _b64url_decode(credential_id_b64url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="credential_id is not a base64url string",
        ) from exc

    deleted = await wa_storage.delete_credential(
        principal_id=principal_id,
        credential_id=credential_id,
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="credential not found for this principal",
        )

    await log_audit(
        token.agent_id,
        _ACTION_REVOKE,
        "info",
        details={
            "principal_id": principal_id,
            "credential_id_b64url": credential_id_b64url,
        },
    )


async def _audit_rejected(
    *,
    agent_id: str,
    principal_id: str,
    ceremony: str,
    reason: str,
) -> None:
    """Best-effort rejection audit (never raises into the request path)."""
    try:
        await log_audit(
            agent_id,
            _ACTION_REJECTED,
            "warning",
            details={
                "principal_id": principal_id,
                "ceremony": ceremony,
                "reason": reason[:512],
            },
        )
    except Exception as exc:
        _log.debug("audit-rejected emit failed (non-critical): %s", exc)
