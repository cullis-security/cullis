"""ADR-021 PR4a (proxy-side) — POST /v1/principals/csr + AD-style password login.

The Frontdesk Connector calls ``/csr`` at every SSO touch to mint a
fresh user-principal cert. Originally lived on the broker; moved to
the proxy because the org-CA private key (the right signer for these
certs) only exists on the proxy. See ``principals_csr.py`` header for
the full rationale.

The ``/password-login`` and ``/change-password`` endpoints layer an
Active-Directory style local credential on top of the same principal
table. Admin pre-creates a row with bcrypt(password) +
must_change_password via ``POST /v1/admin/users``; the user logs in
with user_name + password + their DPoP public key, gets a short-lived
DPoP-bound JWT, and spends it on ``/csr`` to materialise the cert.

Auth contract:
- ``/csr`` and ``/change-password`` use ``get_authenticated_agent``
  (DPoP-bound JWT). RBAC inside ``sign_user_csr`` enforces same-org.
- ``/password-login`` is intentionally unauthenticated — it IS the
  authentication endpoint. Brute-force is bounded by bcrypt cost
  (rounds=12) and the rate limiter the dashboard wraps it in.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from mcp_proxy.admin.users import (
    _SELECT_COLS,
    _principal_id as _short_principal_id,
    hash_password,
    verify_password,
)
from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.auth.dpop import compute_jkt
from mcp_proxy.db import get_db
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

    # AD-style password gate: if the principal has a local password and
    # the change-password flag is still set, refuse to mint a long-lived
    # cert until the user rotates the admin-supplied initial credential.
    # Only applies to user principals — agents/workloads have no
    # password leg. Best-effort lookup; absence of the row leaves the
    # legacy SSO flow untouched.
    if token.principal_type == "user":
        try:
            short_pid = f"{token.org}::user::{body.principal_id.split('/')[-1]}"
            user_row = await _load_user_row(short_pid)
            if user_row and user_row["password_hash"] and bool(
                user_row["must_change_password"],
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "must change password before minting cert — call "
                        "/v1/principals/change-password first"
                    ),
                )
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001 — best-effort gate
            _log.warning(
                "principals.csr: must_change_password gate skipped: %s", exc,
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
        cert_pem, thumbprint, not_after = await sign_user_csr(
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
    # Best-effort: surface the user in the dashboard's Users tab. Errors
    # are swallowed inside the helper — the user-facing flow is the
    # cert response, not the directory upsert.
    from mcp_proxy.admin.users import upsert_from_csr
    await upsert_from_csr(
        principal_id=body.principal_id,
        org_id=token.org,
        cert_thumbprint=thumbprint,
    )
    return CsrSignResponse(
        cert_pem=cert_pem,
        cert_thumbprint=thumbprint,
        cert_not_after=not_after,
    )


# ── AD-style password layer ─────────────────────────────────────────────


# Short TTL so the login token can only be used for the immediate CSR /
# change-password follow-up; the resulting cert is the long-lived
# credential, not this JWT.
_LOGIN_TOKEN_TTL_SECONDS = 5 * 60
_MIN_PASSWORD_LENGTH = 8
_MAX_PASSWORD_LENGTH = 128


class PasswordLoginRequest(BaseModel):
    user_name: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    password: str = Field(
        ..., min_length=_MIN_PASSWORD_LENGTH, max_length=_MAX_PASSWORD_LENGTH,
    )
    # The DPoP public key the client just generated. The server hashes
    # it (RFC 7638) and pins ``cnf.jkt`` so the issued JWT can only be
    # spent with proofs from this same key.
    dpop_jwk: dict = Field(...)


class PasswordLoginResponse(BaseModel):
    access_token: str
    token_type: str = "DPoP"
    expires_in: int
    principal_id: str
    must_change_password: bool


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(
        ..., min_length=_MIN_PASSWORD_LENGTH, max_length=_MAX_PASSWORD_LENGTH,
    )
    new_password: str = Field(
        ..., min_length=_MIN_PASSWORD_LENGTH, max_length=_MAX_PASSWORD_LENGTH,
    )


class ChangePasswordResponse(BaseModel):
    principal_id: str
    must_change_password: bool


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _load_user_row(principal_id: str) -> Optional[dict]:
    async with get_db() as conn:
        row = (await conn.execute(
            text(f"SELECT {_SELECT_COLS} FROM local_user_principals "
                 "WHERE principal_id = :pid"),
            {"pid": principal_id},
        )).mappings().first()
    return dict(row) if row else None


@router.post(
    "/password-login",
    response_model=PasswordLoginResponse,
    status_code=status.HTTP_200_OK,
)
async def password_login(
    body: PasswordLoginRequest, request: Request,
) -> PasswordLoginResponse:
    """Verify ``user_name + password`` and mint a DPoP-bound JWT.

    Failure modes return generic 401 (no oracle on which leg failed):
    - row missing
    - password mismatch
    - SSO-only row (``password_hash`` NULL)
    - row disabled

    On success the response includes ``must_change_password``; the SPA
    must show a change-password screen before letting the user touch
    anything sensitive. The CSR endpoint also refuses cert minting
    while the flag is set, so even a misbehaving client cannot bypass.
    """
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None or not getattr(mgr, "ca_loaded", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent manager not initialized — Org CA not loaded",
        )
    issuer = getattr(request.app.state, "local_issuer", None)
    if issuer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="local JWT issuer not initialized",
        )
    try:
        dpop_jkt = compute_jkt(body.dpop_jwk)
    except (ValueError, KeyError, TypeError) as exc:
        _log.warning("password-login: invalid DPoP JWK: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid DPoP JWK",
        ) from exc

    pid = _short_principal_id(mgr.org_id, body.user_name)
    row = await _load_user_row(pid)
    if row is None:
        # Constant-ish time: still hash a throwaway to dodge user-enum.
        await verify_password(body.password, "$2b$12$invalidsaltinvalidsalt..")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    if bool(row["disabled"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="account disabled",
        )
    if not row["password_hash"]:
        # SSO-only row — no local credential to verify against.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "account has no local password — sign in via Frontdesk SSO"
            ),
        )
    if not await verify_password(body.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )

    must_change = bool(row["must_change_password"])
    token = issuer.issue(
        agent_id=pid,
        ttl_seconds=_LOGIN_TOKEN_TTL_SECONDS,
        extra_claims={
            "cnf": {"jkt": dpop_jkt},
            "principal_type": "user",
            "org": mgr.org_id,
            "must_change_password": must_change,
        },
    )
    _log.info(
        "password-login OK principal_id=%s must_change=%s",
        pid, must_change,
    )
    return PasswordLoginResponse(
        access_token=token.token,
        expires_in=token.expires_at - token.issued_at,
        principal_id=pid,
        must_change_password=must_change,
    )


@router.post(
    "/change-password",
    response_model=ChangePasswordResponse,
    status_code=status.HTTP_200_OK,
)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> ChangePasswordResponse:
    """Self-service password change — auth via the login JWT.

    Verifies the old password, hashes the new one, clears the
    ``must_change_password`` flag. Refuses if the principal is not a
    user (workloads + agents have no password leg) or the row was
    disabled between login and change.
    """
    if token.principal_type != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only user principals may change a password",
        )
    pid = token.agent_id  # `<org>::user::<name>` shape (ADR-020)
    row = await _load_user_row(pid)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="user principal not found",
        )
    if bool(row["disabled"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="account disabled",
        )
    if not row["password_hash"] or not await verify_password(
        body.old_password, row["password_hash"],
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid current password",
        )
    if body.old_password == body.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="new password must differ from current",
        )
    new_hash = await hash_password(body.new_password)
    now = _now_iso()
    async with get_db() as conn:
        await conn.execute(
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
                "pid": pid, "pw": new_hash,
                "mcp": bool(False), "now": now,
            },
        )
    _log.info("change-password OK principal_id=%s", pid)
    return ChangePasswordResponse(
        principal_id=pid,
        must_change_password=False,
    )
