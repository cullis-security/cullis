"""ADR-025 Phase 5 / F4 R3 — Connector local-auth → user-bound session.

Companion to ``connector_login_router.py``. The two share the
``user_sessions`` row format (R1's migration 0034) and the
``maybe_stamp_user_session`` downstream pinning (R2). They diverge on
the trust model:

* OIDC path (``connector_login_router.py``): the Connector replays a
  fresh IdP id_token; Mastio derives the user from ``sub`` + ``iss``.
* Local-auth path (this file): the Connector has already verified
  bcrypt against ``cullis_connector/identity/users.py`` (ADR-025
  Phase 1) and declares ``"user X just logged in"``. Mastio trusts
  the declaration because:

    1. cert+DPoP authenticates the calling Connector device.
    2. The device cert is org-CA issued + thumbprint-pinned, so a
       compromised Connector can be revoked centrally.
    3. The threat-model parity with OIDC: an attacker who compromises
       the IdP token store can mint arbitrary ``sub`` claims; an
       attacker who compromises a Connector can declare arbitrary
       local_subject claims. Both paths fall back to cert revocation
       + audit forensics. Acceptable for pilot pre-revenue per
       ADR-032 + ADR-025 threat model.

NO password verify here. NO password column. Migration 0028
explicitly removed ``local_user_principals.password_hash`` with the
rationale "Mastio is not the password store". The credential lives in
the Connector's ``users.db``; Mastio just mints + tracks the session.

Endpoint:

    POST /v1/principals/connector-login-local-attribution

Request body:

    {
      "local_subject": "alice",
      "display_name": "Alice Smith",
      "device_cert_thumbprint": "<sha256-hex>",
      "auth_mode": "local"
    }

Response: same shape as the SSO sibling.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.config import get_settings
from mcp_proxy.db import (
    create_user_session,
    upsert_local_user_principal_local,
)
from mcp_proxy.models import TokenPayload
from mcp_proxy.registry.connector_login_router import (
    _client_ip,
    _enforce_connector_login_rate_limit,
)

_log = logging.getLogger("mcp_proxy.registry.connector_login_local_attribution")

router = APIRouter(prefix="/v1/principals", tags=["principals"])


_DEFAULT_TTL_SECONDS = 3600

# Username convention shared with ``mcp_proxy/admin/users.py`` +
# ``cullis_connector/identity/users.py``: 1-64 chars, alphanumerics +
# ``._-``. Constrains the body so a malformed Connector can't smuggle a
# control byte through to ``local_user_principals.user_name`` (which we
# splice into the SPIFFE-shaped principal_id below).
_LOCAL_SUBJECT_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


class ConnectorLoginLocalAttributionRequest(BaseModel):
    """Body for ``POST /v1/principals/connector-login-local-attribution``."""

    local_subject: str = Field(..., min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    device_cert_thumbprint: str = Field(
        ..., min_length=32, max_length=128,
        description="SHA-256 hex digest of the calling Connector's "
                    "agent cert (DER).",
    )
    auth_mode: Literal["local"] = "local"

    # ADR-033 Phase 2 — optional WebAuthn assertion produced by the
    # browser during ``navigator.credentials.get``. When present the
    # router verifies it against a previously registered credential and
    # stores it on the new ``user_sessions`` row. When
    # ``MCP_PROXY_WEBAUTHN_ENFORCEMENT="required"`` and these fields are
    # missing the router returns 401 so the Connector dashboard knows
    # it must drive the user through the WebAuthn ceremony before
    # retrying.
    user_signed_assertion: dict | None = Field(
        default=None,
        description=(
            "AssertionResponse JSON returned by navigator.credentials."
            "get on the Connector dashboard. Required when "
            "MCP_PROXY_WEBAUTHN_ENFORCEMENT=required."
        ),
    )
    webauthn_challenge_b64url: str | None = Field(
        default=None, min_length=8, max_length=256,
        description=(
            "Base64url challenge previously issued by "
            "/v1/principals/{id}/webauthn/authenticate/start. Required "
            "alongside user_signed_assertion."
        ),
    )


class ConnectorLoginLocalAttributionResponse(BaseModel):
    """Body returned by ``POST /v1/principals/connector-login-local-attribution``."""

    user_id: str
    session_token: str
    expires_at: datetime


def _derive_caller_cert_thumbprint(request: Request) -> str | None:
    """SHA-256 hex of the caller's TLS client cert, or None.

    Mirrors :func:`mcp_proxy.registry.connector_login_router._derive_caller_cert_thumbprint`
    so the local-auth flow gets the same MEDIUM C2 guarantee: the body
    thumbprint cannot disagree with the cert nginx accepted.
    """
    from mcp_proxy.auth.client_cert import _decode_escaped_pem

    if request.headers.get("X-SSL-Client-Verify") != "SUCCESS":
        return None
    escaped_pem = request.headers.get("X-SSL-Client-Cert") or ""
    if not escaped_pem:
        return None
    try:
        pem = _decode_escaped_pem(escaped_pem)
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    except (ValueError, AttributeError):
        return None
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER),
    ).hexdigest()


def _resolve_ttl_seconds() -> int:
    """Read the configurable session TTL, fall back to 1h."""
    settings = get_settings()
    raw = getattr(settings, "user_session_ttl_seconds", None)
    if raw is None:
        return _DEFAULT_TTL_SECONDS
    try:
        ttl = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_TTL_SECONDS
    if ttl <= 0:
        return _DEFAULT_TTL_SECONDS
    return ttl


@router.post(
    "/connector-login-local-attribution",
    response_model=ConnectorLoginLocalAttributionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def connector_login_local_attribution(
    body: ConnectorLoginLocalAttributionRequest,
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> ConnectorLoginLocalAttributionResponse:
    """Bind a local-auth user identity to the calling Connector.

    The Connector attests it verified bcrypt against its local
    ``users.db`` for ``body.local_subject``; Mastio mints a
    ``user_sessions`` row pinned to the calling Connector's cert
    thumbprint so the resulting session_token only attributes audit
    rows when re-presented from the same device.
    """
    if not _LOCAL_SUBJECT_RE.match(body.local_subject):
        # Pydantic max_length already capped at 64, but the regex closes
        # the SQL/SPIFFE injection vector on the *content* of the value.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "local_subject must match the local-user_name convention "
                "(alphanumerics + ._- only, 1-64 chars)"
            ),
        )

    # Same MEDIUM C2 guarantee as the SSO sibling: refuse a body
    # thumbprint that disagrees with the nginx-forwarded cert.
    server_thumbprint = _derive_caller_cert_thumbprint(request)
    if server_thumbprint is not None:
        if not hmac.compare_digest(
            server_thumbprint.lower(), body.device_cert_thumbprint.lower(),
        ):
            _log.warning(
                "connector-login-local-attribution: device_cert_thumbprint "
                "mismatch (agent=%s body_prefix=%s server_prefix=%s)",
                token.agent_id,
                body.device_cert_thumbprint[:16],
                server_thumbprint[:16],
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "device_cert_thumbprint does not match the TLS "
                    "client cert presented at the handshake"
                ),
            )
        bound_thumbprint = server_thumbprint
    else:
        bound_thumbprint = body.device_cert_thumbprint

    # F-A-208 — see sibling router for the threat model. Same three
    # buckets: per-agent, per-IP, per-(agent, local_subject). Placed
    # after the regex + thumbprint gates so malformed bodies still 400
    # without consuming budget.
    await _enforce_connector_login_rate_limit(
        agent_id=token.agent_id,
        client_ip=_client_ip(request),
        subject=body.local_subject,
        endpoint="connector-login-local-attribution",
    )

    # principal_id mirrors the SSO sibling's shape so downstream policy /
    # audit code does not need a special-case for local-auth. The
    # uniqueness invariant is preserved: ``users.db`` enforces UNIQUE
    # on ``user_name`` within a Connector deployment, and each
    # deployment is bound to one Mastio org.
    user_name = body.local_subject.lower()
    principal_id = f"{token.org}::user::{user_name}"

    try:
        await upsert_local_user_principal_local(
            principal_id=principal_id,
            user_name=user_name,
            display_name=body.display_name,
        )
    except Exception:  # noqa: BLE001
        _log.exception(
            "connector-login-local-attribution: upsert failed for %s",
            principal_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="user-principal store temporarily unavailable",
        )

    ttl = _resolve_ttl_seconds()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl)
    session_id = secrets.token_urlsafe(32)

    # ADR-033 Phase 2 — verify the WebAuthn assertion when present, refuse
    # the login outright when enforcement="required" and it is missing.
    enforcement = (
        get_settings().webauthn_enforcement or "warn"
    ).lower()
    serialised_assertion: str | None = None
    credential_id: bytes | None = None
    if body.user_signed_assertion is not None:
        if not body.webauthn_challenge_b64url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "user_signed_assertion was provided but "
                    "webauthn_challenge_b64url is missing"
                ),
            )
        from mcp_proxy.auth.user_session import (
            verify_and_serialise_user_assertion,
        )

        serialised_assertion, credential_id = (
            await verify_and_serialise_user_assertion(
                caller_agent_id=token.agent_id,
                principal_id=principal_id,
                assertion=body.user_signed_assertion,
                challenge_b64url=body.webauthn_challenge_b64url,
            )
        )
    elif enforcement == "required":
        _log.warning(
            "connector-login-local-attribution: enforcement=required but "
            "request omitted WebAuthn assertion (agent=%s user=%s)",
            token.agent_id, principal_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "WebAuthn assertion required by MCP_PROXY_WEBAUTHN_"
                "ENFORCEMENT=required; complete the WebAuthn ceremony "
                "before retrying."
            ),
        )

    # The SSO sibling carries the real ``sso_subject`` / ``idp_issuer``
    # for the audit row; local-auth has neither, so we stuff a constant
    # marker into ``sso_subject`` so a downstream SQL "where did this
    # session come from" query can still cluster local vs SSO without a
    # schema migration. ``idp_issuer`` mirrors the same marker.
    try:
        await create_user_session(
            session_id=session_id,
            principal_id=principal_id,
            agent_cert_thumbprint=bound_thumbprint,
            sso_subject=f"local:{user_name}",
            idp_issuer="local",
            display_name=body.display_name,
            expires_at=expires_at,
            user_signed_assertion=serialised_assertion,
            user_credential_id=credential_id,
        )
    except Exception:  # noqa: BLE001
        _log.exception(
            "connector-login-local-attribution: create_user_session failed "
            "for %s",
            principal_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="session store temporarily unavailable",
        )

    _log.info(
        "connector-login-local-attribution: agent=%s bound user=%s "
        "auth_mode=local session_ttl=%ds",
        token.agent_id, principal_id, ttl,
    )

    return ConnectorLoginLocalAttributionResponse(
        user_id=principal_id,
        session_token=session_id,
        expires_at=expires_at,
    )
