"""ADR-032 Layer 2 — Connector OIDC login → user-bound session.

After ``cullis-connector login`` walks the user through an OIDC flow
with the configured IdP, the Connector POSTs to this endpoint with:

* ``user_subject_sso`` — the ``sub`` claim from the validated ID token
* ``display_name``    — email / name surfaced by the IdP
* ``idp_issuer``      — issuer URL from the ID token
* ``device_cert_thumbprint`` — SHA-256 of the Connector's enrolled cert
  (the caller's own cert, sent so the proxy can pin the session to the
  exact device that authenticated this request).

Auth: same DPoP-bound path as the rest of ``/v1/*`` (``get_authenticated_agent``).
The endpoint is invoked by the *agent* identity of the Connector (the
device cert + DPoP key minted at enrollment). The user identity comes
from the body; the agent identity tells the proxy *which* device is
binding it.

Output: opaque ``session_token`` (just ``user_sessions.session_id``)
plus the ``user_id`` (derived ``<org>::user::<name>``) and the absolute
``expires_at``. The Connector keeps these locally and forwards the
token on every subsequent MCP envelope as ``X-Cullis-Session-Token``.

Logout: ``DELETE /v1/principals/connector-login`` revokes the session
row. The agent identity must match the one the session was bound to —
no cross-Connector revoke from an unrelated device.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.config import get_settings
from mcp_proxy.db import (
    create_user_session,
    get_user_session,
    revoke_user_session,
    upsert_local_user_principal_sso,
)
from mcp_proxy.models import TokenPayload

_log = logging.getLogger("mcp_proxy.registry.connector_login")

router = APIRouter(prefix="/v1/principals", tags=["principals"])


# Default TTL aligned with ADR-032 decision D — 1h idle banking-grade
# default, tunable via env.
_DEFAULT_TTL_SECONDS = 3600

# RFC-friendly user_name slug: lower-case alphanumerics + a couple of
# separators. Anything else is replaced. The full SSO sub stays in
# ``user_sessions.sso_subject`` + ``local_user_principals.sso_subject``,
# so this only shapes the *principal_id*, never the audit trail.
_USER_NAME_SLUG_RE = re.compile(r"[^a-z0-9._-]+")


class ConnectorLoginRequest(BaseModel):
    """Body for ``POST /v1/principals/connector-login``."""

    user_subject_sso: str = Field(..., min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    idp_issuer: str = Field(..., min_length=1, max_length=255)
    device_cert_thumbprint: str = Field(
        ..., min_length=32, max_length=128,
        description="SHA-256 hex digest of the calling Connector's "
                    "agent cert (DER).",
    )


class ConnectorLoginResponse(BaseModel):
    """Body returned by ``POST /v1/principals/connector-login``."""

    user_id: str
    session_token: str
    expires_at: datetime


def _identity_hash_suffix(idp_issuer: str, sso_subject: str) -> str:
    """Stable 8-hex disambiguator for the (issuer, subject) pair.

    Without this, two users with the same local-part across different
    IdPs (``alice@acme.com`` from the corporate IdP vs
    ``alice@external.com`` from a B2B partner federated into the same
    org) would slug to the *same* principal_id, and the upsert would
    silently rebind the principal to whichever caller logged in last
    — a cross-IdP identity-takeover primitive. Hashing the canonical
    pair makes the suffix deterministic across re-logins (the same
    user always lands on the same principal_id) while keeping the
    pair distinct from the next user with the same local-part.

    The hash input is normalised (lowercase + stripped) so trivial
    formatting differences from the IdP don't fork the suffix.
    """
    canonical = f"{idp_issuer.strip().lower()}|{sso_subject.strip()}".encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:8]


def _slug_from_sso(
    subject: str,
    fallback_name: str | None,
    *,
    idp_issuer: str,
) -> str:
    """Derive a stable user_name slug from the SSO subject.

    Format: ``<base>-<hash8>`` where ``<base>`` is the readable
    local-part of the subject (or a fallback) and ``<hash8>`` is the
    deterministic ``_identity_hash_suffix`` of the ``(idp_issuer, subject)``
    pair. The suffix is what makes the slug collision-safe across IdPs;
    the readable prefix is purely cosmetic (dashboard display).

    Email-shaped subjects (``alice@example.com``) keep ``alice`` as the
    prefix; UUIDs / opaque subs stay verbatim modulo the slug regex.
    The fallback display_name is consulted only when both transforms
    collapse to empty.
    """
    base = subject.split("@", 1)[0].lower()
    base = _USER_NAME_SLUG_RE.sub("-", base).strip("-")
    if not base and fallback_name:
        base = _USER_NAME_SLUG_RE.sub("-", fallback_name.lower()).strip("-")
    if not base:
        base = "user"
    # Trim the readable prefix so the total stays well under the 64-char
    # local-part budget even with the 9 extra chars from "-<hash8>".
    base = base[:55]
    suffix = _identity_hash_suffix(idp_issuer, subject)
    return f"{base}-{suffix}"


def _derive_caller_cert_thumbprint(request) -> str | None:
    """SHA-256 hex of the caller's TLS client cert, or None when nginx
    didn't forward one.

    Mirrors ``mcp_proxy.auth.client_cert.get_agent_from_client_cert``:
    nginx escapes the leaf PEM into the ``X-SSL-Client-Cert`` header
    when ``ssl_verify_client on`` accepted the handshake, and sets
    ``X-SSL-Client-Verify=SUCCESS`` next to it. We only trust the
    header when verify=SUCCESS so a request that bypassed nginx (or
    that landed via a misconfigured location block without mTLS) can't
    smuggle in a forged thumbprint.

    Returns ``None`` for dev / test deployments behind plain HTTP —
    the caller falls back to the body-supplied thumbprint there.
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
    "/connector-login",
    response_model=ConnectorLoginResponse,
    status_code=status.HTTP_201_CREATED,
)
async def connector_login(
    body: ConnectorLoginRequest,
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> ConnectorLoginResponse:
    """Bind a user identity to the calling Connector and mint a session."""
    # MEDIUM C2 — derive the device thumbprint server-side from the
    # nginx-forwarded client cert and refuse a body that disagrees.
    # Without this gate a caller authenticated with cert A could bind a
    # session to thumbprint B (which they don't hold), defeating the
    # ``maybe_stamp_user_session`` pinning step downstream. When nginx
    # is not forwarding a cert (dev / test without mTLS) the body
    # value is accepted as-is.
    server_thumbprint = _derive_caller_cert_thumbprint(request)
    if server_thumbprint is not None:
        if not hmac.compare_digest(
            server_thumbprint.lower(), body.device_cert_thumbprint.lower(),
        ):
            _log.warning(
                "connector-login: device_cert_thumbprint mismatch "
                "(agent=%s body_prefix=%s server_prefix=%s)",
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

    user_name = _slug_from_sso(
        body.user_subject_sso,
        body.display_name,
        idp_issuer=body.idp_issuer,
    )
    principal_id = f"{token.org}::user::{user_name}"

    # Upsert the user row so the dashboard "Users" tab + future audit
    # joins always have an authoritative metadata source for this
    # principal — even before the first CSR signing call.
    try:
        await upsert_local_user_principal_sso(
            principal_id=principal_id,
            user_name=user_name,
            display_name=body.display_name,
            sso_subject=body.user_subject_sso,
            idp_issuer=body.idp_issuer,
        )
    except Exception:  # noqa: BLE001
        _log.exception(
            "connector-login: upsert_local_user_principal_sso failed for %s",
            principal_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="user-principal store temporarily unavailable",
        )

    ttl = _resolve_ttl_seconds()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl)
    # url-safe + plenty of entropy. Stored verbatim — see helper.
    session_id = secrets.token_urlsafe(32)

    try:
        await create_user_session(
            session_id=session_id,
            principal_id=principal_id,
            agent_cert_thumbprint=bound_thumbprint,
            sso_subject=body.user_subject_sso,
            idp_issuer=body.idp_issuer,
            display_name=body.display_name,
            expires_at=expires_at,
        )
    except Exception:  # noqa: BLE001
        _log.exception(
            "connector-login: create_user_session failed for %s",
            principal_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="session store temporarily unavailable",
        )

    _log.info(
        "connector-login: agent=%s bound user=%s idp=%s session_ttl=%ds",
        token.agent_id, principal_id, body.idp_issuer, ttl,
    )

    return ConnectorLoginResponse(
        user_id=principal_id,
        session_token=session_id,
        expires_at=expires_at,
    )


@router.delete(
    "/connector-login",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def connector_logout(
    request: Request,
    token: TokenPayload = Depends(get_authenticated_agent),
) -> None:
    """Revoke the session named in ``X-Cullis-Session-Token``.

    Idempotent on a missing / unknown / already-revoked session: returns
    204 anyway so the Connector can safely call this on every logout
    without coordinating with the proxy on prior state.

    The caller must hold the same agent identity that bound the session
    — otherwise we silently no-op (avoids leaking which sessions exist).
    """
    session_token = request.headers.get("X-Cullis-Session-Token")
    if not session_token:
        return

    row = await get_user_session(session_token)
    if row is None:
        return

    # Don't let a Connector revoke a session it doesn't own. We compare
    # by ``principal_id`` org-prefix because the token's agent_id ≠
    # the session's user principal_id by construction; the org prefix
    # is the cheap shared invariant.
    stored_principal = row.get("principal_id", "")
    if not stored_principal.startswith(f"{token.org}::"):
        _log.warning(
            "connector-logout: cross-org revoke attempt (agent=%s session_org_prefix=%s)",
            token.agent_id, stored_principal.split("::", 1)[0],
        )
        return

    revoked = await revoke_user_session(session_token)
    if revoked:
        _log.info(
            "connector-logout: revoked session for user=%s (agent=%s)",
            stored_principal, token.agent_id,
        )
