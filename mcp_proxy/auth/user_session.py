"""Connector session verifier (ADR-032 Layer 2 + ADR-033 Phase 2 enforcement).

When the Connector calls Mastio after a successful ``cullis-connector login``
the MCP envelope carries two headers in addition to the usual cert + DPoP:

* ``X-Cullis-Session-Token`` — opaque session id from ``user_sessions.session_id``
* ``X-Cullis-On-Behalf-Of-User`` — the user principal_id the agent acts for

The auth deps call :func:`maybe_stamp_user_session` *after* the agent
identity is verified. If the headers are absent, that's fine — the
request stays attributed to the agent only (anonymous-agent mode). If
they're present and valid, the user principal_id lands in the
per-request contextvar so ``audit_log.on_behalf_of_user_id`` populates
without each tool handler forwarding the value explicitly.

Failure modes are intentionally graceful for the legacy gates: an
expired, revoked, or mismatched session does NOT 401 the request, it
logs a warning and leaves the contextvar at None. ADR-033 Phase 2
adds one strict failure mode on top: when
``MCP_PROXY_WEBAUTHN_ENFORCEMENT="required"`` and the stored session
row lacks a ``user_signed_assertion`` field, the function raises
HTTP 401 so the Connector knows it must re-authenticate the user
through the WebAuthn ceremony. Customers running Phase 1 enforcement
(``warn``) keep the legacy audit-warning behaviour.

ADR-033 Phase 1 audit warning (carried over):
When a session token is accepted but the stored row lacks a
``user_signed_assertion`` field (no cryptographic proof from the user),
:func:`maybe_stamp_user_session` emits a WARNING log and writes an
audit chain row of type
``frontdesk_shared_unauthenticated_user_session_warning``. This
visibility was the Phase 1 baseline; Phase 2 strengthens it into the
enforcement gate above.

ADR-033 Phase 2 session emission helper:
:func:`verify_and_serialise_user_assertion` is the helper the
connector-login endpoints call when the Connector dashboard forwards
a freshly produced WebAuthn assertion. Successful verification
returns a JSON-serialised canonical form of the assertion plus the
credential id, ready to be persisted on the new ``user_sessions``
row via :func:`mcp_proxy.db.create_user_session`. Verification
failure is signalled with a typed exception so the calling endpoint
can map it to a 401 or a 400 depending on the enforcement mode.
"""
from __future__ import annotations

import hmac
import json
import logging
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status

from mcp_proxy.auth.user_context import set_on_behalf_of_user
from mcp_proxy.db import get_user_session

_log = logging.getLogger("mcp_proxy.auth.user_session")

# Action constant for the ADR-033 Phase 1 audit entry.
ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION = (
    "frontdesk_shared_unauthenticated_user_session_warning"
)

# Action constant for the ADR-033 Phase 2 enforcement rejection.
ACTION_FRONTDESK_SHARED_WEBAUTHN_ENFORCEMENT_REJECTED = (
    "frontdesk_shared_webauthn_enforcement_rejected"
)

# Action constant for the ADR-033 Phase 2 authenticated session marker.
ACTION_FRONTDESK_SHARED_AUTHENTICATED_USER_SESSION = (
    "frontdesk_shared_authenticated_user_session"
)

SESSION_HEADER = "X-Cullis-Session-Token"
PRINCIPAL_HEADER = "X-Cullis-On-Behalf-Of-User"


async def maybe_stamp_user_session(
    request: Request,
    *,
    caller_agent_id: str,
    caller_cert_thumbprint: str | None = None,
) -> str | None:
    """Inspect the request for Connector session headers; verify + stamp.

    Returns the verified ``principal_id`` on success, ``None`` otherwise.
    Never raises — failure is logged and the contextvar stays at None.

    ADR-033 Phase 1: when the session is accepted but lacks a
    ``user_signed_assertion``, emits an audit chain row and a WARNING log
    so operators can alert on unauthenticated-to-user sessions in
    Frontdesk shared mode.
    """
    session_token = request.headers.get(SESSION_HEADER)
    claimed_principal = request.headers.get(PRINCIPAL_HEADER)
    if not session_token or not claimed_principal:
        return None

    row = await get_user_session(session_token)
    if row is None:
        _log.warning(
            "user-session: unknown session token presented by agent=%s",
            caller_agent_id,
        )
        return None

    if row.get("revoked_at"):
        _log.warning(
            "user-session: revoked session presented by agent=%s",
            caller_agent_id,
        )
        return None

    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except (TypeError, ValueError):
        _log.warning("user-session: malformed expires_at on session row")
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        _log.info(
            "user-session: expired session presented by agent=%s (re-login required)",
            caller_agent_id,
        )
        return None

    stored_principal = row.get("principal_id")
    if not stored_principal or not hmac.compare_digest(
        stored_principal, claimed_principal,
    ):
        _log.warning(
            "user-session: principal header mismatch (claimed=%s stored=%s)",
            claimed_principal, stored_principal,
        )
        return None

    if caller_cert_thumbprint:
        stored_thumb = row.get("agent_cert_thumbprint", "")
        if stored_thumb and not hmac.compare_digest(
            stored_thumb, caller_cert_thumbprint,
        ):
            _log.warning(
                "user-session: cert thumbprint mismatch — session bound to "
                "a different device (agent=%s)",
                caller_agent_id,
            )
            return None

    # ADR-033 Phase 2 enforcement gate. Read the configured mode and
    # decide whether the absence of a stored ``user_signed_assertion``
    # is fatal (required), warned (warn), or silently accepted (off).
    enforcement = _resolve_webauthn_enforcement()
    has_user_assertion = bool(row.get("user_signed_assertion"))

    if enforcement == "required" and not has_user_assertion:
        await _emit_enforcement_rejected(
            caller_agent_id=caller_agent_id,
            claimed_principal=stored_principal,
            session_id=session_token,
            reason="missing_user_signed_assertion",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "user session lacks a WebAuthn assertion; re-authenticate "
                "via the Connector dashboard before retrying."
            ),
        )

    set_on_behalf_of_user(stored_principal)
    _log.debug(
        "user-session: stamped on_behalf_of_user=%s (agent=%s)",
        stored_principal, caller_agent_id,
    )

    # ADR-033 Phase 1 — emit audit warning when no user-signed assertion is
    # present. Phase 2 enforcement="required" already returned 401 above,
    # so this path only fires under enforcement="warn" (default migration
    # mode) and "off" (only when the operator has explicitly opted out).
    if enforcement != "off":
        await _emit_unauthenticated_session_warning_if_needed(
            caller_agent_id=caller_agent_id,
            claimed_principal=stored_principal,
            session_id=session_token,
            row=row,
        )

    return stored_principal


def _resolve_webauthn_enforcement() -> str:
    """Read the enforcement mode from settings, falling back to 'warn'.

    Centralised here so the gate stays consistent between
    :func:`maybe_stamp_user_session` and
    :func:`verify_and_serialise_user_assertion`. Unknown / empty values
    degrade to 'warn' (the default migration mode) rather than raising
    in the auth path.
    """
    try:
        from mcp_proxy.config import get_settings

        raw = (get_settings().webauthn_enforcement or "warn").lower()
    except Exception:  # pragma: no cover - defensive on settings module load
        return "warn"
    return raw if raw in {"off", "warn", "required"} else "warn"


async def _emit_unauthenticated_session_warning_if_needed(
    *,
    caller_agent_id: str,
    claimed_principal: str,
    session_id: str,
    row: dict,
) -> None:
    """Emit WARNING log + audit chain entry for sessions lacking user assertion.

    Checks ``MCP_PROXY_FRONTDESK_AUDIT_WARNING_ENABLED`` before acting.
    Never raises — audit warning failures must not break the auth flow.
    The audit entry is awaited inline (not fire-and-forget) to ensure
    correctness: the write is cheap (same DB connection pool) and the
    latency added is below the DPoP proof window.
    """
    try:
        from mcp_proxy.config import get_settings
        if not get_settings().frontdesk_audit_warning_enabled:
            return
    except Exception:
        return

    # Check whether the session row carries a user-signed assertion (Phase 2).
    # The field does not exist yet; any truthy value would suppress the warning.
    has_user_assertion = bool(row.get("user_signed_assertion"))
    if has_user_assertion:
        return

    ts = datetime.now(timezone.utc).isoformat()

    _log.warning(
        "frontdesk-shared: session accepted without user cryptographic assertion "
        "(agent=%s claimed_user=%s session=%s). "
        "This is expected pre-Phase-2 (ADR-033). "
        "Alert if rate exceeds 10/min per container.",
        caller_agent_id,
        claimed_principal,
        session_id[:12] + "...",  # truncate for log hygiene
    )

    from mcp_proxy.db import log_audit

    try:
        await log_audit(
            caller_agent_id,
            ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION,
            "warning",
            details={
                "connector_agent_id": caller_agent_id,
                "claimed_user_principal_id": claimed_principal,
                "session_id": session_id[:12] + "...",
                "timestamp": ts,
                "note": (
                    "No user_signed_assertion field present. "
                    "Phase 2 WebAuthn-bound sessions will add this. "
                    "See ADR-033."
                ),
            },
        )
    except Exception as exc:
        _log.debug(
            "frontdesk-shared: audit warning entry failed (non-critical): %s", exc,
        )


async def _emit_enforcement_rejected(
    *,
    caller_agent_id: str,
    claimed_principal: str,
    session_id: str,
    reason: str,
) -> None:
    """Emit an audit chain row for an ADR-033 enforcement rejection.

    Best-effort: a failure to write the audit row must not mask the
    underlying 401 raised by the caller.
    """
    _log.warning(
        "frontdesk-shared: enforcement=required rejected session "
        "(agent=%s claimed_user=%s session=%s reason=%s)",
        caller_agent_id,
        claimed_principal,
        session_id[:12] + "...",
        reason,
    )

    from mcp_proxy.db import log_audit

    try:
        await log_audit(
            caller_agent_id,
            ACTION_FRONTDESK_SHARED_WEBAUTHN_ENFORCEMENT_REJECTED,
            "warning",
            details={
                "connector_agent_id": caller_agent_id,
                "claimed_user_principal_id": claimed_principal,
                "session_id": session_id[:12] + "...",
                "reason": reason,
                "note": (
                    "MCP_PROXY_WEBAUTHN_ENFORCEMENT=required rejected the "
                    "session because the stored row lacks a WebAuthn "
                    "assertion. The Connector should drive the user "
                    "through the WebAuthn ceremony and re-mint the "
                    "session before retrying."
                ),
            },
        )
    except Exception as exc:
        _log.debug(
            "frontdesk-shared: enforcement audit entry failed (non-critical): %s",
            exc,
        )


async def verify_and_serialise_user_assertion(
    *,
    caller_agent_id: str,
    principal_id: str,
    assertion: dict,
    challenge_b64url: str,
) -> tuple[str, bytes]:
    """Verify a fresh WebAuthn assertion and return persistable bytes.

    Called from the connector-login routers when the Connector
    dashboard forwards a freshly produced assertion alongside the
    session emission request. Returns ``(canonical_json, credential_id)``
    ready to be passed to :func:`mcp_proxy.db.create_user_session` via
    its new ``user_signed_assertion`` + ``user_credential_id`` kwargs.

    On any verification failure the function writes a
    ``frontdesk_shared_webauthn_verification_rejected`` audit row and
    raises :class:`fastapi.HTTPException` 401 (matching the request-path
    enforcement) so the calling endpoint does not need to translate
    library exceptions itself.
    """
    from mcp_proxy.auth.webauthn import authentication as wa_auth
    from mcp_proxy.auth.webauthn import storage as wa_storage
    from mcp_proxy.auth.webauthn.errors import (
        WebAuthnLibraryMissingError,
        WebAuthnVerificationFailedError,
    )
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import log_audit

    settings = get_settings()
    rp_id = settings.webauthn_rp_id
    raw_origin = (settings.webauthn_expected_origin or "").strip()
    if raw_origin:
        expected_origins = [o.strip() for o in raw_origin.split(",") if o.strip()]
    elif rp_id:
        expected_origins = [f"https://{rp_id}"]
    else:
        expected_origins = []

    records = await wa_storage.load_credential_records_for_verification(principal_id)

    try:
        verified = wa_auth.verify_response(
            rp_id=rp_id,
            expected_origins=expected_origins,
            expected_challenge_b64url=challenge_b64url,
            credential_response=assertion,
            credentials=records,
        )
    except (WebAuthnVerificationFailedError, WebAuthnLibraryMissingError) as exc:
        try:
            await log_audit(
                caller_agent_id,
                "frontdesk_shared_webauthn_verification_rejected",
                "warning",
                details={
                    "principal_id": principal_id,
                    "reason": str(exc)[:512],
                },
            )
        except Exception as audit_exc:
            _log.debug(
                "frontdesk-shared: verification-rejected audit failed: %s",
                audit_exc,
            )
        # Audit F-B-119 — WebAuthn library exceptions are usually
        # curated, but ``cryptography`` / base64 decoders mixed in via
        # the verification chain can leak cert subject DNs or PEM
        # fragments. Redact at the boundary.
        from mcp_proxy._http_safety import safe_http_detail
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=safe_http_detail(
                exc,
                public_hint="WebAuthn assertion rejected",
                log_context="webauthn_verify_assertion",
            ),
        ) from exc

    await wa_storage.update_sign_count(
        credential_id=verified.credential_id,
        new_sign_count=verified.new_sign_count,
    )
    canonical = json.dumps(assertion, separators=(",", ":"), sort_keys=True)

    try:
        await log_audit(
            caller_agent_id,
            ACTION_FRONTDESK_SHARED_AUTHENTICATED_USER_SESSION,
            "info",
            details={
                "principal_id": principal_id,
                "credential_id_prefix": verified.credential_id.hex()[:16],
                "new_sign_count": verified.new_sign_count,
            },
        )
    except Exception as audit_exc:
        _log.debug(
            "frontdesk-shared: authenticated-session audit failed: %s",
            audit_exc,
        )

    return canonical, verified.credential_id
