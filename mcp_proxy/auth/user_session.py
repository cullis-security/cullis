"""Connector session verifier (ADR-032 Layer 2).

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

Failure modes are intentionally graceful: an expired, revoked, or
mismatched session does NOT 401 the request. We log a warning and
leave the contextvar at None. Rationale: the agent identity is the
primary credential — the user binding is optional dual-attribution.
If the user wants strict enforcement they can run with
``CULLIS_REQUIRE_USER_SESSION=true`` (config flag added in a follow-up).

ADR-033 Phase 1 audit warning:
When a session token is accepted but the stored row lacks a
``user_signed_assertion`` field (no cryptographic proof from the user),
:func:`maybe_stamp_user_session` emits a WARNING log and writes an
audit chain row of type
``frontdesk_shared_unauthenticated_user_session_warning``. This
visibility is the Phase 1 baseline; Phase 2 (WebAuthn-bound session
tokens) will add the assertion and the warning will cease.
"""
from __future__ import annotations

import hmac
import logging
from datetime import datetime, timezone

from fastapi import Request

from mcp_proxy.auth.user_context import set_on_behalf_of_user
from mcp_proxy.db import get_user_session

_log = logging.getLogger("mcp_proxy.auth.user_session")

# Action constant for the ADR-033 Phase 1 audit entry.
ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION = (
    "frontdesk_shared_unauthenticated_user_session_warning"
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

    set_on_behalf_of_user(stored_principal)
    _log.debug(
        "user-session: stamped on_behalf_of_user=%s (agent=%s)",
        stored_principal, caller_agent_id,
    )

    # ADR-033 Phase 1 — emit audit warning when no user-signed assertion is
    # present. Today this fires on every accepted session because Phase 2
    # (WebAuthn-bound tokens) is not yet implemented. The warning enables
    # SOC alerting on anomalous on_behalf_of volume before Phase 2 lands.
    await _emit_unauthenticated_session_warning_if_needed(
        caller_agent_id=caller_agent_id,
        claimed_principal=stored_principal,
        session_id=session_token,
        row=row,
    )

    return stored_principal


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
