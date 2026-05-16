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
"""
from __future__ import annotations

import hmac
import logging
from datetime import datetime, timezone

from fastapi import Request

from mcp_proxy.auth.user_context import set_on_behalf_of_user
from mcp_proxy.db import get_user_session

_log = logging.getLogger("mcp_proxy.auth.user_session")


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
    return stored_principal
