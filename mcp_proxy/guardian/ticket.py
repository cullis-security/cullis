"""Guardian inspection ticket — JWT HS256 with short TTL.

Mastio signs a ticket alongside every ``/v1/guardian/inspect`` decision.
The receiving agent runtime verifies it before delivering the message
to user code, so a tampered SDK that returns a synthetic ``pass``
without calling Mastio cannot fabricate the signature.

Algorithm: HS256 (symmetric — the verifier is co-located with the
issuer in v1, both being the customer's own Mastio + agent fleet).
The shared secret lives in ``MCP_PROXY_GUARDIAN_TICKET_KEY`` (hex or
base64url accepted). Distribution to agent runtimes piggy-backs on
the org CA bundle refresh (open question Q2 in the rollout plan,
default resolved here as "same channel, rotate together").

TTL is intentionally short (30s) so a captured ticket cannot be
replayed across messages; the SDK calls Mastio once per message.
"""
from __future__ import annotations

import base64
import binascii
import re
import time
from typing import Any

import jwt as jose_jwt

# urlsafe_b64decode silently ignores characters outside [A-Za-z0-9_-=]
# unless we pre-check, which would let "not-hex-not-b64!!!" decode to
# garbage instead of raising. Pre-validate explicitly.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_=-]+$")


_ALGO = "HS256"


class GuardianTicketError(Exception):
    """Raised on any verification failure (expired, bad signature, …).

    Carries a short ``reason`` tag so audit + observability can label
    the failure mode without depending on the underlying jwt-library
    exception class names.
    """

    def __init__(self, reason: str, *, detail: str | None = None):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


def _decode_key(key: str) -> bytes:
    """Accept hex or base64url for the shared secret; raise if neither.

    Operators dropping random bytes into the env tend to base64url them
    (no padding) or hex-encode them. Either is fine; we try hex first
    (the canonical form in the docs) and fall back to b64url.
    """
    if not key:
        raise GuardianTicketError(
            "missing_key",
            detail="MCP_PROXY_GUARDIAN_TICKET_KEY is empty.",
        )
    try:
        return binascii.unhexlify(key)
    except (binascii.Error, ValueError):
        pass
    if not _B64URL_RE.match(key):
        raise GuardianTicketError(
            "malformed_key",
            detail=(
                "GUARDIAN_TICKET_KEY is neither hex nor base64url "
                "(unexpected characters)."
            ),
        )
    try:
        padded = key + "=" * (-len(key) % 4)
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        # Audit F-B-119 — base64 decoder messages occasionally interpolate
        # input fragments. The key itself is a Guardian secret; even a
        # 4-char prefix in the error message is too much.
        from mcp_proxy._http_safety import safe_http_detail
        raise GuardianTicketError(
            "malformed_key",
            detail=safe_http_detail(
                exc,
                public_hint="GUARDIAN_TICKET_KEY base64url decode failed",
                log_context="guardian.ticket._decode_key",
            ),
        ) from exc


def sign_ticket(
    *,
    key: str,
    agent_id: str,
    peer_agent_id: str,
    msg_id: str,
    direction: str,
    decision: str,
    audit_id: str,
    ttl_s: int = 30,
) -> tuple[str, int]:
    """Sign a guardian ticket. Returns (jwt_str, exp_unix_seconds).

    Fields kept minimal so the agent runtime's verify path stays cheap.
    The audit_id ties back to the persisted row for ops queries.
    """
    secret = _decode_key(key)
    now = int(time.time())
    exp = now + ttl_s
    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "peer_agent_id": peer_agent_id,
        "msg_id": msg_id,
        "direction": direction,
        "decision": decision,
        "audit_id": audit_id,
        "iat": now,
        "exp": exp,
    }
    token = jose_jwt.encode(payload, secret, algorithm=_ALGO)
    return token, exp


def verify_ticket(
    *,
    key: str,
    token: str,
    expected_msg_id: str | None = None,
    expected_agent_id: str | None = None,
) -> dict[str, Any]:
    """Verify a guardian ticket and return the decoded claims.

    The optional ``expected_*`` checks are the agent runtime's job:
    a rogue SDK could relay a legit ticket from a different message,
    so the runtime binds the ticket to the message it is about to
    deliver. We surface the check here so callers don't have to
    re-implement it consistently.
    """
    secret = _decode_key(key)
    try:
        claims = jose_jwt.decode(token, secret, algorithms=[_ALGO])
    except jose_jwt.ExpiredSignatureError as exc:
        raise GuardianTicketError("expired", detail=str(exc)) from exc
    except jose_jwt.InvalidSignatureError as exc:
        raise GuardianTicketError("bad_signature", detail=str(exc)) from exc
    except jose_jwt.InvalidTokenError as exc:
        raise GuardianTicketError("malformed", detail=str(exc)) from exc

    if expected_msg_id is not None and claims.get("msg_id") != expected_msg_id:
        raise GuardianTicketError(
            "msg_id_mismatch",
            detail=f"expected msg_id={expected_msg_id}, got {claims.get('msg_id')}",
        )
    if expected_agent_id is not None and claims.get("agent_id") != expected_agent_id:
        raise GuardianTicketError(
            "agent_id_mismatch",
            detail=f"expected agent_id={expected_agent_id}, got {claims.get('agent_id')}",
        )
    return claims
