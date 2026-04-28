"""FastAPI router exposing per-session audit trail reads to authenticated agents.

Endpoint:

    GET /v1/audit/session/{session_id}

Authentication: mTLS client cert (ADR-014). The cert presented at the TLS
handshake IS the agent identity — same dep as ``/v1/egress/*``.

Authorization (MVP): the caller may read the audit trail for a session
only if the ``audit_log`` table contains at least one entry with
``agent_id = caller_agent_id`` AND ``request_id = session_id``. In
practice every session the agent participated in (open/send/accept/
close/poll…) writes such a row, so this is a reasonable proxy for
"was this agent a peer of the session". It is intentionally not
bulletproof — a full per-session ACL store is future work.

Response shape: ``list[AuditEntry]`` ordered by timestamp ascending,
capped at 500 entries per response to bound DoS surface.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text

from mcp_proxy.auth.client_cert import get_agent_from_client_cert
from mcp_proxy.db import get_db
from mcp_proxy.models import InternalAgent

logger = logging.getLogger("mcp_proxy")

router = APIRouter(tags=["audit"])

# Cap responses so a single authenticated agent can't force the proxy to
# serialize unbounded rows. 500 comfortably covers any realistic session.
_MAX_ENTRIES = 500


class AuditEntry(BaseModel):
    """One immutable row from ``audit_log``, scoped to a single session."""

    timestamp: str
    agent_id: str
    action: str
    tool_name: str | None = None
    status: str
    detail: str | None = None
    duration_ms: float | None = None


def _row_to_entry(row: Any) -> AuditEntry:
    duration_raw = row["duration_ms"]
    duration: float | None
    if duration_raw is None or duration_raw == "":
        duration = None
    else:
        try:
            duration = float(duration_raw)
        except (TypeError, ValueError):
            duration = None
    return AuditEntry(
        timestamp=row["timestamp"],
        agent_id=row["agent_id"],
        action=row["action"],
        tool_name=row["tool_name"],
        status=row["status"],
        detail=row["detail"],
        duration_ms=duration,
    )


@router.get(
    "/v1/audit/session/{session_id}",
    response_model=list[AuditEntry],
)
async def get_session_audit(
    session_id: str,
    agent: InternalAgent = Depends(get_agent_from_client_cert),
) -> list[AuditEntry]:
    """Return the audit trail for ``session_id`` if the caller is a peer.

    * 200 with ``[]`` is never returned for a legitimate caller on a real
      session — the caller's own open/send/etc. entries always exist.
    * 403 is returned when no row links the caller to the session.
    * 404 is returned when the session_id has no audit entries at all.
    """
    async with get_db() as conn:
        # Authorization probe: is the caller a peer of this session?
        probe = await conn.execute(
            text(
                "SELECT 1 FROM audit_log "
                "WHERE request_id = :sid AND agent_id = :aid "
                "LIMIT 1"
            ),
            {"sid": session_id, "aid": agent.agent_id},
        )
        own_row = probe.first()

        # Does the session exist at all (any agent)?
        any_probe = await conn.execute(
            text(
                "SELECT 1 FROM audit_log WHERE request_id = :sid LIMIT 1"
            ),
            {"sid": session_id},
        )
        any_row = any_probe.first()

        if any_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No audit entries for the given session_id",
            )
        if own_row is None:
            logger.warning(
                "audit_read_forbidden agent=%s session=%s",
                agent.agent_id, session_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Caller is not a peer of this session",
            )

        result = await conn.execute(
            text(
                "SELECT timestamp, agent_id, action, tool_name, status, "
                "detail, duration_ms "
                "FROM audit_log "
                "WHERE request_id = :sid "
                "ORDER BY timestamp ASC, id ASC "
                "LIMIT :lim"
            ),
            {"sid": session_id, "lim": _MAX_ENTRIES},
        )
        rows = result.mappings().all()

    return [_row_to_entry(r) for r in rows]
