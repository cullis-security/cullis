"""Persistence for local_sessions — save on every state change, restore
non-terminal rows at startup so the in-memory store survives restarts.

Schema (alembic 0002_local_tables.py): session_id, initiator_agent_id,
responder_agent_id, status, created_at, last_activity_at, close_reason.
Capabilities and expires_at are NOT persisted — they're reconstructed
in-memory (see LocalSession / LocalSessionStore).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import text

from mcp_proxy.db import get_db
from mcp_proxy.local.models import SessionCloseReason, SessionStatus
from mcp_proxy.local.session import LocalSession, LocalSessionStore

_log = logging.getLogger("mcp_proxy.local.persistence")


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _parse_iso(raw: str | None) -> datetime | None:
    if raw is None:
        return None
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def save_session(session: LocalSession) -> None:
    """UPSERT a session row. Called from the router on every state change."""
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_sessions
                    (session_id, initiator_agent_id, responder_agent_id,
                     status, created_at, last_activity_at, close_reason)
                VALUES
                    (:session_id, :initiator_agent_id, :responder_agent_id,
                     :status, :created_at, :last_activity_at, :close_reason)
                ON CONFLICT(session_id) DO UPDATE SET
                    status = excluded.status,
                    last_activity_at = excluded.last_activity_at,
                    close_reason = excluded.close_reason
                """
            ),
            {
                "session_id": session.session_id,
                "initiator_agent_id": session.initiator_agent_id,
                "responder_agent_id": session.responder_agent_id,
                "status": session.status.value,
                "created_at": _iso(session.created_at),
                "last_activity_at": _iso(session.last_activity_at),
                "close_reason": session.close_reason.value if session.close_reason else None,
            },
        )


async def restore_sessions(store: LocalSessionStore) -> int:
    """Load all non-terminal sessions into the in-memory store on startup.

    Rebuilds expires_at from created_at + store.hard_ttl (schema has no
    expires_at column). Sessions already past expiry are left persisted
    but NOT loaded — the sweeper (Phase 3d) will observe them as closed
    via the DB next sweep; nothing to deliver meanwhile.
    """
    restored = 0
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT session_id, initiator_agent_id, responder_agent_id,
                       status, created_at, last_activity_at, close_reason
                  FROM local_sessions
                 WHERE status IN ('pending', 'active')
                """
            )
        )
        rows = list(result.mappings())

    now = datetime.now(timezone.utc)
    for row in rows:
        created_at = _parse_iso(row["created_at"]) or now
        expires_at = created_at + store.hard_ttl
        if expires_at <= now:
            continue
        session = LocalSession(
            session_id=row["session_id"],
            initiator_agent_id=row["initiator_agent_id"],
            responder_agent_id=row["responder_agent_id"],
            requested_capabilities=[],
            status=SessionStatus(row["status"]),
            created_at=created_at,
            expires_at=expires_at,
            last_activity_at=_parse_iso(row["last_activity_at"]) or created_at,
            close_reason=(
                SessionCloseReason(row["close_reason"])
                if row["close_reason"] else None
            ),
        )
        store.restore(session)
        restored += 1

    if restored:
        _log.info("Restored %d local session(s) from DB", restored)
    return restored
