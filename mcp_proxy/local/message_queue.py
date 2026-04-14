"""Local message queue — ADR-001 Phase 3c.

Twin of `app/broker/message_queue.py` targeting the proxy-local
`local_messages` table. Same public behavior: at-least-once delivery
with TTL + idempotency, drained on recipient WS reconnect.

Schema differences vs the broker queue (kept intentionally lean for
single-org proxy use):
  - `status` is a TEXT enum ('pending' | 'delivered' | 'expired')
    instead of an int for readability at the SQL prompt.
  - No `seq` or `attempts` columns — delivery order is by enqueued_at
    and a retry counter isn't needed for the simpler single-process
    delivery path.
  - No DB-level UNIQUE constraint on (recipient, idempotency_key) —
    single-process proxy, app-level dedupe is sufficient. When proxy
    HA lands (Redis + Postgres), the migration will add the unique
    index and this module will switch to ON CONFLICT DO NOTHING.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from mcp_proxy.db import get_db

_log = logging.getLogger("mcp_proxy.local.message_queue")


STATUS_PENDING = "pending"
STATUS_DELIVERED = "delivered"
STATUS_EXPIRED = "expired"

DEFAULT_TTL_SECONDS = 300  # mirror broker M3 default


@dataclass
class QueuedLocalMessage:
    msg_id: str
    session_id: str
    sender_agent_id: str
    recipient_agent_id: str
    payload_ciphertext: str
    idempotency_key: str | None
    enqueued_at: datetime
    expires_at: datetime | None


@dataclass
class ExpiredLocalMessageNotice:
    msg_id: str
    session_id: str
    sender_agent_id: str
    recipient_agent_id: str


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _parse(raw: str | None) -> datetime | None:
    if raw is None:
        return None
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def enqueue(
    *,
    session_id: str,
    sender_agent_id: str,
    recipient_agent_id: str,
    payload_ciphertext: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    idempotency_key: str | None = None,
) -> tuple[str, bool]:
    """Persist a message awaiting ack.

    Returns `(msg_id, inserted)` — when `inserted` is False the caller
    is looking at a replay that collided with an existing row via the
    idempotency key; the returned msg_id is the canonical one. Without
    an idempotency key, every call is a fresh insert.
    """
    async with get_db() as conn:
        if idempotency_key is not None:
            existing = await conn.execute(
                text(
                    """
                    SELECT msg_id FROM local_messages
                     WHERE recipient_agent_id = :recipient
                       AND idempotency_key = :ikey
                    """
                ),
                {"recipient": recipient_agent_id, "ikey": idempotency_key},
            )
            row = existing.first()
            if row is not None:
                return row[0], False

        msg_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        await conn.execute(
            text(
                """
                INSERT INTO local_messages
                    (msg_id, session_id, sender_agent_id, recipient_agent_id,
                     payload_ciphertext, idempotency_key, status, enqueued_at,
                     delivered_at, expires_at)
                VALUES
                    (:msg_id, :session_id, :sender, :recipient,
                     :payload, :ikey, :status, :enqueued_at,
                     NULL, :expires_at)
                """
            ),
            {
                "msg_id": msg_id,
                "session_id": session_id,
                "sender": sender_agent_id,
                "recipient": recipient_agent_id,
                "payload": payload_ciphertext,
                "ikey": idempotency_key,
                "status": STATUS_PENDING,
                "enqueued_at": _iso(now),
                "expires_at": _iso(expires),
            },
        )
        return msg_id, True


async def fetch_pending_for_recipient(
    recipient_agent_id: str,
    *,
    limit: int = 500,
) -> list[QueuedLocalMessage]:
    """Return pending messages ordered by enqueue time. Pure read."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT msg_id, session_id, sender_agent_id, recipient_agent_id,
                       payload_ciphertext, idempotency_key, enqueued_at, expires_at
                  FROM local_messages
                 WHERE recipient_agent_id = :recipient
                   AND status = :status
                 ORDER BY enqueued_at ASC
                 LIMIT :limit
                """
            ),
            {
                "recipient": recipient_agent_id,
                "status": STATUS_PENDING,
                "limit": limit,
            },
        )
        out: list[QueuedLocalMessage] = []
        for row in result.mappings():
            out.append(
                QueuedLocalMessage(
                    msg_id=row["msg_id"],
                    session_id=row["session_id"],
                    sender_agent_id=row["sender_agent_id"],
                    recipient_agent_id=row["recipient_agent_id"],
                    payload_ciphertext=row["payload_ciphertext"],
                    idempotency_key=row["idempotency_key"],
                    enqueued_at=_parse(row["enqueued_at"]),
                    expires_at=_parse(row["expires_at"]),
                )
            )
        return out


async def mark_delivered(msg_id: str, recipient_agent_id: str) -> bool:
    """Flip a pending row to `delivered`. Scoped by recipient so one agent
    can't ack another agent's queue entry. Returns True on success."""
    async with get_db() as conn:
        now_iso = _iso(datetime.now(timezone.utc))
        result = await conn.execute(
            text(
                """
                UPDATE local_messages
                   SET status = :delivered,
                       delivered_at = :now
                 WHERE msg_id = :msg_id
                   AND recipient_agent_id = :recipient
                   AND status = :pending
                """
            ),
            {
                "delivered": STATUS_DELIVERED,
                "now": now_iso,
                "msg_id": msg_id,
                "recipient": recipient_agent_id,
                "pending": STATUS_PENDING,
            },
        )
        return (result.rowcount or 0) > 0


async def fetch_for_session(
    session_id: str,
    after_iso: str | None = None,
    *,
    limit: int = 500,
) -> list[QueuedLocalMessage]:
    """Read messages visible to session participants. Includes both
    pending and delivered rows so the legacy REST poll path (pre-WS
    clients) observes a stable history."""
    async with get_db() as conn:
        params: dict = {"session_id": session_id, "limit": limit}
        where = "session_id = :session_id"
        if after_iso is not None:
            where += " AND enqueued_at > :after_iso"
            params["after_iso"] = after_iso
        result = await conn.execute(
            text(
                f"""
                SELECT msg_id, session_id, sender_agent_id, recipient_agent_id,
                       payload_ciphertext, idempotency_key, enqueued_at, expires_at
                  FROM local_messages
                 WHERE {where}
                 ORDER BY enqueued_at ASC
                 LIMIT :limit
                """
            ),
            params,
        )
        return [
            QueuedLocalMessage(
                msg_id=row["msg_id"],
                session_id=row["session_id"],
                sender_agent_id=row["sender_agent_id"],
                recipient_agent_id=row["recipient_agent_id"],
                payload_ciphertext=row["payload_ciphertext"],
                idempotency_key=row["idempotency_key"],
                enqueued_at=_parse(row["enqueued_at"]),
                expires_at=_parse(row["expires_at"]),
            )
            for row in result.mappings()
        ]


async def sweep_expired(
    *, limit: int = 1000
) -> list[ExpiredLocalMessageNotice]:
    """Flip TTL-expired pending rows to status=expired and return the
    set so callers can notify senders. Used by the Phase 3d sweeper."""
    async with get_db() as conn:
        now_iso = _iso(datetime.now(timezone.utc))
        result = await conn.execute(
            text(
                """
                SELECT msg_id, session_id, sender_agent_id, recipient_agent_id
                  FROM local_messages
                 WHERE status = :pending
                   AND expires_at IS NOT NULL
                   AND expires_at < :now
                 LIMIT :limit
                """
            ),
            {"pending": STATUS_PENDING, "now": now_iso, "limit": limit},
        )
        notices = [
            ExpiredLocalMessageNotice(
                msg_id=row["msg_id"],
                session_id=row["session_id"],
                sender_agent_id=row["sender_agent_id"],
                recipient_agent_id=row["recipient_agent_id"],
            )
            for row in result.mappings()
        ]
        if not notices:
            return []
        await conn.execute(
            text(
                """
                UPDATE local_messages
                   SET status = :expired
                 WHERE status = :pending
                   AND expires_at IS NOT NULL
                   AND expires_at < :now
                """
            ),
            {"expired": STATUS_EXPIRED, "pending": STATUS_PENDING, "now": now_iso},
        )
        return notices
