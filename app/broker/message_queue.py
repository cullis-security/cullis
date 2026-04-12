"""
Proxy message queue — at-least-once delivery with TTL + idempotency (M3).

This module owns the lifecycle of queued ciphertext messages:

- ``enqueue`` persists a message awaiting ack, respecting the
  ``(recipient_agent_id, idempotency_key)`` UNIQUE constraint so replays
  from a retrying sender collapse into a single stored row.
- ``mark_delivered`` ack's a message (recipient confirms receipt).
- ``fetch_pending_for_recipient`` returns pending messages for drain on
  reconnect or WS resume.
- ``sweep_expired`` (used by the session_sweeper) flips TTL-expired rows
  to status=expired and yields the sender/session pairs so the router
  can notify senders via ``message.expired`` events.

Scope for M3 v1: the queue lives in the broker DB next to
session_messages. When per-org proxy storage ships (M5+), only the DSN
and the SQL dialect-specific dedup change — the public API here stays
stable.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.broker.db_models import ProxyMessageQueueRecord

_log = logging.getLogger("agent_trust")


# Delivery status enum values (kept as ints on the row for index efficiency)
DELIVERY_PENDING = 0
DELIVERY_DELIVERED = 1
DELIVERY_EXPIRED = 2


@dataclass
class QueuedMessage:
    """Lightweight DTO for dequeue-side consumers."""
    msg_id: str
    session_id: str
    recipient_agent_id: str
    sender_agent_id: str
    ciphertext: bytes
    seq: int
    enqueued_at: datetime
    ttl_expires_at: datetime
    attempts: int
    idempotency_key: Optional[str]


@dataclass
class ExpiredMessageNotice:
    """Returned by sweep_expired so the router can notify senders."""
    msg_id: str
    session_id: str
    sender_agent_id: str
    recipient_agent_id: str


# ─────────────────────────────────────────────────────────────────────
# Enqueue
# ─────────────────────────────────────────────────────────────────────
async def enqueue(
    db: AsyncSession,
    *,
    session_id: str,
    recipient_agent_id: str,
    sender_agent_id: str,
    ciphertext: bytes,
    seq: int,
    ttl_seconds: int,
    idempotency_key: Optional[str] = None,
) -> tuple[str, bool]:
    """Enqueue a ciphertext for later delivery (M3.2).

    Returns ``(msg_id, inserted)``:
      - ``inserted=True`` means a new row was created.
      - ``inserted=False`` means an existing row with the same
        ``(recipient_agent_id, idempotency_key)`` was found — the caller
        should treat the send as already-queued (idempotency, M3.5).

    ``idempotency_key`` is optional; when None the insert always succeeds
    (no dedupe surface). When provided, collisions are resolved at the
    DB level via the UNIQUE constraint — no race window.
    """
    msg_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    ttl = now + timedelta(seconds=ttl_seconds)

    values = dict(
        msg_id=msg_id,
        session_id=session_id,
        recipient_agent_id=recipient_agent_id,
        sender_agent_id=sender_agent_id,
        ciphertext=ciphertext,
        seq=seq,
        enqueued_at=now,
        ttl_expires_at=ttl,
        delivery_status=DELIVERY_PENDING,
        attempts=0,
        idempotency_key=idempotency_key,
    )

    dialect_name = db.bind.dialect.name if db.bind else "unknown"

    if idempotency_key is None:
        # No dedupe: a plain insert suffices. Wrap in IntegrityError catch
        # only as a belt-and-braces; the happy path does not hit it.
        try:
            db.add(ProxyMessageQueueRecord(**values))
            await db.commit()
            return msg_id, True
        except IntegrityError:
            await db.rollback()
            raise
    else:
        # Dedupe path: ON CONFLICT DO NOTHING targeting the UNIQUE
        # constraint. If the insert is skipped, re-read the existing
        # msg_id so the caller can continue their flow transparently.
        if dialect_name == "postgresql":
            stmt = pg_insert(ProxyMessageQueueRecord).values(**values)
            stmt = stmt.on_conflict_do_nothing(
                constraint="uq_proxy_queue_idempotency",
            )
        else:
            stmt = sqlite_insert(ProxyMessageQueueRecord).values(**values)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["recipient_agent_id", "idempotency_key"],
            )
        result = await db.execute(stmt)
        await db.commit()

        if result.rowcount > 0:
            return msg_id, True

        # Re-fetch the canonical msg_id for the dedupe row.
        existing = await db.execute(
            select(ProxyMessageQueueRecord.msg_id).where(
                ProxyMessageQueueRecord.recipient_agent_id == recipient_agent_id,
                ProxyMessageQueueRecord.idempotency_key == idempotency_key,
            )
        )
        canonical = existing.scalar_one()
        return canonical, False


# ─────────────────────────────────────────────────────────────────────
# Dequeue + ack
# ─────────────────────────────────────────────────────────────────────
async def fetch_pending_for_recipient(
    db: AsyncSession,
    recipient_agent_id: str,
    limit: int = 500,
) -> list[QueuedMessage]:
    """Fetch pending messages for ``recipient_agent_id`` ordered by seq.

    Does NOT mutate state — mark_delivered must be called after the
    client ack's. Safe to call from WS reconnect / resume / polling.
    """
    result = await db.execute(
        select(ProxyMessageQueueRecord)
        .where(
            ProxyMessageQueueRecord.recipient_agent_id == recipient_agent_id,
            ProxyMessageQueueRecord.delivery_status == DELIVERY_PENDING,
        )
        .order_by(ProxyMessageQueueRecord.seq)
        .limit(limit)
    )
    out: list[QueuedMessage] = []
    for r in result.scalars().all():
        out.append(QueuedMessage(
            msg_id=r.msg_id,
            session_id=r.session_id,
            recipient_agent_id=r.recipient_agent_id,
            sender_agent_id=r.sender_agent_id,
            ciphertext=bytes(r.ciphertext) if r.ciphertext else b"",
            seq=r.seq,
            enqueued_at=r.enqueued_at.replace(tzinfo=timezone.utc),
            ttl_expires_at=r.ttl_expires_at.replace(tzinfo=timezone.utc),
            attempts=r.attempts,
            idempotency_key=r.idempotency_key,
        ))
    return out


async def mark_delivered(
    db: AsyncSession,
    msg_id: str,
    *,
    recipient_agent_id: Optional[str] = None,
) -> bool:
    """Flip a pending row to delivered (M3.2 ack endpoint).

    Returns True when exactly one pending row was updated. Returns False
    when the row is already delivered/expired/missing — caller can log
    and respond 404/409 as appropriate but must NOT treat the duplicate
    ack as fatal.

    ``recipient_agent_id`` is optional; when provided it scopes the
    update so an attacker who guesses a msg_id cannot ack someone else's
    message (defense in depth on top of the router-level auth check).
    """
    now = datetime.now(timezone.utc)
    conditions = [
        ProxyMessageQueueRecord.msg_id == msg_id,
        ProxyMessageQueueRecord.delivery_status == DELIVERY_PENDING,
    ]
    if recipient_agent_id is not None:
        conditions.append(
            ProxyMessageQueueRecord.recipient_agent_id == recipient_agent_id
        )
    stmt = (
        update(ProxyMessageQueueRecord)
        .where(*conditions)
        .values(delivery_status=DELIVERY_DELIVERED, delivered_at=now)
    )
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount == 1


async def bump_attempts(db: AsyncSession, msg_id: str) -> None:
    """Increment attempts counter after a failed delivery try (M3.6)."""
    stmt = (
        update(ProxyMessageQueueRecord)
        .where(
            ProxyMessageQueueRecord.msg_id == msg_id,
            ProxyMessageQueueRecord.delivery_status == DELIVERY_PENDING,
        )
        .values(attempts=ProxyMessageQueueRecord.attempts + 1)
    )
    await db.execute(stmt)
    await db.commit()


# ─────────────────────────────────────────────────────────────────────
# Sweep (TTL expiry)
# ─────────────────────────────────────────────────────────────────────
async def sweep_expired(
    db: AsyncSession,
    *,
    limit: int = 1000,
) -> list[ExpiredMessageNotice]:
    """Flip pending rows whose ``ttl_expires_at`` has passed to expired.

    Returns the rows transitioned so the sweeper can emit a
    ``message.expired`` event to each original sender (M3.3). Capped by
    ``limit`` so a burst of expirations does not block the sweeper loop.
    """
    now = datetime.now(timezone.utc)

    # Select first so we can return the set of senders/sessions to notify.
    # The subsequent UPDATE is narrow (by msg_id IN …) so concurrent
    # updates to unrelated rows don't contend.
    candidates = await db.execute(
        select(
            ProxyMessageQueueRecord.msg_id,
            ProxyMessageQueueRecord.session_id,
            ProxyMessageQueueRecord.sender_agent_id,
            ProxyMessageQueueRecord.recipient_agent_id,
        )
        .where(
            ProxyMessageQueueRecord.delivery_status == DELIVERY_PENDING,
            ProxyMessageQueueRecord.ttl_expires_at < now,
        )
        .limit(limit)
    )
    notices = [
        ExpiredMessageNotice(
            msg_id=row.msg_id,
            session_id=row.session_id,
            sender_agent_id=row.sender_agent_id,
            recipient_agent_id=row.recipient_agent_id,
        )
        for row in candidates.all()
    ]

    if not notices:
        return []

    ids = [n.msg_id for n in notices]
    await db.execute(
        update(ProxyMessageQueueRecord)
        .where(ProxyMessageQueueRecord.msg_id.in_(ids))
        .values(delivery_status=DELIVERY_EXPIRED, expired_at=now)
    )
    await db.commit()
    _log.info("message_queue: expired %d message(s)", len(notices))
    return notices


async def queue_depth_for_recipient(
    db: AsyncSession,
    recipient_agent_id: str,
) -> int:
    """Number of pending messages for an agent (M3.7 metrics)."""
    from sqlalchemy import func
    result = await db.execute(
        select(func.count()).select_from(ProxyMessageQueueRecord).where(
            ProxyMessageQueueRecord.recipient_agent_id == recipient_agent_id,
            ProxyMessageQueueRecord.delivery_status == DELIVERY_PENDING,
        )
    )
    return int(result.scalar() or 0)
