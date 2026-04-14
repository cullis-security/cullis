"""Broker-side federation event log (ADR-001 Phase 4a).

The broker emits federation events on state changes that a proxy's local
cache must reflect: agent lifecycle, policy updates, binding grants.
Events are append-only, per-org, monotonically sequenced. Proxies
subscribe to an SSE stream and replay from a cursor to catch up after a
disconnect.

Design notes:
  - `seq` is scoped per `org_id`. A proxy cursor is therefore (org_id,
    last_seen_seq). This keeps replays org-isolated: a proxy catching up
    for org A never sees events for org B.
  - Payloads are compact JSON with just enough identity to let the
    proxy re-fetch details via REST when needed. We do NOT embed full
    entities here — the broker remains the source of truth and the
    event is a pointer + minimal changed fields.
  - The table is append-only. We never UPDATE or DELETE federation
    events once persisted. Retention is handled by a future reaper
    outside the hot path (not in scope for 4a).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    func,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


# Event types emitted on the federation stream. Proxies should treat any
# unknown type as a trigger to refresh from REST (defensive).
EVENT_AGENT_REGISTERED = "agent.registered"
EVENT_AGENT_REVOKED = "agent.revoked"
EVENT_AGENT_ROTATED = "agent.rotated"
EVENT_POLICY_UPDATED = "org.policy.updated"
EVENT_POLICY_REMOVED = "org.policy.removed"
EVENT_BINDING_GRANTED = "binding.granted"
EVENT_BINDING_REVOKED = "binding.revoked"


class FederationEvent(Base):
    """Per-org, append-only log of state changes a proxy must mirror.

    `seq` is unique per `org_id` and assigned at publish time under a row
    lock on the previous max(seq) for the org. Readers can replay with
    `WHERE org_id = :o AND seq > :cursor ORDER BY seq ASC`.
    """
    __tablename__ = "federation_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(String(128), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    event_type = Column(String(64), nullable=False)
    payload = Column(Text, nullable=False)  # JSON
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_federation_events_org_seq", "org_id", "seq", unique=True),
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "org_id": self.org_id,
            "event_type": self.event_type,
            "payload": json.loads(self.payload) if self.payload else {},
            "created_at": (
                self.created_at.isoformat() if self.created_at else None
            ),
        }


async def publish_federation_event(
    db: AsyncSession,
    *,
    org_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> FederationEvent:
    """Append a federation event for `org_id` with a freshly assigned
    monotonic seq. Caller controls commit.

    Sequence assignment: we read max(seq) for the org and insert max+1.
    Under concurrent writers this can race; the unique (org_id, seq)
    index prevents duplicate seqs — a concurrent insert fails with an
    IntegrityError and the caller should retry. For 4a the single-writer
    commit pattern (each emit-site commits in its own transaction) plus
    the index is enough; multi-writer serialization is deferred.
    """
    current_max = (
        await db.execute(
            select(func.max(FederationEvent.seq)).where(
                FederationEvent.org_id == org_id
            )
        )
    ).scalar() or 0

    ev = FederationEvent(
        org_id=org_id,
        seq=current_max + 1,
        event_type=event_type,
        payload=json.dumps(payload, separators=(",", ":"), sort_keys=True),
    )
    db.add(ev)
    await db.flush()
    return ev


async def list_events_since(
    db: AsyncSession,
    *,
    org_id: str,
    since_seq: int = 0,
    limit: int = 500,
) -> list[FederationEvent]:
    """Read events for `org_id` with seq > since_seq, ordered ascending.

    `limit` caps a single replay page so the SSE endpoint can flush
    batches incrementally instead of loading an unbounded tail into
    memory on a first-time subscriber.
    """
    rows = (
        await db.execute(
            select(FederationEvent)
            .where(
                FederationEvent.org_id == org_id,
                FederationEvent.seq > since_seq,
            )
            .order_by(FederationEvent.seq.asc())
            .limit(limit)
        )
    ).scalars().all()
    return list(rows)
