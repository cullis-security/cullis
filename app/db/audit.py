"""
Append-only audit log with cryptographic hash chain.

Every event is recorded with a SHA-256 hash that chains to the previous entry,
making any tampering (insert, update, delete, reorder) detectable.

No row is ever modified or deleted (threat model: non-repudiation, SOC2).
"""
import asyncio
import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Text, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base

# Serializes audit log inserts to prevent hash chain bifurcation.
# Two concurrent log_event() calls reading the same previous_hash before
# either commits would fork the chain. This lock ensures sequential access.
_audit_chain_lock = asyncio.Lock()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(128), nullable=True, index=True)
    session_id = Column(String(128), nullable=True, index=True)
    org_id = Column(String(128), nullable=True, index=True)
    details = Column(Text, nullable=True)   # serialized JSON
    result = Column(String(16), nullable=False)  # "ok" | "denied" | "error"
    entry_hash = Column(String(64), nullable=True, index=True)
    previous_hash = Column(String(64), nullable=True)


def compute_entry_hash(
    entry_id: int,
    timestamp: datetime,
    event_type: str,
    agent_id: str | None,
    session_id: str | None,
    org_id: str | None,
    result: str,
    details: str | None,
    previous_hash: str | None,
) -> str:
    """Compute the SHA-256 hash of an audit log entry.

    The canonical string is deterministic — any field change invalidates the hash.
    """
    canonical = (
        f"{entry_id}|{timestamp.isoformat()}|{event_type}|"
        f"{agent_id or ''}|{session_id or ''}|{org_id or ''}|"
        f"{result}|{details or ''}|{previous_hash or 'genesis'}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def log_event(
    db: AsyncSession,
    event_type: str,
    result: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    org_id: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    details_json = json.dumps(details) if details else None

    # Serialize chain access: read previous_hash + insert + commit must be
    # atomic to prevent two coroutines forking the hash chain.
    async with _audit_chain_lock:
        last = await db.execute(
            select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)
        )
        previous_hash = last.scalar_one_or_none()

        entry = AuditLog(
            event_type=event_type,
            agent_id=agent_id,
            session_id=session_id,
            org_id=org_id,
            details=details_json,
            result=result,
            previous_hash=previous_hash,
        )
        db.add(entry)
        await db.flush()  # assigns auto-incremented id

        # Normalize timestamp for hash computation — SQLite may strip tzinfo on refresh
        ts = entry.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        entry.entry_hash = compute_entry_hash(
            entry.id, ts, event_type,
            agent_id, session_id, org_id, result,
            details_json, previous_hash,
        )
        await db.commit()

    await db.refresh(entry)
    return entry


async def query_audit_logs(
    db: AsyncSession,
    start: datetime | None = None,
    end: datetime | None = None,
    org_id: str | None = None,
    event_type: str | None = None,
    limit: int = 10000,
) -> list[AuditLog]:
    """Query audit log entries with optional filters."""
    query = select(AuditLog)
    if start:
        query = query.where(AuditLog.timestamp >= start)
    if end:
        query = query.where(AuditLog.timestamp <= end)
    if org_id:
        query = query.where(AuditLog.org_id == org_id)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    query = query.order_by(AuditLog.id.asc()).limit(min(limit, 50000))
    result = await db.execute(query)
    return list(result.scalars().all())


async def verify_chain(db: AsyncSession) -> tuple[bool, int, int]:
    """Walk the audit log and verify every hash in the chain.

    Returns (is_valid, total_checked, first_broken_id).
    first_broken_id is 0 if the chain is intact.
    """
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.id.asc())
    )
    entries = result.scalars().all()

    if not entries:
        return (True, 0, 0)

    expected_previous: str | None = None
    for i, entry in enumerate(entries):
        # Skip entries without hashes (pre-migration)
        if entry.entry_hash is None:
            continue

        if entry.previous_hash != expected_previous:
            return (False, i, entry.id)

        ts = entry.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        expected_hash = compute_entry_hash(
            entry.id, ts, entry.event_type,
            entry.agent_id, entry.session_id, entry.org_id,
            entry.result, entry.details, entry.previous_hash,
        )
        if entry.entry_hash != expected_hash:
            return (False, i, entry.id)

        expected_previous = entry.entry_hash

    return (True, len(entries), 0)
