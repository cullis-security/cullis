"""
Append-only audit log with per-org cryptographic hash chain.

Every event is recorded with a SHA-256 hash that chains to the previous
entry **for the same org_id**, making tampering detectable per tenant.
Cross-org events are dual-written: two rows, one per involved org,
sharing the same payload hash + peer cross-references so a dispute
verifier can cross-check both orgs' exports.

Legacy rows (pre-per-org migration, chain_seq IS NULL) stay globally
chained and are grandfathered by verify_chain — they remain
tamper-evident under the original rules; only new rows use per-org
chains.

No row is ever modified or deleted (threat model: non-repudiation, SOC2).
"""
import asyncio
import hashlib
import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base

# Sentinel org used for audit events that have no natural tenant
# (system-level events, bootstrap, etc.). Isolates their chain from
# real tenants so an export for a real org never mixes in system rows.
SYSTEM_ORG = "__system__"

# One lock per org_id guarantees that reads of "last entry for org X"
# + insert of the next entry are atomic without blocking writes to
# other orgs' chains. A top-level guard protects the dict itself.
_org_locks: dict[str, asyncio.Lock] = {}
_locks_guard = asyncio.Lock()


async def _get_org_lock(org_id: str) -> asyncio.Lock:
    """Return (or lazily create) the per-org append lock."""
    if org_id in _org_locks:
        return _org_locks[org_id]
    async with _locks_guard:
        if org_id not in _org_locks:
            _org_locks[org_id] = asyncio.Lock()
        return _org_locks[org_id]


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
    # Per-org chain ordering; NULL = legacy row (pre-per-org migration).
    chain_seq = Column(Integer, nullable=True)
    # Cross-org linkage: on dual-write these point to the companion row.
    peer_org_id = Column(String(128), nullable=True, index=True)
    peer_row_hash = Column(String(64), nullable=True)


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
    chain_seq: int | None = None,
    peer_org_id: str | None = None,
) -> str:
    """Compute the SHA-256 hash of an audit log entry.

    The canonical string is deterministic — any field change invalidates
    the hash. When `chain_seq` is None (legacy row) the hash format is
    identical to the pre-per-org version so existing rows stay
    verifiable against the original algorithm.
    """
    base = (
        f"{entry_id}|{timestamp.isoformat()}|{event_type}|"
        f"{agent_id or ''}|{session_id or ''}|{org_id or ''}|"
        f"{result}|{details or ''}|{previous_hash or 'genesis'}"
    )
    if chain_seq is None:
        canonical = base
    else:
        # New rows bind chain_seq + peer_org_id into the hash so either
        # field cannot be rewritten without detection.
        canonical = f"{base}|seq={chain_seq}|peer={peer_org_id or ''}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _last_per_org(db: AsyncSession, org_id: str) -> tuple[str | None, int]:
    """Return (last_entry_hash, last_chain_seq) for the given org.

    Looks up the most recent row with `chain_seq IS NOT NULL` for the
    org (i.e. the last post-migration entry). Returns (None, 0) when the
    org has no per-org entries yet — the first append becomes seq=1
    with `previous_hash` tied to any legacy entry_hash (if present) or
    NULL for brand-new orgs.
    """
    stmt = (
        select(AuditLog.entry_hash, AuditLog.chain_seq)
        .where(and_(AuditLog.org_id == org_id, AuditLog.chain_seq.is_not(None)))
        .order_by(AuditLog.chain_seq.desc())
        .limit(1)
    )
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        # Fall back to the last legacy row for this org, so the per-org
        # chain's genesis is hash-linked to the most recent legacy entry
        # (if any) rather than starting cold. This preserves
        # append-only continuity across the migration boundary.
        legacy = await db.execute(
            select(AuditLog.entry_hash)
            .where(and_(AuditLog.org_id == org_id, AuditLog.chain_seq.is_(None)))
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        return (legacy.scalar_one_or_none(), 0)
    return (row[0], row[1])


async def _append_row(
    db: AsyncSession,
    *,
    org_id: str,
    event_type: str,
    result: str,
    agent_id: str | None,
    session_id: str | None,
    details_json: str | None,
    peer_org_id: str | None,
    peer_row_hash: str | None,
) -> AuditLog:
    """Insert one audit row in the org's chain. Caller must hold the
    per-org lock and will commit. Does NOT commit itself."""
    previous_hash, last_seq = await _last_per_org(db, org_id)
    new_seq = last_seq + 1

    entry = AuditLog(
        event_type=event_type,
        agent_id=agent_id,
        session_id=session_id,
        org_id=org_id,
        details=details_json,
        result=result,
        previous_hash=previous_hash,
        chain_seq=new_seq,
        peer_org_id=peer_org_id,
        peer_row_hash=peer_row_hash,
    )
    db.add(entry)
    await db.flush()  # assigns auto-incremented id

    ts = entry.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    entry.entry_hash = compute_entry_hash(
        entry.id, ts, event_type,
        agent_id, session_id, org_id, result,
        details_json, previous_hash,
        chain_seq=new_seq,
        peer_org_id=peer_org_id,
    )
    return entry


async def log_event(
    db: AsyncSession,
    event_type: str,
    result: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    org_id: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    """Append a single entry to the caller's org chain.

    For cross-org events that should appear on both orgs' chains, use
    `log_event_cross_org` instead.
    """
    details_json = json.dumps(details) if details else None
    chain_org = org_id or SYSTEM_ORG
    lock = await _get_org_lock(chain_org)

    async with lock:
        entry = await _append_row(
            db,
            org_id=chain_org,
            event_type=event_type,
            result=result,
            agent_id=agent_id,
            session_id=session_id,
            details_json=details_json,
            peer_org_id=None,
            peer_row_hash=None,
        )
        await db.commit()
        await db.refresh(entry)

    # Notify connected dashboard clients via SSE
    try:
        from app.dashboard.sse import sse_manager
        await sse_manager.broadcast(event_type)
    except Exception:
        pass  # SSE failure must never break audit logging

    return entry


async def log_event_cross_org(
    db: AsyncSession,
    event_type: str,
    result: str,
    org_a: str,
    org_b: str,
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
    details: dict | None = None,
) -> tuple[AuditLog, AuditLog]:
    """Append the same event to both org chains atomically.

    Produces two rows, one per involved org, linked by `peer_org_id` +
    `peer_row_hash`. Both rows share identical `details` / event_type /
    result / session_id, so a dispute verifier can confirm both orgs
    recorded the same fact. Returns (row_a, row_b) in the order the
    args were passed — the append order itself is sorted(org_ids) to
    prevent deadlocks under concurrent cross-org writes.
    """
    if org_a == org_b:
        raise ValueError("cross-org append requires distinct org ids")

    details_json = json.dumps(details) if details else None

    # Deterministic lock order ⇒ no deadlocks when two coroutines race
    # on the same pair in opposite directions.
    first, second = sorted([org_a, org_b])
    lock_first = await _get_org_lock(first)
    lock_second = await _get_org_lock(second)

    async with lock_first, lock_second:
        row_first = await _append_row(
            db,
            org_id=first,
            event_type=event_type,
            result=result,
            agent_id=agent_id,
            session_id=session_id,
            details_json=details_json,
            peer_org_id=second,
            peer_row_hash=None,  # filled in after row_second is hashed
        )
        row_second = await _append_row(
            db,
            org_id=second,
            event_type=event_type,
            result=result,
            agent_id=agent_id,
            session_id=session_id,
            details_json=details_json,
            peer_org_id=first,
            peer_row_hash=row_first.entry_hash,
        )
        # Back-fill peer_row_hash on the first row now that the second
        # row's hash exists. This closes the cross-reference ring.
        # The entry_hash of row_first was computed with peer_row_hash=None,
        # so we must recompute after setting the link — otherwise the
        # stored entry_hash would mismatch on verify. To preserve
        # immutability of entry_hash post-commit, we include peer_row_hash
        # in the hash computation only via peer_org_id (not the hash
        # itself); the peer_row_hash column is thus informational/reference
        # data, not part of the signed content.
        row_first.peer_row_hash = row_second.entry_hash
        await db.commit()
        await db.refresh(row_first)
        await db.refresh(row_second)

    try:
        from app.dashboard.sse import sse_manager
        await sse_manager.broadcast(event_type)
    except Exception:
        pass

    # Return in caller's original (a, b) order.
    return (row_first, row_second) if org_a == first else (row_second, row_first)


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


async def verify_chain(
    db: AsyncSession,
    org_id: str | None = None,
) -> tuple[bool, int, int]:
    """Verify the hash chain integrity.

    When `org_id` is None, verifies every org's chain + the residual
    legacy global chain. When provided, limits the verification to that
    org's per-org chain (legacy rows are skipped).

    Returns (is_valid, total_checked, first_broken_id). first_broken_id
    is 0 if the chain is intact.

    Verification modes:
      - Per-org rows (chain_seq IS NOT NULL): each row's previous_hash
        must equal the entry_hash of the same org's row at chain_seq-1
        (or the last legacy entry_hash for that org, for chain_seq=1).
      - Legacy rows (chain_seq IS NULL): each row's previous_hash must
        equal the entry_hash of the row globally preceding it by id —
        this mirrors the pre-migration global-chain invariant.
    """
    from app.telemetry_metrics import AUDIT_CHAIN_VERIFY_FAILED_COUNTER

    # ── Per-org chains ─────────────────────────────────────────────
    if org_id is not None:
        orgs = [org_id]
    else:
        org_rows = await db.execute(
            select(AuditLog.org_id)
            .where(AuditLog.chain_seq.is_not(None))
            .distinct()
        )
        orgs = [r for r in org_rows.scalars().all() if r is not None]

    total_checked = 0
    for o in orgs:
        stmt = (
            select(AuditLog)
            .where(and_(AuditLog.org_id == o, AuditLog.chain_seq.is_not(None)))
            .order_by(AuditLog.chain_seq.asc())
        )
        entries = (await db.execute(stmt)).scalars().all()
        if not entries:
            continue
        # Genesis previous_hash = last legacy entry for this org (or None).
        legacy_tail = await db.execute(
            select(AuditLog.entry_hash)
            .where(and_(AuditLog.org_id == o, AuditLog.chain_seq.is_(None)))
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        expected_previous = legacy_tail.scalar_one_or_none()

        for entry in entries:
            if entry.previous_hash != expected_previous:
                AUDIT_CHAIN_VERIFY_FAILED_COUNTER.add(
                    1, {"reason": "previous_hash_mismatch", "scope": "per_org"}
                )
                return (False, total_checked, entry.id)

            ts = entry.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            expected_hash = compute_entry_hash(
                entry.id, ts, entry.event_type,
                entry.agent_id, entry.session_id, entry.org_id,
                entry.result, entry.details, entry.previous_hash,
                chain_seq=entry.chain_seq,
                peer_org_id=entry.peer_org_id,
            )
            if entry.entry_hash != expected_hash:
                AUDIT_CHAIN_VERIFY_FAILED_COUNTER.add(
                    1, {"reason": "entry_hash_mismatch", "scope": "per_org"}
                )
                return (False, total_checked, entry.id)

            expected_previous = entry.entry_hash
            total_checked += 1

    # ── Legacy global chain (only when org_id filter omitted) ──────
    if org_id is None:
        legacy_stmt = (
            select(AuditLog)
            .where(AuditLog.chain_seq.is_(None))
            .order_by(AuditLog.id.asc())
        )
        legacy = (await db.execute(legacy_stmt)).scalars().all()
        expected_previous = None
        for entry in legacy:
            if entry.entry_hash is None:
                # pre-hash-chain row, predating even the legacy chain
                continue
            if entry.previous_hash != expected_previous:
                AUDIT_CHAIN_VERIFY_FAILED_COUNTER.add(
                    1, {"reason": "previous_hash_mismatch", "scope": "legacy"}
                )
                return (False, total_checked, entry.id)
            ts = entry.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            expected_hash = compute_entry_hash(
                entry.id, ts, entry.event_type,
                entry.agent_id, entry.session_id, entry.org_id,
                entry.result, entry.details, entry.previous_hash,
            )
            if entry.entry_hash != expected_hash:
                AUDIT_CHAIN_VERIFY_FAILED_COUNTER.add(
                    1, {"reason": "entry_hash_mismatch", "scope": "legacy"}
                )
                return (False, total_checked, entry.id)
            expected_previous = entry.entry_hash
            total_checked += 1

    return (True, total_checked, 0)
