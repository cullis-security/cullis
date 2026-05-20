"""Background worker: periodically TSA-anchor each per-org chain head.

Runs as an asyncio task launched from the FastAPI lifespan. Every
`audit_tsa_interval_seconds`, for each org whose chain has advanced
since the last anchor, request a timestamp on the current chain head
and persist an `AuditTsaAnchor` row.

Design notes:
  - The worker NEVER writes to audit_log; it only reads and writes
    anchor rows. This keeps the chain append-only path free of worker
    latency.
  - TSA failures are logged but do not block the loop — the next tick
    retries. A TSA outage should not stop audit logging.
  - Per-org parallelism: anchors are issued sequentially per tick (a
    typical deployment has few orgs); a busy broker with 100+ orgs
    would benefit from asyncio.gather, defer that optimization.
  - The first anchor for an org uses the genesis row_hash; subsequent
    anchors cover all rows between the previous anchor and the current
    head (the TSA token + chain linkage prove inclusion of every row
    in between).
"""
from __future__ import annotations

import asyncio
import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.tsa_client import TimestampedAnchor, TsaClient, get_tsa_client
from app.db.audit import AuditLog, AuditTsaAnchor
from app.db.database import AsyncSessionLocal

_log = logging.getLogger("audit.tsa.worker")


async def _orgs_with_new_entries(db: AsyncSession) -> list[tuple[str, int, str]]:
    """Return [(org_id, latest_chain_seq, latest_row_hash)] for orgs
    whose chain advanced beyond the last anchor (or has no anchor yet).

    Implementation: compute the current max(chain_seq) per org, compare
    to the corresponding max(chain_seq) in anchors. Uses two round-trips
    instead of a single subquery so the SQL stays readable and the
    driver-specific dialects (sqlite in tests, postgres in prod) behave
    the same.
    """
    # Current per-org heads with their row_hash.
    # SQLite's MAX-aggregation with correlated subquery is fragile, so
    # we pull the minimal set and resolve in Python.
    head_rows = (await db.execute(
        select(AuditLog.org_id, AuditLog.chain_seq, AuditLog.entry_hash)
        .where(AuditLog.chain_seq.is_not(None))
    )).all()
    heads: dict[str, tuple[int, str]] = {}
    for org_id, seq, entry_hash in head_rows:
        if org_id is None:
            continue
        current = heads.get(org_id)
        if current is None or seq > current[0]:
            heads[org_id] = (seq, entry_hash)

    # Latest anchor seq per org.
    anchor_rows = (await db.execute(
        select(AuditTsaAnchor.org_id, AuditTsaAnchor.chain_seq)
    )).all()
    anchors: dict[str, int] = {}
    for org_id, seq in anchor_rows:
        current = anchors.get(org_id, 0)
        if seq > current:
            anchors[org_id] = seq

    out: list[tuple[str, int, str]] = []
    for org_id, (seq, entry_hash) in heads.items():
        if seq > anchors.get(org_id, 0):
            out.append((org_id, seq, entry_hash))
    return out


async def _persist_anchor(
    db: AsyncSession,
    *,
    org_id: str,
    chain_seq: int,
    row_hash: str,
    ts: TimestampedAnchor,
) -> AuditTsaAnchor:
    record = AuditTsaAnchor(
        org_id=org_id,
        chain_seq=chain_seq,
        row_hash=row_hash,
        tsa_token=ts.token,
        tsa_url=ts.tsa_url,
        # Audit F-A-405 — persist the TSA signing cert chain so an
        # offline dispute verifier can walk the chain to a trusted
        # root. ``None`` for the mock backend.
        tsa_cert_chain=ts.cert_chain_pem,
        created_at=ts.created_at,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def anchor_all_orgs_once(
    client: TsaClient,
    *,
    session_factory=AsyncSessionLocal,
) -> int:
    """One tick: anchor every org that has advanced. Returns count of
    anchors created. Exposed as a module function so tests can invoke
    the lifecycle without waiting on the interval sleep."""
    created = 0
    async with session_factory() as db:
        pending = await _orgs_with_new_entries(db)

    for org_id, seq, row_hash in pending:
        try:
            ts = await client.timestamp(row_hash)
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "TSA timestamp failed for org=%s seq=%d: %s", org_id, seq, exc
            )
            continue
        try:
            async with session_factory() as db:
                await _persist_anchor(
                    db, org_id=org_id, chain_seq=seq, row_hash=row_hash, ts=ts,
                )
            created += 1
        except Exception as exc:  # noqa: BLE001
            _log.exception(
                "persist anchor failed for org=%s seq=%d: %s", org_id, seq, exc
            )
    return created


async def run_forever(
    client: TsaClient,
    *,
    interval_seconds: int,
    session_factory=AsyncSessionLocal,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Main loop. `stop_event` lets the lifespan cancel cleanly."""
    _log.info(
        "audit TSA worker started (tsa_url=%s, interval=%ds)",
        getattr(client, "url", "?"), interval_seconds,
    )
    while stop_event is None or not stop_event.is_set():
        try:
            created = await anchor_all_orgs_once(client, session_factory=session_factory)
            if created:
                _log.info("audit TSA: anchored %d org chain head(s)", created)
        except Exception:  # noqa: BLE001
            _log.exception("audit TSA worker tick failed; continuing")
        # Sleep but remain cancellable.
        if stop_event is None:
            await asyncio.sleep(interval_seconds)
        else:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
            except asyncio.TimeoutError:
                pass
    _log.info("audit TSA worker stopped")


def start_worker_task(settings) -> tuple[asyncio.Task, asyncio.Event]:
    """Create the worker task + stop event. The caller (lifespan) keeps
    a reference and triggers stop on shutdown."""
    client = get_tsa_client(settings)
    stop = asyncio.Event()
    task = asyncio.create_task(
        run_forever(
            client,
            interval_seconds=getattr(settings, "audit_tsa_interval_seconds", 3600),
            stop_event=stop,
        ),
        name="audit-tsa-worker",
    )
    return task, stop


