"""Per-agent traffic recorder — ADR-013 Phase 4 (anomaly detector input).

Counts successful inbound requests per ``(agent_id, 10-min-bucket)``
into an in-memory dict and flushes to ``agent_traffic_samples`` every
30 s. The anomaly evaluator (commit 4) reads from the table to compute
rolling 5-min rates and compare them to the hour-of-week baseline.

## Why direct call-from-auth rather than generic middleware

The design doc calls this a "middleware" because it's the natural place
to think about per-request hooks. In practice the useful semantic is
"count requests that successfully authenticated as an agent" — a pure
ASGI middleware sitting outside the auth dep chain cannot know the
agent_id without re-parsing auth headers. Two cleaner options:

1. Call ``record()`` from the auth dep(s) after a successful lookup.
2. Have the auth dep write ``request.state.agent_id`` and have a
   middleware read it post-handler.

Option 1 is what we use here: two call-sites (egress API-key dep +
local-token dep) vs a middleware + state-write contract spread across
every future auth path. Fewer moving parts, explicit at every site.

Requests shed by ADR-013 layers 2 (global bucket) and 6 (DB circuit
breaker) never reach the auth dep, so they never call ``record()`` —
which matches the design-doc requirement that shed traffic does not
count against an agent's baseline.

## Flush contract

- ``record()`` is synchronous, non-blocking, no DB touch. Safe to call
  from hot paths.
- Flush runs on a single background task (one per process) created by
  the lifespan. It swaps the in-memory dict atomically (Python
  reference assignment is a single bytecode, and all mutations happen
  in the single asyncio event loop), then writes the swap-out to DB
  with ``INSERT ... ON CONFLICT (agent_id, bucket_ts) DO UPDATE SET
  req_count = req_count + excluded.req_count``. Both SQLite (>= 3.24)
  and Postgres support the UPSERT with identical syntax.
- Flush losses on crash: a single 30 s window's worth of samples,
  acceptable. The baseline is a 4-week rolling signal; one lost bucket
  per crash is statistical noise, not a correctness issue.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

_log = logging.getLogger("mcp_proxy")

_BUCKET_SECONDS: int = 600  # 10 min


def _bucket_ts_iso(now: datetime | None = None) -> str:
    """Start of the 10-min bucket containing ``now`` as ISO-8601 UTC.

    Buckets align on the wall clock: 00, 10, 20, 30, 40, 50 of every
    hour. Makes hour-of-week roll-up trivial (one bucket fits entirely
    in one hour-of-week) and keeps bucket boundaries stable under
    restarts.
    """
    now = now or datetime.now(timezone.utc)
    aligned = now.replace(
        minute=(now.minute // 10) * 10,
        second=0,
        microsecond=0,
    )
    return aligned.isoformat().replace("+00:00", "Z")


class TrafficRecorder:
    """In-memory per-agent request counter with 30 s DB flush.

    Instantiated once in the lifespan and stored on
    ``app.state.traffic_recorder``. Auth deps call ``record(agent_id)``
    after a successful agent lookup. The flush task is started by
    ``start()`` and cancelled by ``stop()`` on shutdown.
    """

    def __init__(
        self,
        engine: "AsyncEngine",
        *,
        flush_interval_s: float = 30.0,
    ) -> None:
        self._engine = engine
        self._flush_interval_s = float(flush_interval_s)
        # agent_id → bucket_ts → count
        # Protected by _lock: record() may be called from multiple threads
        # (or asyncio tasks running on different thread-pool workers) concurrently.
        # The read-modify-write `agent_buckets[bucket] = get(..., 0) + 1` is NOT
        # atomic under CPython even though individual dict ops are — the GIL can
        # be released between the LOAD and the STORE bytecodes. A threading.Lock
        # costs microseconds and is safe to acquire from both sync and async
        # contexts because we never hold it across an await.
        self._buckets: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()
        self._flush_task: asyncio.Task | None = None
        self._stopped = False
        # Counters exposed via the admin observability endpoint.
        self.flush_count: int = 0
        self.flush_failures: int = 0
        self.rows_written: int = 0

    # ── public API ────────────────────────────────────────────────

    def record(self, agent_id: str) -> None:
        """Bump the counter for ``agent_id`` in the current 10-min
        bucket. Cheap: one dict lookup + one increment. Runs in the
        request's own task so a slow auth dep doesn't block other
        agents' records.

        Thread-safe: the read-modify-write on the bucket counter is
        protected by ``self._lock``. The lock is held for nanoseconds
        (two dict ops) so contention is negligible even under high
        concurrency.
        """
        if not agent_id:
            return
        bucket = _bucket_ts_iso()
        with self._lock:
            agent_buckets = self._buckets.get(agent_id)
            if agent_buckets is None:
                self._buckets[agent_id] = {bucket: 1}
                return
            agent_buckets[bucket] = agent_buckets.get(bucket, 0) + 1

    async def start(self) -> None:
        if self._flush_task is not None:
            return
        self._stopped = False
        self._flush_task = asyncio.create_task(
            self._flush_loop(), name="traffic-recorder-flush"
        )

    async def stop(self) -> None:
        self._stopped = True
        task = self._flush_task
        self._flush_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        # One final synchronous flush so a graceful shutdown doesn't
        # lose the last partial window.
        await self._flush_once()

    async def flush_for_test(self) -> None:
        """Forces a single flush cycle — test helper. Production code
        should never call this; the background task owns flushing.
        """
        await self._flush_once()

    def agents_tracked(self) -> int:
        """Number of distinct agents with at least one pending or
        flushed bucket in this process's lifetime.

        For admin observability we want the stable count including
        agents seen historically, not just the in-memory pending
        set. The pending dict alone would drop to 0 the moment after a
        flush, which would be misleading on the dashboard.
        """
        return len(self._buckets)

    # ── internals ─────────────────────────────────────────────────

    async def _flush_loop(self) -> None:
        try:
            while not self._stopped:
                try:
                    await asyncio.sleep(self._flush_interval_s)
                except asyncio.CancelledError:
                    break
                if self._stopped:
                    break
                await self._flush_once()
        except asyncio.CancelledError:
            return

    async def _flush_once(self) -> None:
        if not self._buckets:
            return
        # Swap under the lock so no in-flight record() writes get lost
        # between the emptiness check and the reference swap.
        with self._lock:
            if not self._buckets:
                return
            pending, self._buckets = self._buckets, {}
        try:
            await self._write_pending(pending)
            self.flush_count += 1
        except Exception as exc:  # defensive: don't kill the flush loop
            self.flush_failures += 1
            _log.warning(
                "traffic recorder flush failed (%s) — %d agent-bucket "
                "pairs dropped, background loop continues",
                exc,
                sum(len(v) for v in pending.values()),
            )

    async def _write_pending(
        self, pending: dict[str, dict[str, int]]
    ) -> None:
        """UPSERT the swapped-out dict into ``agent_traffic_samples``.

        Uses the SQL-99 idiom ``INSERT ... ON CONFLICT ... DO UPDATE SET
        req_count = req_count + excluded.req_count`` which both SQLite
        (>=3.24) and Postgres render identically. Keeps the recorder
        dialect-agnostic — no per-backend branch, same code path in
        tests and production.
        """
        rows = [
            {
                "agent_id": agent_id,
                "bucket_ts": bucket_ts,
                "req_count": count,
            }
            for agent_id, buckets in pending.items()
            for bucket_ts, count in buckets.items()
        ]
        if not rows:
            return
        stmt = text(
            "INSERT INTO agent_traffic_samples "
            "(agent_id, bucket_ts, req_count) "
            "VALUES (:agent_id, :bucket_ts, :req_count) "
            "ON CONFLICT (agent_id, bucket_ts) DO UPDATE SET "
            "req_count = agent_traffic_samples.req_count + excluded.req_count"
        )
        async with self._engine.begin() as conn:
            await conn.execute(stmt, rows)
        self.rows_written += len(rows)


def record_agent_request(request, agent_id: str) -> None:
    """Helper for auth deps: fetch the recorder from app.state and
    call ``record``. No-ops when the recorder isn't wired (tests,
    standalone CLI use). Never raises — auth paths must not fail
    because the anomaly pipeline is down.
    """
    try:
        recorder = getattr(request.app.state, "traffic_recorder", None)
        if recorder is None:
            return
        recorder.record(agent_id)
    except Exception:  # defensive: anomaly pipeline is non-critical
        _log.debug(
            "record_agent_request swallowed exception (agent=%s)",
            agent_id,
            exc_info=True,
        )
