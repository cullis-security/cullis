"""Hour-of-week baseline roll-up — ADR-013 Phase 4 (detector input).

Daily cron that aggregates the 4-week trailing ``agent_traffic_samples``
into 168 ``agent_hourly_baselines`` buckets per agent (one per
hour-of-week, computed as ``dow * 24 + hour``). The anomaly evaluator
divides the current 5-min rate by ``req_per_min_avg`` for the current
hour-of-week to decide whether the ratio signal fires.

## Why hour-of-week and not a flat mean

Agent traffic is not stationary. An agent used during business hours
has a very different baseline at 2 AM than at 2 PM, and at 2 PM Monday
vs 2 PM Sunday. Comparing a Monday-morning spike against a
Sunday-night baseline would false-positive every Monday. 168 buckets
(7 * 24) captures both diurnal and weekly seasonality; finer grain
(e.g. 15-min buckets) would make each bucket noisier without enough
samples to compute p95 honestly.

## "Mature baseline" gate

Agents with less than 7 days of data are skipped. Their baseline row
stays empty → the evaluator falls back to the absolute-rate signal
alone (§2.2). The cutoff is deliberately on "earliest sample older
than 7 days" rather than "sample count ≥ X": an agent that only runs
during business hours should still hit mature at 7 days even though
it has far fewer than 7 * 24 * 6 possible samples.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

_log = logging.getLogger("mcp_proxy")

_DEFAULT_ROLLUP_WINDOW_DAYS: int = 28
_DEFAULT_MIN_BASELINE_DAYS: int = 7
# 04:00 UTC — design doc §4.4. Runs in a quiet window for most
# customer deployments + leaves time for the morning's detector runs
# to use fresh baselines.
_DEFAULT_ROLLUP_HOUR_UTC: int = 4


def _hour_of_week(iso_ts: str) -> int:
    """``dow * 24 + hour`` for an ISO-8601 UTC timestamp.

    Python's ``weekday()`` returns Monday=0 ... Sunday=6, same as the
    ISO convention. hour 0..23. Range 0..167.
    """
    dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    return dt.weekday() * 24 + dt.hour


def _percentile(sorted_values: list[float], q: float) -> float:
    """Simple linear-interpolation percentile. ``sorted_values`` must
    be pre-sorted ascending. ``q`` in [0, 1]. Returns 0.0 on empty.
    """
    n = len(sorted_values)
    if n == 0:
        return 0.0
    if n == 1:
        return sorted_values[0]
    pos = q * (n - 1)
    lo = int(pos)
    hi = min(lo + 1, n - 1)
    frac = pos - lo
    return sorted_values[lo] + frac * (sorted_values[hi] - sorted_values[lo])


async def _fetch_distinct_agents(engine: "AsyncEngine", since_iso: str) -> list[str]:
    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT DISTINCT agent_id FROM agent_traffic_samples "
                    "WHERE bucket_ts >= :since"
                ),
                {"since": since_iso},
            )
        ).all()
    return [row[0] for row in rows]


async def _fetch_earliest_sample(
    engine: "AsyncEngine", agent_id: str
) -> str | None:
    async with engine.begin() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT MIN(bucket_ts) FROM agent_traffic_samples "
                    "WHERE agent_id = :a"
                ),
                {"a": agent_id},
            )
        ).first()
    return row[0] if row and row[0] else None


async def _fetch_samples(
    engine: "AsyncEngine", agent_id: str, since_iso: str
) -> list[tuple[str, int]]:
    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT bucket_ts, req_count FROM agent_traffic_samples "
                    "WHERE agent_id = :a AND bucket_ts >= :since"
                ),
                {"a": agent_id, "since": since_iso},
            )
        ).all()
    return [(r[0], int(r[1])) for r in rows]


async def _upsert_baseline_rows(
    engine: "AsyncEngine",
    agent_id: str,
    buckets: dict[int, tuple[float, float, int]],
    updated_at: str,
) -> int:
    """UPSERT per hour-of-week bucket. Returns rows written."""
    if not buckets:
        return 0
    stmt = text(
        "INSERT INTO agent_hourly_baselines "
        "(agent_id, hour_of_week, req_per_min_avg, req_per_min_p95, "
        "sample_count, updated_at) "
        "VALUES (:agent_id, :how, :avg, :p95, :n, :updated_at) "
        "ON CONFLICT (agent_id, hour_of_week) DO UPDATE SET "
        "req_per_min_avg = excluded.req_per_min_avg, "
        "req_per_min_p95 = excluded.req_per_min_p95, "
        "sample_count = excluded.sample_count, "
        "updated_at = excluded.updated_at"
    )
    rows = [
        {
            "agent_id": agent_id,
            "how": how,
            "avg": avg,
            "p95": p95,
            "n": n,
            "updated_at": updated_at,
        }
        for how, (avg, p95, n) in buckets.items()
    ]
    async with engine.begin() as conn:
        await conn.execute(stmt, rows)
    return len(rows)


async def run_once(
    engine: "AsyncEngine",
    *,
    now: datetime | None = None,
    window_days: int = _DEFAULT_ROLLUP_WINDOW_DAYS,
    min_baseline_days: int = _DEFAULT_MIN_BASELINE_DAYS,
) -> dict[str, int]:
    """Compute baselines for every agent with mature data.

    Returns a counter dict: ``{"agents_seen", "agents_mature",
    "agents_skipped_immature", "rows_written"}``. Used by tests and
    by the periodic loop's summary log.
    """
    now = now or datetime.now(timezone.utc)
    window_start = now - timedelta(days=window_days)
    since_iso = window_start.isoformat().replace("+00:00", "Z")
    mature_threshold = now - timedelta(days=min_baseline_days)
    updated_at_iso = now.isoformat().replace("+00:00", "Z")

    stats = {
        "agents_seen": 0,
        "agents_mature": 0,
        "agents_skipped_immature": 0,
        "rows_written": 0,
    }

    agents = await _fetch_distinct_agents(engine, since_iso)
    stats["agents_seen"] = len(agents)

    for agent_id in agents:
        earliest = await _fetch_earliest_sample(engine, agent_id)
        if earliest is None:
            stats["agents_skipped_immature"] += 1
            continue
        earliest_dt = datetime.fromisoformat(earliest.replace("Z", "+00:00"))
        if earliest_dt > mature_threshold:
            stats["agents_skipped_immature"] += 1
            continue

        samples = await _fetch_samples(engine, agent_id, since_iso)
        if not samples:
            stats["agents_skipped_immature"] += 1
            continue

        # hour_of_week → list of req_per_min rates for each 10-min sample
        by_bucket: dict[int, list[float]] = {}
        for bucket_ts, req_count in samples:
            how = _hour_of_week(bucket_ts)
            rpm = req_count / 10.0  # 10-min bucket → per-minute rate
            by_bucket.setdefault(how, []).append(rpm)

        summaries: dict[int, tuple[float, float, int]] = {}
        for how, rates in by_bucket.items():
            rates.sort()
            n = len(rates)
            avg = sum(rates) / n
            p95 = _percentile(rates, 0.95)
            summaries[how] = (avg, p95, n)

        written = await _upsert_baseline_rows(
            engine, agent_id, summaries, updated_at_iso
        )
        stats["rows_written"] += written
        stats["agents_mature"] += 1

    return stats


def _seconds_until_next_run(
    now: datetime, rollup_hour_utc: int
) -> float:
    """Seconds from ``now`` to the next ``rollup_hour_utc:00``.

    Never returns 0 or less — if ``now`` is past today's run hour, the
    next run is tomorrow. This keeps the loop's ``asyncio.sleep`` safe
    (negative sleep returns immediately and would tight-loop the
    rollup).
    """
    target = now.replace(
        hour=rollup_hour_utc, minute=0, second=0, microsecond=0
    )
    if target <= now:
        target = target + timedelta(days=1)
    return (target - now).total_seconds()


class BaselineRollupScheduler:
    """Background task that runs ``run_once`` daily at 04:00 UTC.

    Owns the wait/run loop. Stored on ``app.state.baseline_rollup`` by
    the lifespan. ``stop()`` cancels the task cleanly.
    """

    def __init__(
        self,
        engine: "AsyncEngine",
        *,
        rollup_hour_utc: int = _DEFAULT_ROLLUP_HOUR_UTC,
        window_days: int = _DEFAULT_ROLLUP_WINDOW_DAYS,
        min_baseline_days: int = _DEFAULT_MIN_BASELINE_DAYS,
    ) -> None:
        self._engine = engine
        self._rollup_hour_utc = rollup_hour_utc
        self._window_days = window_days
        self._min_baseline_days = min_baseline_days
        self._task: asyncio.Task | None = None
        self._stopped = False
        self.runs_completed: int = 0
        self.last_run_ts: str | None = None
        self.last_run_stats: dict[str, int] | None = None

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stopped = False
        self._task = asyncio.create_task(
            self._loop(), name="baseline-rollup"
        )

    async def stop(self) -> None:
        self._stopped = True
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _loop(self) -> None:
        try:
            while not self._stopped:
                wait_s = _seconds_until_next_run(
                    datetime.now(timezone.utc), self._rollup_hour_utc
                )
                try:
                    await asyncio.sleep(wait_s)
                except asyncio.CancelledError:
                    break
                if self._stopped:
                    break
                await self._run_with_logging()
        except asyncio.CancelledError:
            return

    async def _run_with_logging(self) -> None:
        try:
            stats = await run_once(
                self._engine,
                window_days=self._window_days,
                min_baseline_days=self._min_baseline_days,
            )
            self.runs_completed += 1
            self.last_run_ts = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            self.last_run_stats = stats
            _log.info(
                "baseline rollup complete: %s (ADR-013 Phase 4)", stats
            )
        except Exception:
            _log.exception(
                "baseline rollup failed — will retry at next scheduled run"
            )
