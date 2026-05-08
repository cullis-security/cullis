"""TrafficRecorder unit tests — ADR-013 Phase 4 commit 2.

Covers the recording path + flush contract in isolation from the ASGI
stack. Integration with auth deps + app.state wiring is exercised by
the shadow-mode test (commit 8).
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.observability.traffic_recorder import (
    TrafficRecorder,
    _bucket_ts_iso,
)


@pytest.fixture
async def engine(tmp_path):
    db_file = tmp_path / "recorder.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    eng: AsyncEngine = create_async_engine(url, future=True)
    yield eng
    await eng.dispose()
    await dispose_db()


def _now_replace(dt: datetime) -> str:
    return _bucket_ts_iso(dt)


def test_bucket_ts_aligns_on_10_min_boundaries():
    for (src_minute, expected_minute) in [
        (0, 0),
        (9, 0),
        (10, 10),
        (11, 10),
        (29, 20),
        (59, 50),
    ]:
        dt = datetime(2026, 4, 24, 12, src_minute, 30, tzinfo=timezone.utc)
        bucket = _bucket_ts_iso(dt)
        assert f":{expected_minute:02d}:00Z" in bucket, (
            f"expected minute {expected_minute} in bucket {bucket}"
        )


def test_bucket_ts_is_iso8601_with_z_suffix():
    bucket = _bucket_ts_iso(
        datetime(2026, 4, 24, 12, 34, 56, tzinfo=timezone.utc)
    )
    assert bucket == "2026-04-24T12:30:00Z"


@pytest.mark.asyncio
async def test_record_bumps_in_memory_counter(engine):
    r = TrafficRecorder(engine)
    r.record("agent-a")
    r.record("agent-a")
    r.record("agent-b")
    assert r.agents_tracked() == 2
    total = sum(
        c for buckets in r._buckets.values() for c in buckets.values()
    )
    assert total == 3


@pytest.mark.asyncio
async def test_record_ignores_empty_agent_id(engine):
    r = TrafficRecorder(engine)
    r.record("")
    r.record(None)  # type: ignore[arg-type]
    assert r.agents_tracked() == 0


@pytest.mark.asyncio
async def test_flush_writes_rows_and_clears_buffer(engine):
    r = TrafficRecorder(engine)
    r.record("agent-a")
    r.record("agent-a")
    r.record("agent-b")

    await r.flush_for_test()

    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT agent_id, req_count FROM agent_traffic_samples "
                    "ORDER BY agent_id"
                )
            )
        ).all()
    assert [(r[0], r[1]) for r in rows] == [("agent-a", 2), ("agent-b", 1)]

    # Buffer is cleared.
    assert r._buckets == {}
    assert r.flush_count == 1
    assert r.rows_written == 2


@pytest.mark.asyncio
async def test_flush_upserts_accumulate_on_same_bucket(engine):
    r = TrafficRecorder(engine)
    r.record("agent-a")
    await r.flush_for_test()

    # Second flush in the same 10-min bucket — UPSERT must sum.
    r.record("agent-a")
    r.record("agent-a")
    await r.flush_for_test()

    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT req_count FROM agent_traffic_samples "
                    "WHERE agent_id = 'agent-a'"
                )
            )
        ).all()
    assert [r[0] for r in rows] == [3]


@pytest.mark.asyncio
async def test_flush_no_op_on_empty_buffer(engine):
    r = TrafficRecorder(engine)
    await r.flush_for_test()
    # No crash, counters unchanged.
    assert r.flush_count == 0
    assert r.rows_written == 0


@pytest.mark.asyncio
async def test_start_stop_runs_background_flush(engine, monkeypatch):
    # Shrink the interval to make the test fast.
    r = TrafficRecorder(engine, flush_interval_s=0.05)
    await r.start()
    try:
        r.record("agent-a")
        # Wait long enough for at least one flush tick.
        await asyncio.sleep(0.15)
    finally:
        await r.stop()

    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text("SELECT req_count FROM agent_traffic_samples")
            )
        ).all()
    # Exact count may be 1 depending on timing, but must be at least 1.
    assert sum(r[0] for r in rows) >= 1


@pytest.mark.asyncio
async def test_stop_flushes_pending_before_exit(engine):
    r = TrafficRecorder(engine, flush_interval_s=60.0)  # effectively never
    await r.start()
    r.record("agent-a")
    r.record("agent-b")
    # The background loop won't fire for 60s, but stop() must flush
    # the pending buffer before returning.
    await r.stop()

    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT agent_id FROM agent_traffic_samples "
                    "ORDER BY agent_id"
                )
            )
        ).all()
    assert [row[0] for row in rows] == ["agent-a", "agent-b"]


@pytest.mark.asyncio
async def test_flush_failure_does_not_kill_loop(engine, monkeypatch):
    """If the DB write raises, the next flush still runs."""
    r = TrafficRecorder(engine, flush_interval_s=60.0)

    original = r._write_pending
    call_count = {"n": 0}

    async def failing_write(pending):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("simulated DB outage")
        await original(pending)

    monkeypatch.setattr(r, "_write_pending", failing_write)

    r.record("agent-a")
    await r.flush_for_test()
    assert r.flush_failures == 1
    assert r.flush_count == 0

    r.record("agent-a")
    await r.flush_for_test()
    assert r.flush_failures == 1
    assert r.flush_count == 1

    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT req_count FROM agent_traffic_samples "
                    "WHERE agent_id = 'agent-a'"
                )
            )
        ).all()
    # Only the second attempt's record survived — first flush's data
    # was dropped (acceptable per the statistical-loss design note).
    assert [row[0] for row in rows] == [1]


def test_record_agent_request_noops_when_app_state_missing():
    """The helper must never raise even if app.state.traffic_recorder is
    absent — auth paths must not fail because anomaly pipeline is down.
    """
    from mcp_proxy.observability.traffic_recorder import record_agent_request

    class _Request:
        class app:
            class state:
                pass

    # Should be a clean no-op, no exception.
    record_agent_request(_Request(), "agent-a")


def test_record_agent_request_ignores_exceptions():
    from mcp_proxy.observability.traffic_recorder import record_agent_request

    class _ExplodingRecorder:
        def record(self, agent_id):
            raise RuntimeError("boom")

    class _Request:
        class app:
            class state:
                traffic_recorder = _ExplodingRecorder()

    # Exception is swallowed — helper never propagates.
    record_agent_request(_Request(), "agent-a")


# ── regression test: L4-H7 atomic bucket counter ──────────────────────────────


@pytest.mark.asyncio
async def test_record_concurrent_threads_no_lost_increments(engine):
    """Regression for L4-H7: concurrent record() calls must not lose counts.

    Spawns N=100 threads, each calling record() once for the same agent+bucket.
    Under the old code the non-atomic read-modify-write could lose increments
    intermittently (the documented 'traffic_recorder timing flake' CI gotcha).
    Under the fixed code the final count must be exactly N, deterministically.

    Uses ThreadPoolExecutor so the threads are truly concurrent (not asyncio
    tasks, which are cooperative and would not expose the race). Asyncio tasks
    would not exercise the race because they yield only at await points and
    record() has none.
    """
    r = TrafficRecorder(engine)
    N = 100

    with ThreadPoolExecutor(max_workers=N) as pool:
        futures = [pool.submit(r.record, "agent-concurrent") for _ in range(N)]
        for f in futures:
            f.result()  # re-raise any exception from worker threads

    # All N increments must be accounted for in a single bucket.
    total = sum(
        count
        for buckets in r._buckets.values()
        for count in buckets.values()
    )
    assert total == N, (
        f"expected {N} increments, got {total}: lost {N - total} under concurrency"
    )
