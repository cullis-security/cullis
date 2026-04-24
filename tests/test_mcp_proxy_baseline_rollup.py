"""Baseline roll-up unit tests — ADR-013 Phase 4 commit 3.

Directly exercises the hour-of-week grouping, the maturity gate, and
the UPSERT semantics. The daily scheduler loop is covered by a
separate ``_seconds_until_next_run`` unit test.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.observability.baseline_rollup import (
    _hour_of_week,
    _percentile,
    _seconds_until_next_run,
    run_once,
)


@pytest.fixture
async def engine(tmp_path):
    db_file = tmp_path / "baseline.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    eng: AsyncEngine = create_async_engine(url, future=True)
    yield eng
    await eng.dispose()
    await dispose_db()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def _insert_sample(
    engine: AsyncEngine, agent_id: str, bucket_ts: str, count: int
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_traffic_samples "
                "(agent_id, bucket_ts, req_count) VALUES (:a, :b, :c)"
            ),
            {"a": agent_id, "b": bucket_ts, "c": count},
        )


def test_hour_of_week_monday_midnight_is_zero():
    # 2026-04-20 was a Monday.
    assert _hour_of_week("2026-04-20T00:00:00Z") == 0


def test_hour_of_week_sunday_last_hour_is_167():
    # 2026-04-26 is the following Sunday.
    assert _hour_of_week("2026-04-26T23:00:00Z") == 167


def test_hour_of_week_various():
    # 2026-04-22 is Wednesday (dow=2); 14:30 UTC → 2*24 + 14 = 62.
    assert _hour_of_week("2026-04-22T14:30:00Z") == 62


def test_percentile_edges():
    assert _percentile([], 0.95) == 0.0
    assert _percentile([1.0], 0.95) == 1.0
    # Linear interpolation at q=0.5 over [1,2,3,4] = 2.5.
    assert _percentile([1.0, 2.0, 3.0, 4.0], 0.5) == pytest.approx(2.5)


def test_seconds_until_next_run_before_hour():
    now = datetime(2026, 4, 24, 2, 0, 0, tzinfo=timezone.utc)
    # 04:00 UTC → 2h away = 7200 s.
    assert _seconds_until_next_run(now, 4) == pytest.approx(7200.0)


def test_seconds_until_next_run_after_hour_rolls_to_tomorrow():
    now = datetime(2026, 4, 24, 5, 0, 0, tzinfo=timezone.utc)
    # Past 04:00 today → next run is 04:00 tomorrow → 23h = 82800 s.
    assert _seconds_until_next_run(now, 4) == pytest.approx(82800.0)


def test_seconds_until_next_run_at_exact_hour_rolls_to_tomorrow():
    # Exact-hour match must advance to the next day so the loop does
    # not double-fire back-to-back.
    now = datetime(2026, 4, 24, 4, 0, 0, tzinfo=timezone.utc)
    assert _seconds_until_next_run(now, 4) == pytest.approx(86400.0)


@pytest.mark.asyncio
async def test_run_once_skips_agent_below_min_baseline_days(engine):
    # Only 3 days of data → below the default 7-day threshold.
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    for day in range(3):
        ts = now - timedelta(days=day, hours=1)
        await _insert_sample(
            engine, "immature", _iso(ts), 10
        )

    stats = await run_once(engine, now=now)
    assert stats["agents_seen"] == 1
    assert stats["agents_mature"] == 0
    assert stats["agents_skipped_immature"] == 1
    assert stats["rows_written"] == 0

    async with engine.begin() as conn:
        count = (
            await conn.execute(
                text("SELECT COUNT(*) FROM agent_hourly_baselines")
            )
        ).scalar()
    assert count == 0


@pytest.mark.asyncio
async def test_run_once_writes_baseline_for_mature_agent(engine):
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    # 10 days of data → mature. Put 6 samples per day in hour 2
    # (02:00..02:50 UTC). Each day maps to a different hour_of_week
    # (Mon=2, Tue=26, ..., Sun=146), wrapping back to Mon=2 on day 7.
    # → hour_of_week=2 gets samples from day 0 and day 7 (2 Mondays) ×
    #   6 samples = 12 samples; other days of the week get 6 each.
    base = datetime(2026, 4, 13, 2, 0, 0, tzinfo=timezone.utc)  # a Monday
    for day_offset in range(10):
        for minute in (0, 10, 20, 30, 40, 50):
            ts = base + timedelta(days=day_offset, minutes=minute)
            if ts > now:
                continue
            await _insert_sample(
                engine, "mature", _iso(ts), 100  # 100 req in 10 min → 10 req/min
            )

    stats = await run_once(engine, now=now)
    assert stats["agents_mature"] == 1
    assert stats["rows_written"] >= 7  # at least 7 distinct hour_of_week buckets

    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT hour_of_week, req_per_min_avg, sample_count "
                    "FROM agent_hourly_baselines WHERE agent_id = 'mature' "
                    "ORDER BY hour_of_week"
                )
            )
        ).all()
    houred = {r[0]: (r[1], r[2]) for r in rows}
    # hour_of_week=2 (Monday 02:00) appears twice in the 10-day window
    # (Mon Apr 13 + Mon Apr 20) × 6 samples/day = 12.
    assert 2 in houred
    avg, n = houred[2]
    assert n == 12
    assert avg == pytest.approx(10.0)  # 100 req / 10 min = 10 req/min
    # Sanity: total samples across all buckets = 10 days × 6 samples = 60.
    total_samples = sum(n for _, n in houred.values())
    assert total_samples == 60


@pytest.mark.asyncio
async def test_run_once_upsert_replaces_baseline(engine):
    """Second roll-up with different data must overwrite the first."""
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    # Four Mondays at 02:00 UTC — all in the same hour_of_week bucket
    # (hour_of_week=2). Count=100 → 10 req/min. Use a wider window so
    # the first Monday (March 30) stays in scope for both passes.
    mondays = [
        datetime(2026, 3, 30, 2, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 4, 6, 2, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 4, 13, 2, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 4, 20, 2, 0, 0, tzinfo=timezone.utc),
    ]
    for mon in mondays:
        await _insert_sample(engine, "a", _iso(mon), 100)
    await run_once(engine, now=now, window_days=60)

    async with engine.begin() as conn:
        row1 = (
            await conn.execute(
                text(
                    "SELECT sample_count, req_per_min_avg "
                    "FROM agent_hourly_baselines "
                    "WHERE agent_id = 'a' AND hour_of_week = 2"
                )
            )
        ).first()
    assert row1 == (4, pytest.approx(10.0))

    # Add a Monday at 02:00 with a much higher rate.
    new_monday = datetime(2026, 4, 20, 2, 10, 0, tzinfo=timezone.utc)
    await _insert_sample(engine, "a", _iso(new_monday), 1000)  # 100 req/min

    await run_once(engine, now=now, window_days=60)

    async with engine.begin() as conn:
        row2 = (
            await conn.execute(
                text(
                    "SELECT sample_count, req_per_min_avg "
                    "FROM agent_hourly_baselines "
                    "WHERE agent_id = 'a' AND hour_of_week = 2"
                )
            )
        ).first()
    assert row2 is not None
    sample_count, avg = row2
    # 5 samples: 4×10 + 1×100 = 140 → avg 28.
    assert sample_count == 5
    assert avg == pytest.approx(28.0)


@pytest.mark.asyncio
async def test_run_once_filters_samples_older_than_window(engine):
    """Samples older than window_days are ignored (bounded roll-up).

    But the earliest-sample check still sees them — the agent is mature
    even if only the in-window samples are used for the baseline.
    """
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    # An ancient sample 60 days old — outside the 28-day window.
    ancient = now - timedelta(days=60)
    # And one recent sample inside the window but only 2 days ago (so
    # the earliest bucket_ts query returns 60d → agent looks mature).
    recent = now - timedelta(days=2)

    await _insert_sample(engine, "a", _iso(ancient), 500)
    await _insert_sample(engine, "a", _iso(recent), 50)

    stats = await run_once(engine, now=now, window_days=28)
    # Only the recent sample goes into the rollup. The ancient one is
    # filtered out by the window bound.
    assert stats["agents_mature"] == 1

    async with engine.begin() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT sample_count FROM agent_hourly_baselines "
                    "WHERE agent_id = 'a'"
                )
            )
        ).all()
    # Exactly 1 bucket, with sample_count = 1.
    assert [r[0] for r in rows] == [1]


@pytest.mark.asyncio
async def test_run_once_handles_zero_agents(engine):
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    stats = await run_once(engine, now=now)
    assert stats == {
        "agents_seen": 0,
        "agents_mature": 0,
        "agents_skipped_immature": 0,
        "rows_written": 0,
    }
