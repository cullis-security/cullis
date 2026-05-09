"""Tests for cullis_connector.identity.lockout — per-IP brute-force defence."""
from __future__ import annotations

import asyncio
import time

import pytest

from cullis_connector.identity import lockout
from cullis_connector.identity.lockout import (
    LOCKOUT_DURATION_SECONDS,
    LOCKOUT_THRESHOLD,
    InMemoryStore,
    get_locked_until,
    is_locked,
    record_failure,
    record_success,
    reset_lockout_for_tests,
)


@pytest.fixture(autouse=True)
def _fresh_default_store():
    """Reset the module-level singleton before and after each test."""
    reset_lockout_for_tests()
    yield
    reset_lockout_for_tests()


# ── Threshold + window ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_locks_after_threshold_failures():
    store = InMemoryStore()
    ip = "10.0.0.5"

    for i in range(LOCKOUT_THRESHOLD - 1):
        count, unlock_at = await record_failure(ip, "mario", store=store)
        assert unlock_at is None
        assert count == i + 1
        assert await is_locked(ip, store=store) is None

    count, unlock_at = await record_failure(ip, "mario", store=store)
    assert count == LOCKOUT_THRESHOLD
    assert unlock_at is not None
    assert unlock_at > time.time()

    locked_until = await is_locked(ip, store=store)
    assert locked_until is not None
    assert locked_until == unlock_at


@pytest.mark.asyncio
async def test_record_success_resets_counter():
    store = InMemoryStore()
    ip = "10.0.0.6"

    for _ in range(LOCKOUT_THRESHOLD - 1):
        await record_failure(ip, "mario", store=store)

    await record_success(ip, store=store)

    # After reset, a single failure should not lock.
    count, unlock_at = await record_failure(ip, "mario", store=store)
    assert count == 1
    assert unlock_at is None


@pytest.mark.asyncio
async def test_expired_lockout_auto_clears(monkeypatch):
    store = InMemoryStore()
    ip = "10.0.0.7"

    fixed_now = [1000.0]

    def _fake_time() -> float:
        return fixed_now[0]

    # Patch time.time inside the module the store uses.
    monkeypatch.setattr("cullis_connector.identity.lockout.time.time", _fake_time)

    for _ in range(LOCKOUT_THRESHOLD):
        await record_failure(ip, "mario", store=store)
    assert await is_locked(ip, store=store) is not None

    # Advance time past the lockout duration → the store should
    # auto-clear and report unlocked.
    fixed_now[0] += LOCKOUT_DURATION_SECONDS + 1
    assert await is_locked(ip, store=store) is None

    # Counter should also be wiped — first new failure starts at 1.
    count, unlock_at = await record_failure(ip, "mario", store=store)
    assert count == 1
    assert unlock_at is None


# ── Concurrency ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_record_failure_is_serialised():
    """10 concurrent failures must produce exactly 10 recorded failures.

    Proves that the asyncio.Lock inside InMemoryStore prevents lost
    updates. Without the lock, two coroutines could both read the same
    initial list and write back two competing extensions — counts under
    10 indicate a race.
    """
    store = InMemoryStore()
    ip = "10.0.0.8"

    results = await asyncio.gather(
        *[record_failure(ip, "mario", store=store) for _ in range(10)]
    )
    counts = [c for c, _ in results]
    # Each call observes a strictly increasing count: {1, 2, ..., 10}.
    assert sorted(counts) == list(range(1, 11))

    # Final state visible to a fresh observer must be 10, and the IP
    # must be locked because we crossed the threshold.
    locked = await is_locked(ip, store=store)
    assert locked is not None


# ── Default store ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_default_store_used_when_none_passed():
    ip = "10.0.0.9"

    for _ in range(LOCKOUT_THRESHOLD):
        await record_failure(ip, "mario")  # no explicit store

    locked = await get_locked_until(ip)
    assert locked is not None


@pytest.mark.asyncio
async def test_distinct_ips_track_independently():
    store = InMemoryStore()

    for _ in range(LOCKOUT_THRESHOLD):
        await record_failure("10.0.0.1", "mario", store=store)

    assert await is_locked("10.0.0.1", store=store) is not None
    # Other IP must remain unlocked.
    assert await is_locked("10.0.0.2", store=store) is None


@pytest.mark.asyncio
async def test_threshold_constants_match_spec():
    # Sanity check: the constants document the operational policy.
    # Changing them is not supposed to be done quietly.
    assert LOCKOUT_THRESHOLD == 5
    assert LOCKOUT_DURATION_SECONDS == 15 * 60
    # Logger name fixed by the maintainer comment block.
    assert lockout._log.name == "cullis_connector.identity.lockout"
