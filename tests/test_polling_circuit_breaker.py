"""Circuit breaker state machine (ADR-032 F6)."""
from __future__ import annotations

import asyncio

import pytest

from mcp_proxy.mdm.circuit_breaker import (
    STATE_CLOSED,
    STATE_HALF_OPEN,
    STATE_OPEN,
    CircuitBreaker,
    CircuitBreakerConfig,
    sleep_until_cooldown_done,
)


def test_breaker_starts_closed():
    b = CircuitBreaker(mdm="intune")
    assert b.state == STATE_CLOSED
    assert b.should_poll() is True


def test_failures_below_threshold_keep_circuit_closed():
    b = CircuitBreaker(
        mdm="intune", config=CircuitBreakerConfig(failure_threshold=5),
    )
    for _ in range(4):
        opened = b.record_failure()
        assert opened is False
    assert b.state == STATE_CLOSED
    assert b.should_poll() is True


def test_threshold_failure_opens_circuit_and_returns_edge():
    b = CircuitBreaker(
        mdm="intune",
        config=CircuitBreakerConfig(failure_threshold=3, cooldown_seconds=60),
    )
    b.record_failure()
    b.record_failure()
    opened = b.record_failure()
    assert opened is True
    assert b.state == STATE_OPEN
    # While cooldown remains, should_poll is False.
    assert b.should_poll() is False


def test_subsequent_failures_after_open_do_not_re_edge():
    b = CircuitBreaker(
        mdm="intune", config=CircuitBreakerConfig(failure_threshold=2),
    )
    b.record_failure()
    edge1 = b.record_failure()
    edge2 = b.record_failure()
    assert edge1 is True
    assert edge2 is False  # already open
    assert b.state == STATE_OPEN


def test_success_in_closed_resets_counter():
    b = CircuitBreaker(
        mdm="intune", config=CircuitBreakerConfig(failure_threshold=5),
    )
    for _ in range(3):
        b.record_failure()
    assert b.consecutive_failures == 3
    b.record_success()
    assert b.consecutive_failures == 0
    assert b.state == STATE_CLOSED


def test_should_poll_flips_open_to_half_open_after_cooldown(monkeypatch):
    b = CircuitBreaker(
        mdm="intune",
        config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=10),
    )
    b.record_failure()
    assert b.state == STATE_OPEN

    # Fast-forward monotonic clock past cooldown.
    real_mono = b.opened_at_monotonic
    monkeypatch.setattr(
        "mcp_proxy.mdm.circuit_breaker.time.monotonic",
        lambda: real_mono + 11,
    )
    assert b.should_poll() is True
    assert b.state == STATE_HALF_OPEN


def test_half_open_success_closes_circuit():
    b = CircuitBreaker(
        mdm="intune", config=CircuitBreakerConfig(failure_threshold=1),
    )
    b.record_failure()
    b.state = STATE_HALF_OPEN  # simulate post-cooldown probe
    b.record_success()
    assert b.state == STATE_CLOSED
    assert b.consecutive_failures == 0


def test_half_open_failure_returns_to_open_without_new_edge():
    b = CircuitBreaker(
        mdm="intune", config=CircuitBreakerConfig(failure_threshold=1),
    )
    b.record_failure()  # CLOSED -> OPEN
    b.state = STATE_HALF_OPEN
    edge = b.record_failure()
    assert edge is False
    assert b.state == STATE_OPEN


@pytest.mark.asyncio
async def test_sleep_until_cooldown_done_returns_immediately_when_closed():
    b = CircuitBreaker(mdm="intune")
    stop = asyncio.Event()
    # Closed has no cooldown — should return immediately.
    await asyncio.wait_for(sleep_until_cooldown_done(b, stop), timeout=0.5)


@pytest.mark.asyncio
async def test_sleep_until_cooldown_done_honours_stop_event(monkeypatch):
    b = CircuitBreaker(
        mdm="intune",
        config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=60),
    )
    b.record_failure()
    stop = asyncio.Event()

    async def fire_stop():
        await asyncio.sleep(0.05)
        stop.set()

    asyncio.create_task(fire_stop())
    await asyncio.wait_for(sleep_until_cooldown_done(b, stop), timeout=1.0)
