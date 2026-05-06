"""Phase A.3 — InMemoryTokenSumLimiter unit tests.

Validates the weighted sliding-window contract: peek returns the sum
of un-evicted weights, consume registers a new weight at the current
timestamp, and expired entries (older than the window) are dropped on
both operations. The Redis backend goes through the same Protocol but
needs a live Redis to test; that lands in Phase A.4 dogfood.
"""
from __future__ import annotations

import time

import pytest

from mcp_proxy.auth.rate_limit import InMemoryTokenSumLimiter


@pytest.mark.asyncio
async def test_peek_empty_returns_zero():
    lim = InMemoryTokenSumLimiter()
    assert await lim.peek("principal:alice:llm_tokens") == 0


@pytest.mark.asyncio
async def test_consume_then_peek_returns_sum():
    lim = InMemoryTokenSumLimiter()
    await lim.consume("k", 100)
    await lim.consume("k", 250)
    await lim.consume("k", 50)
    assert await lim.peek("k") == 400


@pytest.mark.asyncio
async def test_consume_zero_or_negative_is_noop():
    lim = InMemoryTokenSumLimiter()
    await lim.consume("k", 0)
    await lim.consume("k", -5)
    assert await lim.peek("k") == 0


@pytest.mark.asyncio
async def test_keys_are_isolated():
    lim = InMemoryTokenSumLimiter()
    await lim.consume("alice", 100)
    await lim.consume("bob", 200)
    assert await lim.peek("alice") == 100
    assert await lim.peek("bob") == 200
    assert await lim.peek("carol") == 0


@pytest.mark.asyncio
async def test_window_eviction_drops_stale_entries(monkeypatch):
    """Entries older than 60s drop out on the next peek/consume."""
    lim = InMemoryTokenSumLimiter()

    # Pin time.monotonic so we can move forward deterministically.
    fake_now = [1000.0]
    monkeypatch.setattr(
        "mcp_proxy.auth.rate_limit.time.monotonic", lambda: fake_now[0],
    )

    await lim.consume("k", 100)
    assert await lim.peek("k") == 100

    # Advance just inside the window — still counts.
    fake_now[0] += 30.0
    await lim.consume("k", 50)
    assert await lim.peek("k") == 150

    # Advance past the window for the first entry only.
    fake_now[0] += 31.0  # total +61s vs first entry
    assert await lim.peek("k") == 50

    # Advance past everything.
    fake_now[0] += 60.0
    assert await lim.peek("k") == 0
