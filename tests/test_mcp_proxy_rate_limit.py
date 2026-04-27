"""Tests for the Mastio (mcp_proxy) per-agent API-key rate limiter — audit F-B-12."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from mcp_proxy.auth import rate_limit as rl_mod
from mcp_proxy.redis import pool as redis_pool

pytestmark = pytest.mark.asyncio


# ── InMemory backend ────────────────────────────────────────────────

async def test_in_memory_allows_under_limit():
    limiter = rl_mod.InMemoryAgentRateLimiter()
    for _ in range(3):
        assert await limiter.check("agent-a", max_per_minute=5) is True


async def test_in_memory_blocks_when_over_limit():
    limiter = rl_mod.InMemoryAgentRateLimiter()
    for _ in range(5):
        assert await limiter.check("agent-a", max_per_minute=5) is True
    # 6th request in the same window: blocked.
    assert await limiter.check("agent-a", max_per_minute=5) is False


async def test_in_memory_separate_agents_have_independent_budgets():
    limiter = rl_mod.InMemoryAgentRateLimiter()
    for _ in range(5):
        assert await limiter.check("agent-a", max_per_minute=5) is True
    # agent-b has its own window.
    assert await limiter.check("agent-b", max_per_minute=5) is True


async def test_in_memory_sliding_window_prunes_old_entries(monkeypatch):
    """Old timestamps outside the 60s window must be evicted so the
    agent regains budget over time."""
    limiter = rl_mod.InMemoryAgentRateLimiter()

    # Seed the window with a stale timestamp in the past.
    stale_time = 0.0
    fresh_time = 120.0  # two minutes later, outside the 60s window.

    monkeypatch.setattr(rl_mod.time, "monotonic", lambda: stale_time)
    for _ in range(5):
        assert await limiter.check("agent-a", max_per_minute=5) is True
    # Budget full at stale_time.
    assert await limiter.check("agent-a", max_per_minute=5) is False

    # Move time forward — all stale entries evicted.
    monkeypatch.setattr(rl_mod.time, "monotonic", lambda: fresh_time)
    assert await limiter.check("agent-a", max_per_minute=5) is True


async def test_in_memory_concurrent_checks_serialized():
    """Two concurrent checks under the limit both succeed, without racing
    on the underlying dict."""
    limiter = rl_mod.InMemoryAgentRateLimiter()

    async def do_check():
        return await limiter.check("race-agent", max_per_minute=10)

    results = await asyncio.gather(*(do_check() for _ in range(10)))
    assert all(results)
    # 11th must be blocked.
    assert await limiter.check("race-agent", max_per_minute=10) is False


# ── Redis backend (via AsyncMock) ───────────────────────────────────

async def test_redis_allowed_returns_true_on_lua_1():
    fake_redis = AsyncMock()
    fake_redis.script_load = AsyncMock(return_value="sha-abc")
    fake_redis.evalsha = AsyncMock(return_value=1)
    limiter = rl_mod.RedisAgentRateLimiter(fake_redis)
    assert await limiter.check("agent-a", max_per_minute=60) is True
    fake_redis.script_load.assert_awaited_once()
    fake_redis.evalsha.assert_awaited_once()


async def test_redis_blocked_returns_false_on_lua_0():
    fake_redis = AsyncMock()
    fake_redis.script_load = AsyncMock(return_value="sha-abc")
    fake_redis.evalsha = AsyncMock(return_value=0)
    limiter = rl_mod.RedisAgentRateLimiter(fake_redis)
    assert await limiter.check("agent-a", max_per_minute=60) is False


async def test_redis_reuses_loaded_lua_sha():
    """script_load runs at most once per RedisAgentRateLimiter instance —
    subsequent checks reuse the SHA via evalsha."""
    fake_redis = AsyncMock()
    fake_redis.script_load = AsyncMock(return_value="sha-abc")
    fake_redis.evalsha = AsyncMock(return_value=1)
    limiter = rl_mod.RedisAgentRateLimiter(fake_redis)
    for _ in range(3):
        await limiter.check("agent-a", max_per_minute=60)
    fake_redis.script_load.assert_awaited_once()
    assert fake_redis.evalsha.await_count == 3


async def test_redis_key_prefix_namespaces_mastio():
    fake_redis = AsyncMock()
    fake_redis.script_load = AsyncMock(return_value="sha-abc")
    fake_redis.evalsha = AsyncMock(return_value=1)
    limiter = rl_mod.RedisAgentRateLimiter(fake_redis)
    await limiter.check("agent-a", max_per_minute=60)
    # args: script_sha, numkeys, key, now, cutoff, max, request_id, ttl
    call_args = fake_redis.evalsha.await_args.args
    key = call_args[2]
    # ADR-014 PR-C: rate-limit key is namespaced ``agent:`` (was
    # ``api_key:``) — the credential is the cert, not the api_key.
    assert key.startswith("mcp_proxy:ratelimit:agent:")
    assert key.endswith("agent-a")


# ── Factory ─────────────────────────────────────────────────────────

async def test_factory_returns_in_memory_when_redis_none(monkeypatch):
    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)
    rl_mod.reset_agent_rate_limiter()
    try:
        limiter = rl_mod._init_limiter()
        assert isinstance(limiter, rl_mod.InMemoryAgentRateLimiter)
    finally:
        rl_mod.reset_agent_rate_limiter()


async def test_factory_returns_redis_when_available(monkeypatch):
    fake_redis = AsyncMock()
    monkeypatch.setattr(redis_pool, "get_redis", lambda: fake_redis)
    rl_mod.reset_agent_rate_limiter()
    try:
        limiter = rl_mod._init_limiter()
        assert isinstance(limiter, rl_mod.RedisAgentRateLimiter)
    finally:
        rl_mod.reset_agent_rate_limiter()


async def test_get_limiter_caches_across_calls(monkeypatch):
    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)
    rl_mod.reset_agent_rate_limiter()
    try:
        first = rl_mod.get_agent_rate_limiter()
        second = rl_mod.get_agent_rate_limiter()
        assert first is second
    finally:
        rl_mod.reset_agent_rate_limiter()
