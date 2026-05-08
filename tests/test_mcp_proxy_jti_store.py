"""Tests for the Mastio (mcp_proxy) DPoP JTI store — audit F-B-12."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from mcp_proxy.auth import dpop_jti_store as jti_mod
from mcp_proxy.redis import pool as redis_pool

pytestmark = pytest.mark.asyncio


# ── InMemory backend ────────────────────────────────────────────────

async def test_in_memory_first_use_allowed():
    store = jti_mod.InMemoryDpopJtiStore()
    assert await store.consume_jti("jti-1") is True


async def test_in_memory_replay_rejected():
    store = jti_mod.InMemoryDpopJtiStore()
    assert await store.consume_jti("jti-1") is True
    assert await store.consume_jti("jti-1") is False


async def test_in_memory_distinct_jtis_coexist():
    store = jti_mod.InMemoryDpopJtiStore()
    assert await store.consume_jti("jti-1") is True
    assert await store.consume_jti("jti-2") is True
    # Neither may be replayed.
    assert await store.consume_jti("jti-1") is False
    assert await store.consume_jti("jti-2") is False


async def test_in_memory_ttl_expiry_allows_reuse():
    store = jti_mod.InMemoryDpopJtiStore()
    assert await store.consume_jti("jti-expiring", ttl_seconds=1) is True
    await asyncio.sleep(1.1)
    # After TTL, the same jti is accepted again (matches broker behavior).
    assert await store.consume_jti("jti-expiring", ttl_seconds=1) is True


async def test_in_memory_concurrent_consume_serialized():
    """Two concurrent consumes of the same jti: only one wins."""
    store = jti_mod.InMemoryDpopJtiStore()

    async def consume():
        return await store.consume_jti("race-jti")

    results = await asyncio.gather(consume(), consume())
    assert sorted(results) == [False, True]


# ── Redis backend (via AsyncMock) ───────────────────────────────────

async def test_redis_first_use_returns_true_on_set_ok():
    fake_redis = AsyncMock()
    fake_redis.set = AsyncMock(return_value=True)
    store = jti_mod.RedisDpopJtiStore(fake_redis)
    assert await store.consume_jti("jti-1") is True
    fake_redis.set.assert_awaited_once()
    # Verify NX + EX usage.
    call = fake_redis.set.await_args
    assert call.kwargs["nx"] is True
    assert call.kwargs["ex"] == jti_mod._DEFAULT_TTL


async def test_redis_replay_returns_false_on_set_none():
    fake_redis = AsyncMock()
    fake_redis.set = AsyncMock(return_value=None)
    store = jti_mod.RedisDpopJtiStore(fake_redis)
    assert await store.consume_jti("jti-replay") is False


async def test_redis_key_prefix_namespaces_mastio():
    """Keys live under 'mcp_proxy:dpop:jti:' so they don't collide with
    the broker's 'dpop:jti:' namespace when both share a Redis instance."""
    fake_redis = AsyncMock()
    fake_redis.set = AsyncMock(return_value=True)
    store = jti_mod.RedisDpopJtiStore(fake_redis)
    await store.consume_jti("jti-x")
    call = fake_redis.set.await_args
    key = call.args[0]
    assert key.startswith("mcp_proxy:dpop:jti:")
    assert key.endswith("jti-x")


# ── Factory: backend selection ──────────────────────────────────────

async def test_factory_returns_in_memory_when_redis_none(monkeypatch):
    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)
    jti_mod.reset_dpop_jti_store()
    try:
        store = jti_mod._init_store()
        assert isinstance(store, jti_mod.InMemoryDpopJtiStore)
    finally:
        jti_mod.reset_dpop_jti_store()


async def test_factory_returns_redis_when_available(monkeypatch):
    fake_redis = AsyncMock()
    monkeypatch.setattr(redis_pool, "get_redis", lambda: fake_redis)
    jti_mod.reset_dpop_jti_store()
    try:
        store = jti_mod._init_store()
        assert isinstance(store, jti_mod.RedisDpopJtiStore)
    finally:
        jti_mod.reset_dpop_jti_store()


async def test_factory_refuses_in_memory_in_production_by_default(monkeypatch):
    """Audit L1-H1 / Ultra U-DD-1 — production + no Redis without explicit
    opt-in must RAISE rather than silently fall back to in-memory. Multi-
    worker HA deploys would otherwise allow cross-worker DPoP replay
    (RFC 9449 violation).
    """
    from mcp_proxy.config import get_settings

    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.delenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", raising=False)
    get_settings.cache_clear()

    jti_mod.reset_dpop_jti_store()
    try:
        with pytest.raises(RuntimeError, match="DPoP JTI store requires Redis"):
            jti_mod._init_store()
    finally:
        get_settings.cache_clear()
        jti_mod.reset_dpop_jti_store()


async def test_factory_allows_in_memory_in_production_with_explicit_optin(monkeypatch):
    """Single-instance / single-worker production deployments that don't
    need Redis can opt out via ``MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES
    =true``. The factory then keeps the legacy in-memory + warning
    behaviour. The broker (Court) raises unconditionally; this opt-in
    preserves the legitimate Mastio single-instance path.

    Intercept ``_log.warning`` directly on the module — pytest's caplog
    misses records because the ``mcp_proxy`` logger is configured with
    ``propagate=False``.
    """
    from mcp_proxy.config import get_settings

    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", "true")
    get_settings.cache_clear()

    warnings: list[str] = []

    def _record(msg, *args, **kwargs):
        warnings.append(str(msg) % args if args else str(msg))

    monkeypatch.setattr(jti_mod._log, "warning", _record)

    jti_mod.reset_dpop_jti_store()
    try:
        store = jti_mod._init_store()
        assert isinstance(store, jti_mod.InMemoryDpopJtiStore)
        assert any("single-instance" in msg for msg in warnings), (
            f"expected single-instance warning, got: {warnings}"
        )
    finally:
        get_settings.cache_clear()
        jti_mod.reset_dpop_jti_store()


async def test_get_store_caches_across_calls(monkeypatch):
    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)
    jti_mod.reset_dpop_jti_store()
    try:
        first = jti_mod.get_dpop_jti_store()
        second = jti_mod.get_dpop_jti_store()
        assert first is second
    finally:
        jti_mod.reset_dpop_jti_store()


async def test_reset_forces_reinitialization(monkeypatch):
    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)
    jti_mod.reset_dpop_jti_store()
    first = jti_mod.get_dpop_jti_store()
    jti_mod.reset_dpop_jti_store()
    second = jti_mod.get_dpop_jti_store()
    assert first is not second
