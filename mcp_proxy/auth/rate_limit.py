"""
Per-agent sliding-window rate limiter for the egress client-cert / DPoP path.

Two backends, chosen on first use based on Redis availability:
  - InMemoryAgentRateLimiter — single-worker only, counters reset on restart.
  - RedisAgentRateLimiter    — multi-worker safe, atomic Lua sliding window
    over a Redis sorted set.

The proxy's current rate-limit surface is narrow: one bucket per agent_id
(``settings.rate_limit_per_minute``), enforced on
``get_agent_from_client_cert`` (ADR-014). This module keeps that shape; the
broker's richer multi-bucket limiter (``app/rate_limit/limiter.py``) can be
ported if more buckets appear.

Mastio default (single-instance intra-org) runs with the in-memory backend.
Deploying with multiple workers without Redis silently multiplies the
advertised rate budget by N — ``validate_config`` now refuses that in
production by requiring ``MCP_PROXY_REDIS_URL`` (audit F-B-12).
"""
import asyncio
import logging
import time
import uuid
from typing import Protocol

_log = logging.getLogger("mcp_proxy")

_WINDOW_SECONDS = 60.0


class AgentRateLimiter(Protocol):
    """Interface for per-agent sliding-window rate limiters."""

    async def check(self, agent_id: str, max_per_minute: int) -> bool:
        """Return True if the request is within budget, False if over the limit."""
        ...


class InMemoryAgentRateLimiter:
    """Per-process sliding window limiter. Async-safe within one event loop."""

    def __init__(self) -> None:
        self._windows: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, agent_id: str, max_per_minute: int) -> bool:
        now = time.monotonic()
        cutoff = now - _WINDOW_SECONDS

        async with self._lock:
            timestamps = [t for t in self._windows.get(agent_id, []) if t > cutoff]
            if len(timestamps) >= max_per_minute:
                self._windows[agent_id] = timestamps
                return False
            timestamps.append(now)
            self._windows[agent_id] = timestamps
            return True


class RedisAgentRateLimiter:
    """Redis sorted-set sliding window limiter.

    Atomic via Lua: ZREMRANGEBYSCORE (evict stale) + ZCARD (count) + ZADD
    (register) + EXPIRE, all in one script. The TOCTOU race between count
    and register is closed server-side.
    """

    _PREFIX = "mcp_proxy:ratelimit:agent:"
    _LUA_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local request_id = ARGV[4]
local ttl = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
local count = redis.call('ZCARD', key)
if count >= max_requests then
    return 0
end
redis.call('ZADD', key, now, request_id)
redis.call('EXPIRE', key, ttl)
return 1
"""

    def __init__(self, redis_client) -> None:
        self._redis = redis_client
        self._lua_sha: str | None = None

    async def check(self, agent_id: str, max_per_minute: int) -> bool:
        now = time.time()
        cutoff = now - _WINDOW_SECONDS
        key = f"{self._PREFIX}{agent_id}"
        request_id = uuid.uuid4().hex
        ttl = int(_WINDOW_SECONDS) + 10

        if self._lua_sha is None:
            self._lua_sha = await self._redis.script_load(self._LUA_SCRIPT)

        allowed = await self._redis.evalsha(
            self._lua_sha, 1, key,
            str(now), str(cutoff), str(max_per_minute), request_id, str(ttl),
        )
        return bool(allowed)


_limiter: AgentRateLimiter | None = None


def _init_limiter() -> AgentRateLimiter:
    """Select the best available backend.

    Unlike the JTI store we do not refuse in-memory in production: a
    silent rate-limit bypass degrades DoS protection, not authentication.
    ``validate_config`` already blocks prod startup when
    ``MCP_PROXY_REDIS_URL`` is empty, so production with Redis
    temporarily unreachable falls back to per-worker in-memory windows —
    degraded ceiling but the system keeps serving. Log the condition
    loudly so operators see it in alerts.
    """
    from mcp_proxy.redis.pool import get_redis

    redis = get_redis()
    if redis is not None:
        _log.info("Agent API-key rate limiter: Redis")
        return RedisAgentRateLimiter(redis)

    _log.info("Agent API-key rate limiter: in-memory")
    return InMemoryAgentRateLimiter()


def get_agent_rate_limiter() -> AgentRateLimiter:
    """Return the active rate limiter, initializing on first call."""
    global _limiter
    if _limiter is None:
        _limiter = _init_limiter()
    return _limiter


def reset_agent_rate_limiter() -> None:
    """Reset the limiter (used by tests to force re-initialization)."""
    global _limiter
    _limiter = None
