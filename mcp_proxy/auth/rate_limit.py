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


class TokenSumLimiter(Protocol):
    """Sliding-window sum of weighted entries (e.g. LLM token usage).

    Unlike ``AgentRateLimiter`` which counts requests, this one tracks
    a *quantity* added per request: pre-call ``peek`` reports the
    current sum over the last window so the caller can decide to 429
    before dispatching; post-call ``consume`` records the actual
    weight (prompt + completion tokens) once known. Two concurrent
    requests can each pass ``peek`` without seeing each other's
    pending consumption — this is an MVP trade-off; for stricter
    bounds add a reservation step.
    """

    async def peek(self, key: str) -> int:
        """Return the current sum over the active window."""
        ...

    async def consume(self, key: str, amount: int) -> None:
        """Record ``amount`` against ``key`` at the current timestamp."""
        ...


class InMemoryTokenSumLimiter:
    """Per-process weighted sliding window. Async-safe within one loop."""

    def __init__(self) -> None:
        self._windows: dict[str, list[tuple[float, int]]] = {}
        self._lock = asyncio.Lock()

    async def peek(self, key: str) -> int:
        cutoff = time.monotonic() - _WINDOW_SECONDS
        async with self._lock:
            entries = [(t, w) for t, w in self._windows.get(key, []) if t > cutoff]
            self._windows[key] = entries
            return sum(w for _, w in entries)

    async def consume(self, key: str, amount: int) -> None:
        if amount <= 0:
            return
        now = time.monotonic()
        cutoff = now - _WINDOW_SECONDS
        async with self._lock:
            entries = [(t, w) for t, w in self._windows.get(key, []) if t > cutoff]
            entries.append((now, int(amount)))
            self._windows[key] = entries


class RedisTokenSumLimiter:
    """Redis sorted-set weighted sliding window.

    Each entry is ``"<amount>:<uuid>"`` with score = epoch seconds.
    ``peek`` evicts stale entries then sums the remaining amounts via
    a Lua script (atomic read). ``consume`` ZADDs the new entry. The
    set's TTL is reset on every consume so empty windows expire.
    """

    _PREFIX = "mcp_proxy:tokensum:"
    _PEEK_LUA = """
local key = KEYS[1]
local cutoff = tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
local entries = redis.call('ZRANGE', key, 0, -1)
local total = 0
for _, member in ipairs(entries) do
    local sep = string.find(member, ':')
    if sep then
        total = total + tonumber(string.sub(member, 1, sep - 1))
    end
end
return total
"""

    def __init__(self, redis_client) -> None:
        self._redis = redis_client
        self._peek_sha: str | None = None

    async def peek(self, key: str) -> int:
        cutoff = time.time() - _WINDOW_SECONDS
        full_key = f"{self._PREFIX}{key}"
        if self._peek_sha is None:
            self._peek_sha = await self._redis.script_load(self._PEEK_LUA)
        total = await self._redis.evalsha(
            self._peek_sha, 1, full_key, str(cutoff),
        )
        return int(total or 0)

    async def consume(self, key: str, amount: int) -> None:
        if amount <= 0:
            return
        now = time.time()
        full_key = f"{self._PREFIX}{key}"
        member = f"{int(amount)}:{uuid.uuid4().hex}"
        ttl = int(_WINDOW_SECONDS) + 10
        await self._redis.zadd(full_key, {member: now})
        await self._redis.expire(full_key, ttl)


_limiter: AgentRateLimiter | None = None
_token_sum_limiter: TokenSumLimiter | None = None


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
    global _limiter, _token_sum_limiter
    _limiter = None
    _token_sum_limiter = None


def _init_token_sum_limiter() -> TokenSumLimiter:
    """Pick the best TokenSumLimiter backend, mirroring _init_limiter."""
    from mcp_proxy.redis.pool import get_redis

    redis = get_redis()
    if redis is not None:
        _log.info("Token-sum limiter: Redis")
        return RedisTokenSumLimiter(redis)

    _log.info("Token-sum limiter: in-memory")
    return InMemoryTokenSumLimiter()


def get_token_sum_limiter() -> TokenSumLimiter:
    """Return the active token-sum limiter, initializing on first call."""
    global _token_sum_limiter
    if _token_sum_limiter is None:
        _token_sum_limiter = _init_token_sum_limiter()
    return _token_sum_limiter
