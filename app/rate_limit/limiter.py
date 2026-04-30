"""
Sliding window rate limiter — dual backend (in-memory / Redis).

In-memory: single-process, counters reset on restart.
Redis: multi-worker safe, sorted sets with automatic TTL cleanup.

The active backend is selected at first use based on Redis availability.
"""
import asyncio
import logging
import time
import uuid
from collections import defaultdict, deque

from fastapi import HTTPException, status
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.telemetry_metrics import RATE_LIMIT_REJECT_COUNTER

_log = logging.getLogger("agent_trust")


_MAX_SUBJECTS = 50_000  # maximum unique subjects in memory — LRU eviction

# Transient Redis failures that should trigger fail-open behaviour (audit F-D-2).
# Rate limiting is a best-effort DoS control, not an auth gate — blocking
# requests when Redis is unreachable creates a bigger outage than allowing
# unlimited requests briefly. asyncio.TimeoutError is included because
# redis.asyncio raises it on socket-level timeouts in some code paths.
_REDIS_TRANSIENT_ERRORS = (
    RedisConnectionError,
    RedisTimeoutError,
    asyncio.TimeoutError,
    OSError,
)


class SlidingWindowLimiter:
    """
    Async sliding window rate limiter with dual backend.

    Bucket configs are registered at module load (below).
    On first check(), the backend is selected based on Redis availability.
    """

    def __init__(self) -> None:
        self._configs: dict[str, tuple[int, int]] = {}
        # In-memory backend
        self._windows: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = asyncio.Lock()
        # Backend selection
        self._use_redis: bool | None = None  # None = not yet decided
        self._redis = None
        # Fail-open observability: count consecutive Redis failures so we can
        # log at WARNING without flooding logs (audit F-D-2).
        self._redis_failure_count: int = 0
        # Buckets seen via check() that are not registered. Audit 2026-04-30
        # found six call sites referencing buckets never registered, which
        # made check() a silent no-op. Track first-sighting to log once per
        # bucket without spamming.
        self._unregistered_buckets: set[str] = set()

    def register(self, bucket: str, window_seconds: int, max_requests: int) -> None:
        """Register the configuration for a bucket. Called at startup."""
        self._configs[bucket] = (window_seconds, max_requests)

    def _select_backend(self) -> None:
        """Lazily select backend on first use."""
        if self._use_redis is not None:
            return
        from app.redis.pool import get_redis
        self._redis = get_redis()
        self._use_redis = self._redis is not None
        backend = "Redis" if self._use_redis else "in-memory"
        _log.info("Rate limiter backend: %s", backend)

    async def check(self, subject: str, bucket: str) -> None:
        """
        Check if subject has exceeded the limit for bucket.
        Raises HTTP 429 if over limit.
        """
        config = self._configs.get(bucket)
        if config is None:
            if bucket not in self._unregistered_buckets:
                self._unregistered_buckets.add(bucket)
                _log.warning(
                    "rate limiter bucket not registered, fail-open "
                    "[bucket=%s] (this should be wired in limiter.py)",
                    bucket,
                )
            return

        self._select_backend()

        if self._use_redis:
            try:
                await self._check_redis(subject, bucket, config)
            except HTTPException:
                # Genuine 429 from the Lua script — must propagate.
                raise
            except _REDIS_TRANSIENT_ERRORS as exc:
                # Audit F-D-2: Redis outage must not surface as HTTP 500.
                # Fail open — rate limiting is a best-effort DoS control,
                # not an auth gate. Blocking requests during a Redis outage
                # is a worse DoS than allowing unlimited requests briefly.
                self._redis_failure_count += 1
                _log.warning(
                    "rate limiter Redis unavailable — allowing request "
                    "(fail-open) [bucket=%s, consecutive_failures=%d]: %s",
                    bucket, self._redis_failure_count, exc,
                )
                return
            except RedisError as exc:
                # Other Redis errors (script errors, response errors) — also
                # fail open but log at a distinct level so operators can
                # distinguish transient connectivity from protocol bugs.
                self._redis_failure_count += 1
                _log.warning(
                    "rate limiter Redis error — allowing request "
                    "(fail-open) [bucket=%s, consecutive_failures=%d]: %s",
                    bucket, self._redis_failure_count, exc,
                )
                return
            # Reset the failure counter on a successful Redis round-trip.
            if self._redis_failure_count:
                _log.info(
                    "rate limiter Redis recovered after %d failed checks",
                    self._redis_failure_count,
                )
                self._redis_failure_count = 0
        else:
            await self._check_memory(subject, bucket, config)

    async def _check_memory(self, subject: str, bucket: str,
                            config: tuple[int, int]) -> None:
        """In-memory sliding window check (single-worker only)."""
        window_seconds, max_requests = config
        now = time.monotonic()
        cutoff = now - window_seconds
        key = (subject, bucket)

        async with self._lock:
            # LRU eviction: if too many unique subjects, drop oldest entries
            if key not in self._windows and len(self._windows) >= _MAX_SUBJECTS:
                oldest_key = next(iter(self._windows))
                del self._windows[oldest_key]

            dq = self._windows[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= max_requests:
                RATE_LIMIT_REJECT_COUNTER.add(1, {"bucket": bucket})
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for '{bucket}': max {max_requests} req/{window_seconds}s",
                    headers={"Retry-After": str(window_seconds)},
                )
            dq.append(now)

    # Lua script for atomic sliding window check + add.
    # Returns 1 if the request is allowed, 0 if rate limited.
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
    _lua_sha: str | None = None

    async def _check_redis(self, subject: str, bucket: str,
                           config: tuple[int, int]) -> None:
        """
        Redis sorted set sliding window (multi-worker safe).

        Uses an atomic Lua script to avoid the TOCTOU race condition
        between ZCARD (count) and ZADD (register).
        """
        window_seconds, max_requests = config
        now = time.time()
        cutoff = now - window_seconds
        redis_key = f"ratelimit:{subject}:{bucket}"
        request_id = uuid.uuid4().hex
        ttl = window_seconds + 10

        # Load the script once, then use EVALSHA for efficiency
        if self._lua_sha is None:
            self._lua_sha = await self._redis.script_load(self._LUA_SCRIPT)

        allowed = await self._redis.evalsha(
            self._lua_sha, 1, redis_key,
            str(now), str(cutoff), str(max_requests), request_id, str(ttl),
        )

        if not allowed:
            RATE_LIMIT_REJECT_COUNTER.add(1, {"bucket": bucket})
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for '{bucket}': max {max_requests} req/{window_seconds}s",
                headers={"Retry-After": str(window_seconds)},
            )


def get_client_ip(request) -> str:
    """Extract the client IP from a FastAPI/Starlette Request.

    When uvicorn runs with --proxy-headers behind a trusted reverse proxy,
    request.client.host already reflects the real client IP (X-Forwarded-For
    is parsed by uvicorn's ProxyHeadersMiddleware). This helper centralises
    that dependency so callers don't access request.client directly.
    """
    if request and request.client:
        return request.client.host
    return "unknown"


# Shared global instance
rate_limiter = SlidingWindowLimiter()

# ── Bucket configuration ──────────────────────────────────────────────────────
rate_limiter.register("auth.token",       window_seconds=60,  max_requests=10)
rate_limiter.register("broker.session",   window_seconds=60,  max_requests=20)
rate_limiter.register("broker.message",   window_seconds=60,  max_requests=60)
rate_limiter.register("dashboard.login",  window_seconds=300, max_requests=5)
rate_limiter.register("onboarding.join",  window_seconds=300, max_requests=5)
# Mastio pubkey rotation — 5/min/IP matches the ``onboarding.join`` cadence:
# rotations are infrequent operator actions (cadence days→weeks), so 5
# attempts per minute is plenty for a legitimate retry loop and tight
# enough to make unauthenticated CPU-burn / audit-flood attacks expensive.
# See issue #282.
rate_limiter.register("onboarding.rotate_mastio_pubkey",
                                          window_seconds=60,  max_requests=5)
rate_limiter.register("broker.rfq",         window_seconds=60,  max_requests=5)
rate_limiter.register("broker.rfq_respond", window_seconds=60,  max_requests=20)
# Oneshot fan-out: sender, recipient inbound flood guard, inbox poll.
# Audit 2026-04-30 C1 — these were referenced in oneshot_router.py but
# never registered, so check() was a silent no-op.
rate_limiter.register("broker.oneshot",         window_seconds=60, max_requests=60)
rate_limiter.register("broker.oneshot_inbound", window_seconds=60, max_requests=120)
rate_limiter.register("broker.oneshot_inbox",   window_seconds=60, max_requests=60)
rate_limiter.register("broker.poll",            window_seconds=60, max_requests=60)
# Onboarding anonymous inspect/attach paths. Inspect is read-only so a
# slightly higher cap is fine; attach consumes invite-token state, so
# match the join cadence (5/5min/IP).
rate_limiter.register("onboarding.invite_inspect",
                                                window_seconds=60,  max_requests=30)
rate_limiter.register("onboarding.attach",      window_seconds=300, max_requests=5)
