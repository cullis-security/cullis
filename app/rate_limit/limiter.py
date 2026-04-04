"""
Sliding window rate limiter — dual backend (in-memory / Redis).

In-memory: single-process, counters reset on restart.
Redis: multi-worker safe, sorted sets with automatic TTL cleanup.

The active backend is selected at first use based on Redis availability.
"""
import logging
import time
import uuid
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, status

from app.telemetry_metrics import RATE_LIMIT_REJECT_COUNTER

_log = logging.getLogger("agent_trust")


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
        self._lock = Lock()
        # Backend selection
        self._use_redis: bool | None = None  # None = not yet decided
        self._redis = None

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
            return

        self._select_backend()

        if self._use_redis:
            await self._check_redis(subject, bucket, config)
        else:
            self._check_memory(subject, bucket, config)

    def _check_memory(self, subject: str, bucket: str,
                      config: tuple[int, int]) -> None:
        """In-memory sliding window check (single-worker only)."""
        window_seconds, max_requests = config
        now = time.monotonic()
        cutoff = now - window_seconds
        key = (subject, bucket)

        with self._lock:
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

    async def _check_redis(self, subject: str, bucket: str,
                           config: tuple[int, int]) -> None:
        """
        Redis sorted set sliding window (multi-worker safe).

        Key:   ratelimit:{subject}:{bucket}
        Score: unix timestamp
        Member: unique request ID (avoids dedup on same-millisecond requests)

        Pipeline:
          1. ZREMRANGEBYSCORE — remove entries outside the window
          2. ZCARD — count entries in the window
          3. ZADD — add current request (only executed if under limit)
          4. EXPIRE — TTL = window_seconds (auto-cleanup for idle keys)
        """
        window_seconds, max_requests = config
        now = time.time()
        cutoff = now - window_seconds
        redis_key = f"ratelimit:{subject}:{bucket}"
        request_id = uuid.uuid4().hex

        pipe = self._redis.pipeline(transaction=True)
        pipe.zremrangebyscore(redis_key, 0, cutoff)
        pipe.zcard(redis_key)
        results = await pipe.execute()
        count = results[1]

        if count >= max_requests:
            RATE_LIMIT_REJECT_COUNTER.add(1, {"bucket": bucket})
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for '{bucket}': max {max_requests} req/{window_seconds}s",
                headers={"Retry-After": str(window_seconds)},
            )

        # Under limit — register this request
        pipe2 = self._redis.pipeline(transaction=True)
        pipe2.zadd(redis_key, {request_id: now})
        pipe2.expire(redis_key, window_seconds + 10)  # +10s slack for cleanup
        await pipe2.execute()


# Shared global instance
rate_limiter = SlidingWindowLimiter()

# ── Bucket configuration ──────────────────────────────────────────────────────
rate_limiter.register("auth.token",       window_seconds=60,  max_requests=10)
rate_limiter.register("broker.session",   window_seconds=60,  max_requests=20)
rate_limiter.register("broker.message",   window_seconds=60,  max_requests=60)
