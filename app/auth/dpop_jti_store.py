"""
DPoP JTI store — short-lived nonce tracking for DPoP proof replay protection.

Two backends:
  - InMemoryDpopJtiStore  — single-worker only (default when Redis is unavailable)
  - RedisDpopJtiStore     — multi-worker safe via SET NX EX (atomic check+insert)

The active backend is selected at startup by get_dpop_jti_store(), which checks
if Redis is available.  The dpop.py module calls consume_jti() — a single atomic
operation that checks and registers the JTI in one step (no race window).

TTL defaults to 300s (5 min): covers the proof iat acceptance window (60s)
plus generous clock-skew slack.
"""
import logging
import threading
import time
from typing import Protocol

_log = logging.getLogger("agent_trust")

_DEFAULT_TTL = 300  # seconds


class DpopJtiStore(Protocol):
    """Interface for DPoP JTI stores."""

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        """
        Atomically check if the JTI has been seen, and register it if not.
        Returns True if newly consumed (first use).
        Returns False if already seen (replay).
        """
        ...


class InMemoryDpopJtiStore:
    """
    Thread-safe in-memory JTI store with TTL and lazy cleanup.
    Not suitable for multi-worker deployments.
    """

    def __init__(self) -> None:
        self._store: dict[str, float] = {}  # jti → expires_at (monotonic)
        self._lock = threading.Lock()

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        now = time.monotonic()
        expires_at = now + ttl_seconds

        with self._lock:
            # Lazy cleanup
            expired = [k for k, v in self._store.items() if v < now]
            for k in expired:
                del self._store[k]

            # Atomic check+insert
            if jti in self._store:
                return False  # replay
            self._store[jti] = expires_at
            return True  # new


class RedisDpopJtiStore:
    """
    Redis-backed JTI store — multi-worker safe.
    Uses SET NX EX for atomic check+insert with automatic TTL expiry.
    """

    _PREFIX = "dpop:jti:"

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        # SET key "1" NX EX ttl → returns True if set (new), None if existed (replay)
        result = await self._redis.set(
            f"{self._PREFIX}{jti}", "1", nx=True, ex=ttl_seconds,
        )
        return result is not None


# ─────────────────────────────────��───────────────────────────────────────────
# Singleton with lazy initialization
# ────────────────────────��───────────────────────────────���────────────────────

_store: DpopJtiStore | None = None


def _init_store() -> DpopJtiStore:
    """Select the best available backend."""
    from app.redis.pool import get_redis
    redis = get_redis()
    if redis is not None:
        _log.info("DPoP JTI store: Redis")
        return RedisDpopJtiStore(redis)
    _log.info("DPoP JTI store: in-memory")
    return InMemoryDpopJtiStore()


def get_dpop_jti_store() -> DpopJtiStore:
    """Return the active JTI store, initializing on first call."""
    global _store
    if _store is None:
        _store = _init_store()
    return _store


def reset_dpop_jti_store() -> None:
    """Reset the store (used by tests to force re-initialization)."""
    global _store
    _store = None
