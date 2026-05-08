"""
DPoP JTI store — short-lived nonce tracking for DPoP proof replay protection.

Two backends:
  - InMemoryDpopJtiStore  — single-worker only (default when Redis is unavailable)
  - RedisDpopJtiStore     — multi-worker safe via SET NX EX (atomic check+insert)

The active backend is selected at startup by ``get_dpop_jti_store()``, which
checks if Redis is available. ``dpop.verify_dpop_proof`` calls
``consume_jti()`` — a single atomic operation that checks and registers
the JTI in one step (no race window).

TTL defaults to 300s (5 min): covers the proof iat acceptance window plus
clock-skew slack.

Ported from ``app/auth/dpop_jti_store.py`` (audit F-E-04). The Mastio
(``mcp_proxy``) side of the same finding lived unguarded until this
port — see issue #182 for context.
"""
import asyncio
import logging
import time
from typing import Protocol

_log = logging.getLogger("mcp_proxy")

_DEFAULT_TTL = 300  # seconds


class DpopJtiStore(Protocol):
    """Interface for DPoP JTI stores."""

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        """Atomically check if the JTI has been seen, and register it if not.

        Returns True if newly consumed (first use).
        Returns False if already seen (replay).
        """
        ...


class InMemoryDpopJtiStore:
    """Async-safe in-memory JTI store with TTL and lazy cleanup.

    Not suitable for multi-worker deployments — each worker has its own
    dict, which defeats replay protection across workers.
    """

    def __init__(self) -> None:
        self._store: dict[str, float] = {}  # jti -> expires_at (monotonic)
        self._lock = asyncio.Lock()

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        now = time.monotonic()
        expires_at = now + ttl_seconds

        async with self._lock:
            expired = [k for k, v in self._store.items() if v < now]
            for k in expired:
                del self._store[k]

            if jti in self._store:
                return False  # replay
            self._store[jti] = expires_at
            return True  # new


class RedisDpopJtiStore:
    """Redis-backed JTI store — multi-worker safe.

    Uses SET NX EX for atomic check+insert with automatic TTL expiry.
    """

    _PREFIX = "mcp_proxy:dpop:jti:"

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    async def consume_jti(self, jti: str, ttl_seconds: int = _DEFAULT_TTL) -> bool:
        result = await self._redis.set(
            f"{self._PREFIX}{jti}", "1", nx=True, ex=ttl_seconds,
        )
        return result is not None


_store: DpopJtiStore | None = None


def _init_store() -> DpopJtiStore:
    """Select the best available backend.

    Production posture: refuse the in-memory fallback unless the operator
    has explicitly opted in via
    ``MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES=true``. The Court raises
    unconditionally (multi-tenant); the Mastio supports a legitimate
    single-instance production mode but makes that choice explicit
    rather than silent (audit L1-H1 / Ultra U-DD-1). Without the opt-in,
    a multi-worker HA deploy that lost Redis would silently allow DPoP
    replay across workers within the ``iat`` window (RFC 9449 violation).

    Dev/test (``environment != "production"``) keeps the warning-only
    path for ergonomics.
    """
    from mcp_proxy.redis.pool import get_redis
    from mcp_proxy.config import get_settings

    redis = get_redis()
    if redis is not None:
        _log.info("DPoP JTI store: Redis")
        return RedisDpopJtiStore(redis)

    settings = get_settings()
    if settings.environment == "production":
        if not settings.allow_inmemory_security_stores:
            _log.critical(
                "DPoP JTI store: Redis unavailable in production and "
                "MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES is not set. "
                "Refusing the in-memory fallback to avoid cross-worker "
                "replay of DPoP proofs (RFC 9449). Set MCP_PROXY_REDIS_URL "
                "for HA, or set MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES=true "
                "to acknowledge a single-instance/single-worker deployment.",
            )
            raise RuntimeError(
                "DPoP JTI store requires Redis in production unless "
                "MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES=true is set "
                "(audit L1-H1 / Ultra U-DD-1)."
            )
        _log.warning(
            "DPoP JTI store: Redis unavailable in production — using "
            "in-memory because MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES "
            "is set. Safe only for single-instance/single-worker "
            "deployments; multi-worker/HA deploys MUST set "
            "MCP_PROXY_REDIS_URL."
        )

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
