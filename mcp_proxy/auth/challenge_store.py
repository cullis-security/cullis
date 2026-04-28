"""Login-challenge nonce store — short-lived, single-use nonces for the
client-signed login flow (tech-debt #2).

The device-code Connector holds its agent private key locally and signs
the broker ``client_assertion`` itself (see
:mod:`mcp_proxy.auth.challenge_response`). To prevent replay of a
captured signed assertion, the Mastio issues a short-lived nonce that
the client embeds as a JWT claim; the assertion is only endorsed if
the nonce is still outstanding and consumed atomically on first use.

Two backends, mirroring :mod:`mcp_proxy.auth.dpop_jti_store`:
  * :class:`InMemoryChallengeStore` — single-worker only.
  * :class:`RedisChallengeStore`    — multi-worker safe via ``SET NX EX``
    + explicit ``DEL`` on consume (two-step because the nonce is
    *single-use* rather than *TTL-only* — the second caller must get a
    miss even before the TTL elapses).

Key shape: ``login_challenge:{agent_id}:{nonce}`` — binding the nonce
to the caller means a leaked nonce can't be redeemed by a different
client-cert holder (defence in depth on top of the ``sub`` claim check
in the verification path).
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Protocol

_log = logging.getLogger("mcp_proxy")

_DEFAULT_TTL = 120  # seconds — covers login round-trip + clock skew,
                    # shorter than the assertion ``exp`` (≤300s).


class ChallengeStore(Protocol):
    """Interface for challenge nonce stores."""

    async def issue(self, agent_id: str, nonce: str,
                    ttl_seconds: int = _DEFAULT_TTL) -> bool:
        """Register a freshly-minted nonce for ``agent_id`` with TTL.

        Returns True on first registration, False if the key already
        exists (collision — caller should regenerate the nonce).
        """
        ...

    async def consume(self, agent_id: str, nonce: str) -> bool:
        """Atomically check and remove a nonce.

        Returns True if the nonce was outstanding and is now consumed,
        False if it was already consumed, expired, or never issued.
        """
        ...


class InMemoryChallengeStore:
    """Async-safe in-memory store with lazy expiry cleanup.

    Single-worker only. Each worker holds its own dict — Multi-worker
    deployments MUST use Redis or a captured nonce could be redeemed by
    a different worker's view of the store.
    """

    def __init__(self) -> None:
        # key -> expires_at (monotonic); key = f"{agent_id}:{nonce}"
        self._store: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def issue(self, agent_id: str, nonce: str,
                    ttl_seconds: int = _DEFAULT_TTL) -> bool:
        now = time.monotonic()
        expires_at = now + ttl_seconds
        key = f"{agent_id}:{nonce}"
        async with self._lock:
            # Expire stale entries opportunistically.
            stale = [k for k, v in self._store.items() if v < now]
            for k in stale:
                del self._store[k]
            if key in self._store:
                return False  # collision — caller regenerates
            self._store[key] = expires_at
            return True

    async def consume(self, agent_id: str, nonce: str) -> bool:
        now = time.monotonic()
        key = f"{agent_id}:{nonce}"
        async with self._lock:
            expires_at = self._store.pop(key, None)
            if expires_at is None:
                return False  # never issued or already consumed
            return expires_at >= now  # False if expired since issue


class RedisChallengeStore:
    """Redis-backed store — multi-worker safe.

    ``issue`` uses ``SET NX EX`` (atomic check+set with TTL).
    ``consume`` uses ``DEL`` after a ``GET`` to keep the op single-use
    semantic-equivalent; Redis's ``GETDEL`` would be cleaner but isn't
    in the minimum redis-py version we pin. The two-call version is
    atomic enough: a concurrent consumer either sees the value (and
    wins the race) or sees ``None`` (and loses).
    """

    _PREFIX = "mcp_proxy:login_challenge:"

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    async def issue(self, agent_id: str, nonce: str,
                    ttl_seconds: int = _DEFAULT_TTL) -> bool:
        key = f"{self._PREFIX}{agent_id}:{nonce}"
        result = await self._redis.set(key, "1", nx=True, ex=ttl_seconds)
        return result is not None

    async def consume(self, agent_id: str, nonce: str) -> bool:
        key = f"{self._PREFIX}{agent_id}:{nonce}"
        # DEL returns the number of keys removed. If 0, nonce was already
        # consumed (or expired, or never issued).
        deleted = await self._redis.delete(key)
        return bool(deleted)


_store: ChallengeStore | None = None


def _init_store() -> ChallengeStore:
    """Select the best available backend. Warns in production when only
    the in-memory store is available (multi-worker can race).
    """
    from mcp_proxy.config import get_settings
    from mcp_proxy.redis.pool import get_redis

    redis = get_redis()
    if redis is not None:
        _log.info("login challenge store: Redis")
        return RedisChallengeStore(redis)

    if get_settings().environment == "production":
        _log.warning(
            "login challenge store: Redis unavailable in production — "
            "falling back to in-memory. Safe only for single-instance/"
            "single-worker deployments. Multi-worker/HA deploys MUST set "
            "MCP_PROXY_REDIS_URL; otherwise a captured login nonce can be "
            "consumed on one worker and replayed on another."
        )

    _log.info("login challenge store: in-memory")
    return InMemoryChallengeStore()


def get_challenge_store() -> ChallengeStore:
    """Return the active challenge store, initializing on first call."""
    global _store
    if _store is None:
        _store = _init_store()
    return _store


def reset_challenge_store() -> None:
    """Reset the store — used by tests to force re-initialization."""
    global _store
    _store = None
