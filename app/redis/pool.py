"""
Redis connection pool — shared async client for the entire broker process.

Usage:
    from app.redis.pool import get_redis

    redis = get_redis()          # returns the shared client (or None if disabled)
    if redis:
        await redis.set("key", "value", ex=300)

The pool is initialized at startup (main.py lifespan) and closed at shutdown.
If REDIS_URL is empty or connection fails, Redis is disabled gracefully:
all callers get None and fall back to in-memory implementations.
"""
import logging

import redis.asyncio as aioredis

_log = logging.getLogger("agent_trust")

_client: aioredis.Redis | None = None


async def init_redis(redis_url: str) -> bool:
    """
    Initialize the shared Redis async client.
    Returns True if the connection succeeded, False otherwise.
    """
    global _client

    if not redis_url:
        _log.info("Redis disabled — REDIS_URL is empty")
        return False

    try:
        client = aioredis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        # Verify connectivity
        await client.ping()
        _client = client
        _log.info("Redis connected: %s", redis_url)
        return True
    except Exception as exc:
        _log.warning("Redis connection failed (%s) — falling back to in-memory: %s", redis_url, exc)
        _client = None
        return False


async def close_redis() -> None:
    """Close the Redis connection pool. Safe to call even if Redis is disabled."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
        _log.info("Redis connection closed")


def get_redis() -> aioredis.Redis | None:
    """
    Return the shared Redis client, or None if Redis is disabled.
    Callers must check for None and fall back to in-memory.
    """
    return _client
