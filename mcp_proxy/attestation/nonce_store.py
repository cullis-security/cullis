"""Single-use server-issued nonces for the TPM attestation flow.

Each ``GET /v1/enrollment/attestation-nonce`` mints a 32-byte random nonce,
returns the base64url encoding + an opaque ``nonce_id``, and records the
pair in an in-process store with a short TTL (default 60s, configurable
via ``MCP_PROXY_ATTESTATION_NONCE_TTL_SECONDS``).

Redis is preferred when the proxy is configured for it; the
``set_attestation_nonce_redis_pool`` hook lets the lifespan wire it in
without circular imports. When Redis is unavailable the fallback is a
``dict`` guarded by an ``asyncio.Lock``; that keeps the spike usable on
laptops and in CI without standing up a broker. Multi-worker uvicorn
deployments must enable Redis (see memoria
``feedback_mastio_multiworker_audit_chain_retry_ship_safe`` for the
analogous shared-state caveat).
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger("mcp_proxy.attestation.nonce_store")


_DEFAULT_TTL_SECONDS = 60
_NONCE_BYTES = 32  # 256-bit, well past TPM quote replay surface


def _ttl_seconds() -> int:
    try:
        return max(5, int(os.environ.get(
            "MCP_PROXY_ATTESTATION_NONCE_TTL_SECONDS",
            str(_DEFAULT_TTL_SECONDS),
        )))
    except ValueError:
        return _DEFAULT_TTL_SECONDS


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


@dataclass(frozen=True)
class IssuedNonce:
    nonce_id: str
    nonce_b64: str
    nonce_bytes: bytes
    expires_at_epoch: int


class _RedisLike(Protocol):
    async def set(self, *args: object, **kwargs: object) -> object: ...
    async def get(self, *args: object, **kwargs: object) -> object: ...
    async def delete(self, *args: object, **kwargs: object) -> object: ...


_REDIS_POOL: _RedisLike | None = None


def set_attestation_nonce_redis_pool(pool: _RedisLike | None) -> None:
    """Lifespan hook; wire the redis client if attestation needs it."""
    global _REDIS_POOL
    _REDIS_POOL = pool


# In-memory fallback. Keys are nonce_id, values are (nonce_b64, expires_at).
_MEMORY: dict[str, tuple[str, int]] = {}
_MEMORY_LOCK = asyncio.Lock()


def _redis_key(nonce_id: str) -> str:
    return f"cullis:attest:nonce:{nonce_id}"


async def issue_nonce() -> IssuedNonce:
    """Mint a fresh single-use nonce. TTL clamps storage on either backend."""
    raw = secrets.token_bytes(_NONCE_BYTES)
    nonce_id = secrets.token_urlsafe(16)
    nonce_b64 = _b64url_nopad(raw)
    ttl = _ttl_seconds()
    expires_at = int(time.time()) + ttl

    if _REDIS_POOL is not None:
        try:
            await _REDIS_POOL.set(_redis_key(nonce_id), nonce_b64, ex=ttl)
            return IssuedNonce(
                nonce_id=nonce_id,
                nonce_b64=nonce_b64,
                nonce_bytes=raw,
                expires_at_epoch=expires_at,
            )
        except Exception as exc:
            # Redis hiccup; fall through to memory backend so the spike
            # path stays usable. Single-process Mastio deployments are
            # safe; multi-worker users hit the gotcha above.
            _log.warning("attestation_nonce_redis_set_failed", extra={"err": str(exc)})

    async with _MEMORY_LOCK:
        _prune_locked()
        _MEMORY[nonce_id] = (nonce_b64, expires_at)
    return IssuedNonce(
        nonce_id=nonce_id,
        nonce_b64=nonce_b64,
        nonce_bytes=raw,
        expires_at_epoch=expires_at,
    )


async def consume_nonce(nonce_id: str) -> bytes | None:
    """Single-use lookup. Returns the raw 32-byte nonce or ``None``."""
    if not nonce_id:
        return None
    if _REDIS_POOL is not None:
        try:
            value = await _REDIS_POOL.get(_redis_key(nonce_id))
            if value is None:
                # Fall through to memory in case the issue path landed there.
                pass
            else:
                await _REDIS_POOL.delete(_redis_key(nonce_id))
                decoded = value.decode() if isinstance(value, (bytes, bytearray)) else str(value)
                return _b64url_decode(decoded)
        except Exception as exc:
            _log.warning("attestation_nonce_redis_get_failed", extra={"err": str(exc)})

    async with _MEMORY_LOCK:
        _prune_locked()
        entry = _MEMORY.pop(nonce_id, None)
    if entry is None:
        return None
    nonce_b64, _expires_at = entry
    return _b64url_decode(nonce_b64)


def _prune_locked() -> None:
    now = int(time.time())
    stale = [k for k, (_b, exp) in _MEMORY.items() if exp < now]
    for key in stale:
        _MEMORY.pop(key, None)


def reset_memory_store_for_tests() -> None:
    """Test helper; wipe the in-memory backend between cases."""
    _MEMORY.clear()
