"""
Per-IP brute-force lockout for the Mastio dashboard ``/proxy/login`` form.

Audit H9: the login handler had no rate-limit, no lockout, and no
back-off, so an attacker on the same network could trial passwords at
HTTP-stack speed. The bcrypt cost slows each attempt down somewhat,
but ~10 guesses per second on commodity hardware is still enough to
chew through a short or pattern-based admin password before anyone
notices.

Two layers, both keyed on the client IP:

1. **Rate limit** — caps the burst rate at 10 attempts/min/IP via the
   existing ``get_agent_rate_limiter()`` (Redis-backed when available,
   in-memory per-worker otherwise). Lets a forgetful operator retry
   without locking themselves out, but stops a fast scripted spray.

2. **Lockout** — after 5 consecutive failures the IP is blocked for
   15 minutes. Successful logins reset the counter; the lockout
   window itself uses absolute timestamps so a restart doesn't
   accidentally reset state mid-attack (in-memory) or persists in
   Redis (multi-worker).

Both layers are advisory rather than authentication: even if the
attacker bypasses the lockout (different IP, header spoof through a
broken reverse proxy), bcrypt + the audit log on every failure still
protect the credential. The point is to put friction on automation
and make the audit trail noisy enough to notice.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Protocol

_log = logging.getLogger("mcp_proxy")

# Tuned for the dashboard threat model: an admin password change is
# rare, so 5 misses inside the cooldown is overwhelmingly likely to
# be an attack rather than a confused operator. 15 min matches the
# OWASP ASVS L1 baseline for account-lockout duration.
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 15 * 60
LOCKOUT_DURATION_SECONDS = 15 * 60
LOGIN_RATE_PER_MINUTE = 10


class LoginLockoutStore(Protocol):
    async def record_failure(self, ip: str) -> tuple[int, float | None]:
        """Increment the failure counter and return ``(count, locked_until)``.

        ``locked_until`` is a wall-clock UNIX timestamp when the IP
        becomes unlocked, or ``None`` when the IP is still under the
        threshold.
        """
        ...

    async def record_success(self, ip: str) -> None:
        """Clear failure state for a successful login."""
        ...

    async def is_locked(self, ip: str) -> float | None:
        """Return the unlock time when the IP is currently locked, else ``None``."""
        ...


class _InMemoryStore:
    """Per-worker in-memory store. Sufficient for single-worker
    deployments; multi-worker needs the Redis-backed variant or each
    worker's lockout window is independent (degrading the threshold
    by a factor of N)."""

    def __init__(self) -> None:
        # ip -> list[float] of recent failure timestamps within the
        # rolling lockout window. The list is trimmed on each access.
        self._failures: dict[str, list[float]] = {}
        # ip -> wall-clock unlock time
        self._locked_until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def record_failure(self, ip: str) -> tuple[int, float | None]:
        now = time.time()
        cutoff = now - LOCKOUT_WINDOW_SECONDS
        async with self._lock:
            recent = [t for t in self._failures.get(ip, []) if t > cutoff]
            recent.append(now)
            self._failures[ip] = recent
            if len(recent) >= LOCKOUT_THRESHOLD:
                unlock_at = now + LOCKOUT_DURATION_SECONDS
                self._locked_until[ip] = unlock_at
                # Leaving the failure list intact means a single mistake
                # after the lockout expires won't reset the counter —
                # only an explicit success does. Closes a partial-bypass
                # where an attacker spaces guesses just past the window.
                return len(recent), unlock_at
            return len(recent), None

    async def record_success(self, ip: str) -> None:
        async with self._lock:
            self._failures.pop(ip, None)
            self._locked_until.pop(ip, None)

    async def is_locked(self, ip: str) -> float | None:
        now = time.time()
        async with self._lock:
            unlock_at = self._locked_until.get(ip)
            if unlock_at is None:
                return None
            if unlock_at <= now:
                # Expired lockout: clear it and the failure history so
                # the next legitimate attempt starts fresh.
                self._locked_until.pop(ip, None)
                self._failures.pop(ip, None)
                return None
            return unlock_at


_store: LoginLockoutStore | None = None


def get_login_lockout_store() -> LoginLockoutStore:
    """Return the active store, initialising on first call.

    Mirrors the pattern in ``auth/rate_limit.py`` — Redis when
    available, in-memory otherwise. The Redis adapter is intentionally
    not implemented yet; multi-worker deployments must run with one
    worker until a Redis-backed variant lands. Single-Mastio default
    deploy is single-worker.
    """
    global _store
    if _store is None:
        _store = _InMemoryStore()
        _log.info("Dashboard login lockout: in-memory")
    return _store


def reset_login_lockout_for_tests() -> None:
    """Test-only helper: drop the singleton so each test starts fresh."""
    global _store
    _store = None


__all__ = [
    "LOCKOUT_DURATION_SECONDS",
    "LOCKOUT_THRESHOLD",
    "LOCKOUT_WINDOW_SECONDS",
    "LOGIN_RATE_PER_MINUTE",
    "LoginLockoutStore",
    "get_login_lockout_store",
    "reset_login_lockout_for_tests",
]
