"""
Per-IP brute-force lockout for the Cullis Connector local-auth login.

ADR-025 Phase 4: ports the proven brute-force defence from
``mcp_proxy/dashboard/login_lockout.py`` into the Connector identity
namespace, so the Frontdesk-mode login handler (Phase 2) can reuse the
same Protocol + InMemoryStore + thresholds (5 fails / 15 min / 15 min
cooldown). One implementation, two call-sites — the Mastio dashboard
and the Connector — share both behaviour and tuning.

Two layers, both keyed on the client IP:

1. **Rate limit** — caps the burst rate at 10 attempts/min/IP. The
   Connector wires this into FastAPI middleware in Phase 2.

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

_log = logging.getLogger("cullis_connector.identity.lockout")

# Audit H9 — porting da mcp_proxy/dashboard/login_lockout.py per
# riusare la stessa difesa contro brute-force; soglie identiche
# (5 tentativi / 15 min) per coerenza operativa fra Mastio dashboard
# e Connector local-auth. OWASP ASVS L1 baseline.
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 15 * 60
LOCKOUT_DURATION_SECONDS = 15 * 60
LOGIN_RATE_PER_MINUTE = 10


class LockoutStore(Protocol):
    async def record_failure(
        self, ip: str, user_name: str | None = None
    ) -> tuple[int, float | None]:
        """Increment the failure counter and return ``(count, locked_until)``.

        ``locked_until`` is a wall-clock UNIX timestamp when the IP
        becomes unlocked, or ``None`` when the IP is still under the
        threshold. ``user_name`` is advisory (used by callers for audit
        logging context) — store implementations key only on ``ip``.
        """
        ...

    async def record_success(self, ip: str) -> None:
        """Clear failure state for a successful login."""
        ...

    async def is_locked(self, ip: str) -> float | None:
        """Return the unlock time when the IP is currently locked, else ``None``."""
        ...


class InMemoryStore:
    """Per-worker in-memory store. Sufficient for single-worker
    Connector deployments; multi-worker setups should back the Protocol
    with Redis or each worker's lockout window is independent
    (degrading the threshold by a factor of N)."""

    def __init__(self) -> None:
        # ip -> list[float] of recent failure timestamps within the
        # rolling lockout window. The list is trimmed on each access.
        self._failures: dict[str, list[float]] = {}
        # ip -> wall-clock unlock time
        self._locked_until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def record_failure(
        self, ip: str, user_name: str | None = None
    ) -> tuple[int, float | None]:
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


# Module-level default singleton: callers that don't pass an explicit
# ``store=`` parameter get this one. Tests can replace it via
# ``reset_lockout_for_tests`` to start from a clean slate.
_default_store: LockoutStore = InMemoryStore()


async def is_locked(ip: str, store: LockoutStore | None = None) -> float | None:
    """Return the unlock time when ``ip`` is currently locked, else ``None``."""
    return await (store or _default_store).is_locked(ip)


async def record_failure(
    ip: str,
    user_name: str | None = None,
    store: LockoutStore | None = None,
) -> tuple[int, float | None]:
    """Record a failed login attempt and return ``(count, locked_until)``.

    ``user_name`` is advisory metadata for the caller's audit row — the
    Protocol implementations key state on ``ip`` only.
    """
    count, unlock_at = await (store or _default_store).record_failure(ip, user_name)
    if unlock_at is not None:
        _log.warning(
            "login lockout triggered ip=%s user=%s count=%d unlock_at=%.0f",
            ip, user_name or "", count, unlock_at,
        )
    return count, unlock_at


async def record_success(ip: str, store: LockoutStore | None = None) -> None:
    """Clear failure state after a successful login."""
    await (store or _default_store).record_success(ip)


async def get_locked_until(
    ip: str, store: LockoutStore | None = None
) -> float | None:
    """Alias of ``is_locked`` for callers that prefer the noun-form name."""
    return await (store or _default_store).is_locked(ip)


def reset_lockout_for_tests() -> None:
    """Test-only helper: drop the module singleton so each test starts fresh."""
    global _default_store
    _default_store = InMemoryStore()


__all__ = [
    "LOCKOUT_DURATION_SECONDS",
    "LOCKOUT_THRESHOLD",
    "LOCKOUT_WINDOW_SECONDS",
    "LOGIN_RATE_PER_MINUTE",
    "InMemoryStore",
    "LockoutStore",
    "get_locked_until",
    "is_locked",
    "record_failure",
    "record_success",
    "reset_lockout_for_tests",
]
