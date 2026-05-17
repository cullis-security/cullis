"""Cross-worker leader election for background tasks + boot-time singletons.

Why
---

Mastio runs multiple uvicorn workers (`MASTIO_WORKERS=4` default,
PR #742). Every background loop spawned in the lifespan hook
(``intune_poll_loop``, ``stale_watcher_loop``, ``local_sweeper_loop``)
runs in EACH worker. Without coordination that means:

* 4x Microsoft Graph API calls per polling tick — burns Intune quota,
  costs the customer real money on Azure Graph throttling tier
* 4x audit rows per stale device — chain inflation
* 4x SQLite migration concurrent at boot — race on
  ``CREATE/DROP/ALTER`` even when each worker holds its own connection

The pattern fix is leader election: exactly ONE worker owns each named
task; the others log + skip. Two concrete implementations cover the
two DB backends Mastio supports:

* **Postgres**: ``pg_try_advisory_lock(key)`` (RFC pattern, also used
  by Alembic gate in ``db.py:225-242``). Lock is session-scoped — when
  the holder connection closes, the lock releases automatically.
* **SQLite**: ``fcntl.flock(LOCK_EX | LOCK_NB)`` on a sidecar lockfile
  next to the DB file. Works cross-process (the 4 uvicorn workers all
  fork from the same uid + see the same filesystem) and survives
  ungraceful worker death (kernel releases on exit).

For tests, use :class:`NoopLeader` which always wins — keeps unit
tests deterministic without needing flock or Postgres.

Scope (V1, Wave 2b)
-------------------

Leader is captured **once at boot** by ``acquire()`` non-blocking. The
winner holds the lock for the full lifetime of the worker process. If
the leader worker dies, no automatic failover — the other workers do
NOT pick up the dropped lock. This is intentional V1: keeps the helper
simple, customer ops detects via "did the polling tick happen in the
last 2x interval?" alert.

V2 follow-up (when needed): lease + heartbeat with periodic
re-acquire so a fresh worker takes over after the original leader
dies. Tracked in ``followup_f5_f6_post_merge_tracker.md`` cluster A
extension.
"""
from __future__ import annotations

import asyncio
import errno
import logging
import os
import zlib
from abc import ABC, abstractmethod
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from mcp_proxy.db import _engine_kwargs  # type: ignore[attr-defined]

_log = logging.getLogger("mcp_proxy.lifespan.leader_election")


class LeaderElection(ABC):
    """Abstract leader-election contract.

    Concrete implementations: :class:`PostgresAdvisoryLeader`,
    :class:`SQLiteFlockLeader`, :class:`NoopLeader`. Pick the right one
    via :func:`get_leader`.
    """

    def __init__(self, task_name: str) -> None:
        self.task_name = task_name
        self._held = False

    @property
    def held(self) -> bool:
        return self._held

    @abstractmethod
    async def acquire(self) -> bool:
        """Try to acquire the leader lock non-blocking.

        Returns ``True`` if this worker won and now owns the lock,
        ``False`` if another worker already holds it. Idempotent: a
        second call after a successful first call returns ``True``
        without re-trying.
        """

    @abstractmethod
    async def release(self) -> None:
        """Release the lock. No-op if not currently held."""


class NoopLeader(LeaderElection):
    """Always-wins leader for tests and single-worker deployments.

    Use when the caller has external knowledge that only one process
    will ever run (pytest, ``--workers 1``, dev mode). Skips all DB
    coordination — zero overhead.
    """

    async def acquire(self) -> bool:
        self._held = True
        return True

    async def release(self) -> None:
        self._held = False


class PostgresAdvisoryLeader(LeaderElection):
    """Postgres ``pg_try_advisory_lock``-based leader.

    Maps the task name to a stable int64 key via zlib.crc32 (XOR'd with
    a fixed salt so collisions with Alembic's
    ``_ALEMBIC_ADVISORY_LOCK_KEY`` and any customer-managed keys stay
    out of band). Holds the lock on a dedicated long-lived connection;
    release closes the connection so even a Python-side crash drops
    the lock cleanly.
    """

    # Salt picked to be deterministic + visually distinct from
    # ``_ALEMBIC_ADVISORY_LOCK_KEY = 0xC0115A1E_EB1C0DE`` so lock-key
    # collisions across the codebase are impossible even if the crc32
    # of a future task name happens to equal "EB1C0DE".
    _SALT: int = 0x_C011_15_1EAD_E20001 & 0x_7FFF_FFFF_FFFF_FFFF

    def __init__(self, task_name: str, url: str) -> None:
        super().__init__(task_name)
        self._url = url
        self._engine: AsyncEngine | None = None
        self._conn: AsyncConnection | None = None
        self._key = self._key_for(task_name)

    @classmethod
    def _key_for(cls, task_name: str) -> int:
        crc = zlib.crc32(task_name.encode("utf-8")) & 0xFFFF_FFFF
        # Spread crc32 into the upper half of int64 to avoid collisions
        # with hand-picked Alembic-style hex keys that pack into 64-bit.
        return ((crc << 16) ^ cls._SALT) & 0x_7FFF_FFFF_FFFF_FFFF

    async def acquire(self) -> bool:
        if self._held:
            return True
        self._engine = create_async_engine(
            self._url, **_engine_kwargs(self._url),
        )
        conn = await self._engine.connect()
        try:
            row = (
                await conn.execute(
                    text("SELECT pg_try_advisory_lock(:k)"),
                    {"k": self._key},
                )
            ).first()
            won = bool(row and row[0])
        except Exception:
            await conn.close()
            await self._engine.dispose()
            self._engine = None
            raise
        if not won:
            await conn.close()
            await self._engine.dispose()
            self._engine = None
            return False
        self._conn = conn
        self._held = True
        return True

    async def release(self) -> None:
        if not self._held:
            return
        try:
            if self._conn is not None:
                try:
                    await self._conn.execute(
                        text("SELECT pg_advisory_unlock(:k)"),
                        {"k": self._key},
                    )
                except Exception as exc:  # noqa: BLE001 — best-effort
                    _log.warning(
                        "pg_advisory_unlock failed for task '%s': %s",
                        self.task_name, exc,
                    )
                await self._conn.close()
                self._conn = None
        finally:
            if self._engine is not None:
                await self._engine.dispose()
                self._engine = None
            self._held = False


class SQLiteFlockLeader(LeaderElection):
    """SQLite leader via ``fcntl.flock`` on a sidecar lockfile.

    Writes a small lockfile next to the SQLite DB at
    ``<db_path>.<task_name>.lock`` and holds an exclusive non-blocking
    flock on it. Cross-process safe — the 4 uvicorn workers fork from
    the same uid and see the same inode, so flock semantics match
    expectations. Survives ungraceful worker exit because the kernel
    releases all open file descriptors at process death.

    Why not just ``open(O_EXCL)`` on a pidfile? Because that would race
    on stale pidfile detection after crashes. flock is the textbook
    solution and is what Linux daemons (sudo, postfix, ...) use.
    """

    def __init__(self, task_name: str, db_path: Path | str) -> None:
        super().__init__(task_name)
        self._db_path = Path(db_path)
        self._lock_path = self._db_path.with_name(
            f"{self._db_path.name}.{task_name}.lock",
        )
        self._fd: int | None = None

    async def acquire(self) -> bool:
        if self._held:
            return True

        # flock is a blocking syscall by default; running in the event
        # loop would freeze every other coroutine on contention. Wrap
        # in a worker thread so the loop stays responsive. The actual
        # syscall is microseconds when uncontended (just inode update).
        def _try_flock() -> int | None:
            import fcntl

            # Create lockfile if missing, no truncation. Mode 0o644.
            fd = os.open(
                str(self._lock_path),
                os.O_CREAT | os.O_WRONLY,
                0o644,
            )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    os.close(fd)
                    return None
                os.close(fd)
                raise
            # Write our pid for ops visibility. Best-effort; not used
            # for lock coordination (kernel handles that via the fd).
            try:
                os.ftruncate(fd, 0)
                os.write(fd, f"{os.getpid()}\n".encode())
            except OSError:
                pass  # noqa: S110 — diagnostic write, not load-bearing
            return fd

        fd = await asyncio.to_thread(_try_flock)
        if fd is None:
            return False
        self._fd = fd
        self._held = True
        return True

    async def release(self) -> None:
        if not self._held or self._fd is None:
            return

        def _unflock(fd: int) -> None:
            import fcntl

            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

        try:
            await asyncio.to_thread(_unflock, self._fd)
        finally:
            self._fd = None
            self._held = False


def _sqlite_db_path(url: str) -> Path:
    """Extract the on-disk file path from a SQLite SQLAlchemy URL.

    Mirrors :func:`mcp_proxy.db._sqlite_path` semantics:

    * ``sqlite:///foo.db`` (3 slash) → relative ``foo.db``
    * ``sqlite+aiosqlite:///foo.db`` (3 slash) → relative ``foo.db``
    * ``sqlite:////absolute/foo.db`` (4 slash) → absolute
      ``/absolute/foo.db``

    The caller is responsible for detecting in-memory URLs and
    routing them to :class:`NoopLeader` — flock on a memory DB makes
    no sense.
    """
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if url.startswith(prefix):
            return Path(url[len(prefix):])
    # Defensive fallback: unrecognised SQLite-ish URL — strip scheme
    # and treat whatever is left as a path.
    return Path(url.split("://", 1)[-1])


def get_leader(task_name: str, db_url: str | None = None) -> LeaderElection:
    """Factory: pick the right leader implementation for the current DB.

    - Postgres URL → :class:`PostgresAdvisoryLeader`
    - SQLite file URL → :class:`SQLiteFlockLeader`
    - SQLite ``:memory:`` URL (tests) → :class:`NoopLeader`
    - Missing URL (defensive) → :class:`NoopLeader` (logs warning)

    The DB URL defaults to the Mastio settings value when not passed;
    tests can override directly.
    """
    if db_url is None:
        from mcp_proxy.config import get_settings

        db_url = get_settings().database_url

    if not db_url:
        _log.warning(
            "No DATABASE_URL configured — leader election for '%s' "
            "falls back to NoopLeader (assume single-worker)",
            task_name,
        )
        return NoopLeader(task_name)

    if db_url.startswith("postgresql") or "+asyncpg" in db_url:
        return PostgresAdvisoryLeader(task_name, db_url)

    if ":memory:" in db_url:
        _log.info(
            "SQLite in-memory DB — leader election for '%s' uses "
            "NoopLeader (single-process test path)",
            task_name,
        )
        return NoopLeader(task_name)

    if db_url.startswith("sqlite"):
        return SQLiteFlockLeader(task_name, _sqlite_db_path(db_url))

    _log.warning(
        "Unrecognised DATABASE_URL scheme for '%s' — falling back "
        "to NoopLeader: %s",
        task_name, db_url.split("://", 1)[0],
    )
    return NoopLeader(task_name)


__all__ = [
    "LeaderElection",
    "NoopLeader",
    "PostgresAdvisoryLeader",
    "SQLiteFlockLeader",
    "get_leader",
]
