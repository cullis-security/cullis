"""Async SQLite engine + session factory for the Connector's users.db.

ADR-025 Phase 1 — separate from any agent-side state. The Connector
already has ``identity/`` for the agent cert/key bundle; the local
user database lives one level up at ``<config_dir>/users.db`` so a
profile reset (``identity/`` wipe) does not blow away the user
accounts the admin pre-created.

WAL journaling is enabled on first connection so an active SPA login
flow does not block an admin DELETE in another tab. ``synchronous =
NORMAL`` is the WAL-mode recommended trade-off — safe against process
crashes, slightly weaker against full OS-level power loss; acceptable
for a single-machine end-user database.

The DB file is ``chmod 0600`` after creation (POSIX only) so the
bcrypt hashes are not readable by other local users on the host.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from cullis_connector.identity.users import Base

_log = logging.getLogger("cullis_connector.identity.users_db")

USERS_DB_FILENAME = "users.db"


# Per-config_dir engine cache. Each ConnectorConfig.config_dir maps to
# a single AsyncEngine for the lifetime of the process. This keeps
# WAL/journal connections warm and avoids the "database is locked"
# class of error from a fresh engine being spun up on every request.
_engines: dict[Path, AsyncEngine] = {}


def _users_db_path(config_dir: Path) -> Path:
    return Path(config_dir) / USERS_DB_FILENAME


def _users_engine(config_dir: Path) -> AsyncEngine:
    """Return (creating if needed) the cached AsyncEngine for ``config_dir``."""
    key = Path(config_dir).resolve()
    engine = _engines.get(key)
    if engine is not None:
        return engine

    Path(config_dir).mkdir(parents=True, exist_ok=True)
    db_path = _users_db_path(config_dir)
    url = f"sqlite+aiosqlite:///{db_path}"
    engine = create_async_engine(url, echo=False, future=True)

    # Apply WAL + synchronous=NORMAL on every fresh aiosqlite connection.
    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_conn, _connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()

    _engines[key] = engine
    return engine


async def init_users_db(config_dir: Path) -> None:
    """Create the schema if missing and enforce 0600 perms on the DB file.

    Idempotent — calling it twice on the same config_dir is safe.
    """
    engine = _users_engine(config_dir)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    db_path = _users_db_path(config_dir)
    _enforce_db_perms(db_path)


def _enforce_db_perms(db_path: Path) -> None:
    """Best-effort chmod 0600 on the users.db file (POSIX only).

    bcrypt hashes are not catastrophic if leaked but they are still
    a credential — let's not leave them group/world readable.
    """
    if os.name != "posix":
        return
    try:
        if db_path.exists():
            os.chmod(db_path, 0o600)
    except OSError as exc:
        _log.warning(
            "could not chmod 0600 %s: %s (continuing)", db_path, exc,
        )


@asynccontextmanager
async def get_users_session(
    config_dir: Path,
) -> AsyncIterator[AsyncSession]:
    """Async context manager yielding a transactional session.

    Lazily initialises the schema on first use, so callers (router
    handlers, tests) do not need to remember to call
    :func:`init_users_db` themselves. Each enter/exit pair commits on
    clean exit and rolls back on exception, mirroring SQLAlchemy's
    ``AsyncSession`` recommended idiom.
    """
    await init_users_db(config_dir)
    engine = _users_engine(config_dir)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_users_engines() -> None:
    """Tear down all cached engines — used by tests for isolation."""
    while _engines:
        _, engine = _engines.popitem()
        await engine.dispose()
