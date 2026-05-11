"""Async SQLite engine + session factory for the conversations store.

Mirrors ``cullis_connector.identity.users_db`` byte-for-byte on the
caching + WAL + chmod logic so the two stores behave identically
under pytest-asyncio (per-loop engine cache) and on disk (0600 file
mode, WAL journal).
"""
from __future__ import annotations

import asyncio
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

from cullis_connector.conversations.models import Base

_log = logging.getLogger("cullis_connector.conversations.db")

CONVERSATIONS_DB_FILENAME = "conversations.db"

_engines: dict[tuple[Path, int], AsyncEngine] = {}


def _current_loop_key() -> int:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return 0
    return id(loop)


def _db_path(config_dir: Path) -> Path:
    return Path(config_dir) / CONVERSATIONS_DB_FILENAME


def _engine(config_dir: Path) -> AsyncEngine:
    key = (Path(config_dir).resolve(), _current_loop_key())
    engine = _engines.get(key)
    if engine is not None:
        return engine

    Path(config_dir).mkdir(parents=True, exist_ok=True)
    url = f"sqlite+aiosqlite:///{_db_path(config_dir)}"
    engine = create_async_engine(url, echo=False, future=True)

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_conn, _connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    _engines[key] = engine
    return engine


async def init_conversations_db(config_dir: Path) -> None:
    """Create the schema if missing, enforce 0600 perms (POSIX only).
    Idempotent on repeat calls."""
    engine = _engine(config_dir)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    _enforce_db_perms(_db_path(config_dir))


def _enforce_db_perms(db_path: Path) -> None:
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
async def get_session(config_dir: Path) -> AsyncIterator[AsyncSession]:
    """Async context manager yielding a transactional session.

    Lazily initialises the schema on first use, so router handlers do
    not need to call :func:`init_conversations_db` explicitly.
    """
    await init_conversations_db(config_dir)
    engine = _engine(config_dir)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engines() -> None:
    """Test helper: tear down every cached engine. Only awaits engines
    bound to the current loop; engines bound to a previous (closed)
    loop are dropped without awaiting to avoid 'no current event loop'
    errors during teardown."""
    current = _current_loop_key()
    keys = list(_engines.keys())
    for key in keys:
        engine = _engines.pop(key, None)
        if engine is None:
            continue
        _, loop_id = key
        if loop_id == current and current != 0:
            try:
                await engine.dispose()
            except Exception:
                pass
