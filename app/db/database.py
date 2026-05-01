import logging
import os

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import get_settings

logger = logging.getLogger("agent_trust")
settings = get_settings()

engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


# M-db-2 audit fix — Postgres advisory lock key for alembic upgrade
# serialization. The integer is arbitrary but stable; choose anything
# that won't collide with operator-defined locks. ``0xCULL15A1emb`` ≈
# "Cullis alembic" — a memorable hex constant operators can grep in
# pg_locks during incident triage.
_ALEMBIC_ADVISORY_LOCK_KEY = 0xC0115A1E_EB1C0DE


async def init_db() -> None:
    """Run Alembic migrations to head.

    Falls back to metadata.create_all when SKIP_ALEMBIC is set (used by
    tests that run on ephemeral in-memory SQLite databases).

    M-db-2 audit fix: under N concurrent uvicorn/gunicorn workers (or
    N kubernetes replicas booting at once), each one used to call
    ``command.upgrade(cfg, "head")`` against the shared Postgres
    cluster. Two workers reading ``alembic_version`` before either
    one wrote the next revision could race the same migration and
    fail with duplicate-column / duplicate-table errors, leaving the
    cluster in a half-migrated state. We now wrap the upgrade in a
    Postgres session-level advisory lock keyed by a fixed integer:
    only one worker runs the migration, the rest wait then no-op
    once head is reached. SQLite is single-writer by file, so the
    lock is skipped there.
    """
    if os.environ.get("SKIP_ALEMBIC"):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return

    import asyncio

    def _run_alembic():
        from alembic.config import Config
        from alembic import command
        alembic_cfg = Config(os.path.join(os.path.dirname(__file__), "..", "..", "alembic.ini"))
        alembic_cfg.set_main_option("sqlalchemy.url", str(engine.url))
        command.upgrade(alembic_cfg, "head")

    url = str(engine.url)
    is_postgres = url.startswith("postgresql") or "+asyncpg" in url

    if is_postgres:
        # Hold the lock on a dedicated connection so the alembic
        # subprocess (which opens its own conn) doesn't deadlock
        # against itself. Using a session-level advisory lock so it
        # survives across statements; release explicitly on exit.
        from sqlalchemy import text as _text

        async with engine.connect() as lock_conn:
            await lock_conn.execute(
                _text("SELECT pg_advisory_lock(:k)"),
                {"k": _ALEMBIC_ADVISORY_LOCK_KEY},
            )
            try:
                await asyncio.to_thread(_run_alembic)
            finally:
                await lock_conn.execute(
                    _text("SELECT pg_advisory_unlock(:k)"),
                    {"k": _ALEMBIC_ADVISORY_LOCK_KEY},
                )
    else:
        # SQLite (and ephemeral test DBs): single-writer at the file
        # level means concurrent alembic.upgrade calls against the
        # same DB serialize naturally. Skip the lock dance.
        await asyncio.to_thread(_run_alembic)
    logger.info("Alembic migrations applied (head)")
