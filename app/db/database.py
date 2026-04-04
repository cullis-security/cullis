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


async def init_db() -> None:
    """Run Alembic migrations to head.

    Falls back to metadata.create_all when SKIP_ALEMBIC is set (used by
    tests that run on ephemeral in-memory SQLite databases).
    """
    if os.environ.get("SKIP_ALEMBIC"):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return

    from alembic.config import Config
    from alembic import command

    alembic_cfg = Config(os.path.join(os.path.dirname(__file__), "..", "..", "alembic.ini"))
    alembic_cfg.set_main_option("sqlalchemy.url", str(engine.url))
    command.upgrade(alembic_cfg, "head")
    logger.info("Alembic migrations applied (head)")
