import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override sqlalchemy.url from DATABASE_URL env var if set
database_url = os.environ.get("DATABASE_URL")
if database_url:
    config.set_main_option("sqlalchemy.url", database_url)

# Import all models so that Base.metadata has the full schema.
# Each import registers the model's table in Base.metadata.
from app.db.database import Base  # noqa: E402
from app.auth.jti_blacklist import JtiBlacklist  # noqa: E402, F401
from app.auth.revocation import RevokedCert  # noqa: E402, F401
from app.broker.db_models import SessionRecord, SessionMessageRecord  # noqa: E402, F401
from app.broker.notifications import Notification  # noqa: E402, F401
from app.db.audit import AuditLog  # noqa: E402, F401
from app.policy.store import PolicyRecord  # noqa: E402, F401
from app.registry.binding_store import BindingRecord  # noqa: E402, F401
from app.registry.org_store import OrganizationRecord  # noqa: E402, F401
from app.registry.store import AgentRecord  # noqa: E402, F401

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
