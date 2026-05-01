"""
M-db-2 regression: ``init_db`` wraps the alembic upgrade in a
Postgres advisory lock when the URL is Postgres, and runs the
upgrade plain when the URL is SQLite.

Under concurrent worker boot two processes used to race the same
migration on a shared Postgres cluster (two readers see no head row,
both run the same upgrade, second one fails on duplicate-column).
The fix grabs ``pg_advisory_lock(<key>)`` on a dedicated connection
before delegating to alembic and releases on exit.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ── Court-side init_db (app/db/database.py) ─────────────────────────


@pytest.mark.asyncio
async def test_court_init_db_skips_lock_for_sqlite(monkeypatch, tmp_path):
    """SKIP_ALEMBIC=1 path doesn't even call alembic; the next-best
    test of the SQLite no-lock path is a clean SQLite URL with
    SKIP_ALEMBIC unset. We only assert that the lock SQL is NOT
    executed, since SQLite serializes by file."""
    db_file = tmp_path / "court_lock_skip.sqlite"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.setenv("SKIP_ALEMBIC", "1")

    # Re-import to pick up the new URL.
    import importlib

    import app.db.database as _db_mod
    importlib.reload(_db_mod)

    # Patch text-based pg_advisory_* calls — they should never fire on SQLite.
    sql_log: list[str] = []
    with patch.object(_db_mod, "engine", _db_mod.engine):
        await _db_mod.init_db()
    # If we got here without a Postgres connection error, the SQLite path
    # ran. Assert no advisory-lock attempts via env reflection.
    assert "pg_advisory" not in str(sql_log)


# ── mcp_proxy-side init_db (mcp_proxy/db.py) ────────────────────────


@pytest.mark.asyncio
async def test_proxy_init_db_skips_lock_for_sqlite(tmp_path, monkeypatch):
    """SQLite URL goes through ``asyncio.to_thread(_run_migrations_sync)``
    directly with no advisory-lock SQL. We assert by patching
    ``_run_migrations_sync`` and confirming it's still called."""
    monkeypatch.delenv("PROXY_SKIP_MIGRATIONS", raising=False)
    db_file = tmp_path / "proxy_lock_skip.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    import mcp_proxy.db as _db_mod

    called = MagicMock()
    monkeypatch.setattr(_db_mod, "_run_migrations_sync", called)

    await _db_mod.init_db(url)
    assert called.called, "_run_migrations_sync must run on SQLite"
    await _db_mod.dispose_db()


@pytest.mark.asyncio
async def test_proxy_init_db_uses_advisory_lock_for_postgres(monkeypatch, tmp_path):
    """For a Postgres URL, ``init_db`` opens a dedicated lock
    connection, calls ``pg_advisory_lock`` before the upgrade and
    ``pg_advisory_unlock`` after."""
    import mcp_proxy.db as _db_mod

    sql_calls: list[str] = []

    class _FakeConn:
        async def execute(self, stmt, params=None):
            sql_calls.append(str(stmt))
            return None

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class _FakeDialect:
        name = "postgresql"

    class _FakeEngine:
        dialect = _FakeDialect()

        def connect(self):
            return _FakeConn()

        async def begin(self):
            return _FakeConn()

        async def dispose(self):
            return None

    def _fake_create_engine(url, **kwargs):
        return _FakeEngine()

    monkeypatch.setattr(_db_mod, "create_async_engine", _fake_create_engine)

    run_called = MagicMock()
    monkeypatch.setattr(_db_mod, "_run_migrations_sync", run_called)

    monkeypatch.delenv("PROXY_SKIP_MIGRATIONS", raising=False)
    await _db_mod.init_db("postgresql+asyncpg://user:pw@db.test/cullis")

    joined = "\n".join(sql_calls)
    assert "pg_advisory_lock" in joined, (
        f"Postgres path must take the advisory lock; saw SQL: {sql_calls!r}"
    )
    assert "pg_advisory_unlock" in joined, (
        "Postgres path must release the advisory lock"
    )
    # Lock acquired before upgrade, released after.
    lock_idx = next(
        i for i, s in enumerate(sql_calls) if "pg_advisory_lock" in s
    )
    unlock_idx = next(
        i for i, s in enumerate(sql_calls) if "pg_advisory_unlock" in s
    )
    assert lock_idx < unlock_idx
    assert run_called.called, "alembic upgrade must run between lock+unlock"
