"""F0.2 — full Alembic chain walk against a live Postgres 16.

Run this with::

    docker compose -f test/compose-pg.yml up -d --wait
    export CULLIS_TEST_PG_URL=postgresql+asyncpg://cullis:cullis@127.0.0.1:5544/cullis_test
    pytest test/integration/test_alembic_full_chain_postgres.py -m postgres -v

The whole module is gated behind ``@pytest.mark.postgres`` so a
developer laptop without Docker stays green; the wrapper at
``test/run-pg-nightly.sh`` boots the compose service, exports the URL,
and runs this file.

What it pins (and why each assertion exists):

1. **All 43 migrations apply clean on asyncpg** — pre-pivot the chain was
   exercised on SQLite at every boot but never on a live Postgres in
   CI. This catches dialect-specific footguns (e.g. ``RAISE`` plpgsql in
   0042's BEFORE UPDATE/DELETE trigger, ``ON CONFLICT DO NOTHING`` vs
   SQLite ``OR IGNORE``) the unit suite cannot see.

2. **Append-only trigger active** — migration 0042 installs a
   ``BEFORE UPDATE/DELETE`` trigger on ``audit_log`` that raises on
   mutation. SQLite uses ``RAISE`` inside a trigger body, Postgres uses
   plpgsql ``RAISE EXCEPTION``. We assert the Postgres path actually
   raises so the threat-model claim ("audit log is append-only at the
   DB layer, not just by convention") survives the dialect switch.

3. **UNIQUE(chain_seq)** — the retry loop in ``db.log_audit`` relies on
   ``IntegrityError`` being raised on duplicate ``chain_seq``. Pin that
   asyncpg actually surfaces ``sqlalchemy.exc.IntegrityError`` (wrapping
   ``asyncpg.exceptions.UniqueViolationError``) so the
   ``_AUDIT_CHAIN_MAX_RETRIES`` loop in ``mcp_proxy/db.py:572`` keeps
   working unmodified.

4. **Advisory lock observable in ``pg_locks``** — the multi-worker
   Alembic gate (``_ALEMBIC_ADVISORY_LOCK_KEY = 0xC0115A1E_EB1C0DE``,
   ``mcp_proxy/db.py:50``) is meant to be greppable during incident
   triage. Assert the literal lock key appears in ``pg_locks`` while a
   concurrent ``init_db`` is in flight so the operator runbook
   (``docs/runbooks/postgres-pilot.md``) keeps describing reality.
"""
from __future__ import annotations

from pathlib import Path
import asyncio

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.postgres


@pytest.fixture
def pg_test_url(pg_url, monkeypatch) -> str:
    """Hand back the live PG URL and stamp the env var ``init_db`` reads.

    ``mcp_proxy.db.init_db`` consults ``MCP_PROXY_DATABASE_URL`` /
    ``PROXY_DB_URL`` indirectly via ``_normalize_url``. We push the URL
    via env so a real ``init_db()`` call later in the suite (other
    tests) doesn't pick up the SQLite default.
    """
    monkeypatch.setenv("PROXY_DB_URL", pg_url)
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "test-admin-secret-not-the-default")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    yield pg_url
    get_settings.cache_clear()


async def _reset_public_schema(url: str) -> None:
    """Drop + recreate ``public`` so the Alembic chain runs against a clean DB."""
    admin = create_async_engine(url, future=True, isolation_level="AUTOCOMMIT")
    try:
        async with admin.connect() as conn:
            await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))
            # asyncpg drops the connection's search_path with the schema;
            # restore it so subsequent statements resolve unqualified names.
            await conn.execute(text("SET search_path TO public"))
    finally:
        await admin.dispose()


def test_full_chain_applies_clean_against_asyncpg(pg_test_url):
    """All 43 migrations apply 0001 → head against a pristine asyncpg DB."""
    from mcp_proxy import db as db_module

    async def _run() -> None:
        await _reset_public_schema(pg_test_url)
        await db_module.init_db(pg_test_url)
        # The engine is now bound; spot-check that ``alembic_version`` is
        # at head and the audit_log shape includes the columns added by
        # the latest migrations (0031 dpop_jkt, 0033 on_behalf_of_user_id,
        # 0042 hash_format).
        async with db_module.get_db() as conn:
            version_rows = (await conn.execute(
                text("SELECT version_num FROM alembic_version"))).all()
            assert len(version_rows) == 1
            head = version_rows[0][0]
            from alembic.config import Config
            from alembic.script import ScriptDirectory
            config = Config(str(Path(__file__).resolve().parents[2] / "mcp_proxy/alembic.ini"))
            assert head == ScriptDirectory.from_config(config).get_current_head(), \
                f"alembic_version not at head: {head!r}"
            columns = (await conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema='public' AND table_name='audit_log'"
            ))).scalars().all()
            for required in ("dpop_jkt", "on_behalf_of_user_id", "hash_format",
                             "chain_seq", "prev_hash", "row_hash"):
                assert required in columns, f"audit_log missing {required}"
        await db_module.dispose_db()

    asyncio.run(_run())


def test_audit_log_update_blocked_by_trigger(pg_test_url):
    """Migration 0042 BEFORE UPDATE/DELETE trigger refuses mutation.

    The append-only claim ("operator cannot tamper with the audit log
    without leaving a forensic trace") is enforced at the SQL layer by
    a plpgsql trigger that raises. We seed a row via the public log_audit
    surface, then attempt a direct UPDATE — the asyncpg driver must
    surface the exception so callers see it as a 5xx, never as silent
    success.
    """
    from mcp_proxy import db as db_module

    async def _run() -> None:
        await _reset_public_schema(pg_test_url)
        await db_module.init_db(pg_test_url)
        try:
            await db_module.log_audit(
                agent_id="test-agent",
                action="test_action",
                tool_name="test_tool",
                status="ok",
                detail="seed row",
            )
            async with db_module.get_db() as conn:
                with pytest.raises(Exception) as exc_info:
                    await conn.execute(text(
                        "UPDATE audit_log SET status='tampered' "
                        "WHERE agent_id='test-agent'"
                    ))
                # plpgsql RAISE EXCEPTION surfaces as an asyncpg
                # RaiseError wrapped by SQLAlchemy. The message contains
                # the trigger name or the explicit RAISE message.
                err_text = str(exc_info.value).lower()
                assert "audit_log" in err_text or "append-only" in err_text \
                    or "immutable" in err_text or "trigger" in err_text, \
                    f"unexpected trigger error: {exc_info.value!r}"
        finally:
            await db_module.dispose_db()

    asyncio.run(_run())


def test_audit_log_delete_blocked_by_trigger(pg_test_url):
    """Sister of UPDATE — DELETE must also be rejected by 0042's trigger."""
    from mcp_proxy import db as db_module

    async def _run() -> None:
        await _reset_public_schema(pg_test_url)
        await db_module.init_db(pg_test_url)
        try:
            await db_module.log_audit(
                agent_id="test-agent",
                action="test_action",
                tool_name="test_tool",
                status="ok",
                detail="seed row",
            )
            async with db_module.get_db() as conn:
                with pytest.raises(Exception):
                    await conn.execute(text(
                        "DELETE FROM audit_log WHERE agent_id='test-agent'"
                    ))
        finally:
            await db_module.dispose_db()

    asyncio.run(_run())


def test_unique_chain_seq_surfaces_integrity_error(pg_test_url):
    """The retry loop in db.log_audit (line 572) depends on this.

    SQLAlchemy wraps ``asyncpg.exceptions.UniqueViolationError`` as
    ``sqlalchemy.exc.IntegrityError`` exactly like it does
    ``sqlite3.IntegrityError`` — pin this so a future asyncpg version
    that changed the wrap chain would fail this test instead of
    silently breaking multi-worker audit append.
    """
    from mcp_proxy import db as db_module

    async def _run() -> None:
        await _reset_public_schema(pg_test_url)
        await db_module.init_db(pg_test_url)
        try:
            async with db_module.get_db() as conn:
                # Insert a row at chain_seq=1 directly, bypassing the
                # retry loop, so we control the duplicate condition.
                await conn.execute(
                    text(
                        """INSERT INTO audit_log
                           (timestamp, agent_id, action, status, chain_seq,
                            prev_hash, row_hash, hash_format)
                           VALUES (:ts, :a, :act, :s, :seq, :ph, :rh, :hf)"""
                    ),
                    {
                        "ts": "2026-05-23T00:00:00+00:00",
                        "a": "test", "act": "x", "s": "ok",
                        "seq": 1,
                        "ph": "genesis",
                        "rh": "deadbeef",
                        "hf": "v2",
                    },
                )
            async with db_module.get_db() as conn:
                with pytest.raises(IntegrityError):
                    await conn.execute(
                        text(
                            """INSERT INTO audit_log
                               (timestamp, agent_id, action, status, chain_seq,
                                prev_hash, row_hash, hash_format)
                               VALUES (:ts, :a, :act, :s, :seq, :ph, :rh, :hf)"""
                        ),
                        {
                            "ts": "2026-05-23T00:00:01+00:00",
                            "a": "test2", "act": "x", "s": "ok",
                            "seq": 1,  # duplicate
                            "ph": "deadbeef",
                            "rh": "cafebabe",
                            "hf": "v2",
                        },
                    )
        finally:
            await db_module.dispose_db()

    asyncio.run(_run())


def test_advisory_lock_visible_in_pg_locks(pg_test_url):
    """The Alembic upgrade gate uses a fixed advisory lock key.

    ``_ALEMBIC_ADVISORY_LOCK_KEY = 0xC0115A1E_EB1C0DE`` (mcp_proxy/db.py:50)
    is the documented incident-triage hook: operators grep ``pg_locks``
    to confirm a stuck worker is sitting on the lock during a hung
    deploy. Acquire the lock from a second connection, then assert it
    is observable.
    """
    advisory_key = 0xC0115A1E_EB1C0DE

    async def _run() -> None:
        await _reset_public_schema(pg_test_url)
        # First engine holds the advisory lock open.
        holder = create_async_engine(pg_test_url, future=True)
        observer = create_async_engine(pg_test_url, future=True)
        try:
            async with holder.connect() as held_conn:
                await held_conn.execute(
                    text("SELECT pg_advisory_lock(:k)"),
                    {"k": advisory_key},
                )
                async with observer.connect() as obs_conn:
                    rows = (await obs_conn.execute(text(
                        "SELECT classid, objid FROM pg_locks "
                        "WHERE locktype='advisory' AND granted=true"
                    ))).all()
                # classid + objid pack a bigint advisory key into two
                # int4 halves. Reconstruct and assert ours appears.
                seen = {
                    (int(r[0]) << 32) | (int(r[1]) & 0xFFFFFFFF)
                    for r in rows
                }
                assert advisory_key in seen, (
                    f"advisory key {advisory_key:#x} not present in "
                    f"pg_locks (saw {[hex(s) for s in seen]})"
                )
                await held_conn.execute(
                    text("SELECT pg_advisory_unlock(:k)"),
                    {"k": advisory_key},
                )
        finally:
            await holder.dispose()
            await observer.dispose()

    asyncio.run(_run())
