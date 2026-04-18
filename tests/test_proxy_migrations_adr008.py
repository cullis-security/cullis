"""Validate proxy Alembic migration 0008 — ADR-008 Phase 1 PR #1.

Schema extension of ``local_messages`` for sessionless one-shot
messaging: nullable ``session_id``, new ``is_oneshot`` /
``correlation_id`` / ``reply_to_correlation_id`` columns, and the
two supporting indexes.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, insert, select
from sqlalchemy.exc import IntegrityError

from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.db_models import LocalMessage

HEAD_REVISION = "0017_internal_agents_reach"
PREVIOUS_REVISION = "0007_mcp_resources"


def _columns(path: str, table: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
    return {r[1] for r in rows}


def _column_nullable(path: str, table: str, col: str) -> bool:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
    for cid, name, _type, notnull, _dflt, _pk in rows:
        if name == col:
            return notnull == 0
    raise KeyError(f"column {col} not found on {table}")


def _index_names(path: str, table: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=?",
            (table,),
        ).fetchall()
    finally:
        conn.close()
    return {r[0] for r in rows}


def _alembic_cfg(url: str) -> AlembicConfig:
    ini = Path(__file__).resolve().parents[1] / "mcp_proxy" / "alembic.ini"
    cfg = AlembicConfig(str(ini))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


@pytest.mark.asyncio
async def test_migration_0008_upgrade_adds_columns(tmp_path):
    db_file = tmp_path / "0008_up.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    cols = _columns(str(db_file), "local_messages")
    assert "is_oneshot" in cols
    assert "correlation_id" in cols
    assert "reply_to_correlation_id" in cols

    conn = sqlite3.connect(str(db_file))
    try:
        version = conn.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
    finally:
        conn.close()
    assert version == (HEAD_REVISION,)


@pytest.mark.asyncio
async def test_migration_0008_makes_session_id_nullable(tmp_path):
    db_file = tmp_path / "0008_null.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    assert _column_nullable(str(db_file), "local_messages", "session_id") is True


@pytest.mark.asyncio
async def test_migration_0008_creates_expected_indexes(tmp_path):
    db_file = tmp_path / "0008_idx.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    idx = _index_names(str(db_file), "local_messages")
    assert "idx_local_messages_correlation" in idx
    assert "idx_local_messages_recipient_oneshot" in idx
    # Legacy indexes still present
    assert "idx_local_messages_session" in idx


def test_migration_0008_downgrade_restores_schema(tmp_path):
    """Sync test — downgrade drops the one-shot columns + reflips nullable."""
    db_file = tmp_path / "0008_down.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"

    cfg = _alembic_cfg(async_url)
    command.upgrade(cfg, "head")

    assert "is_oneshot" in _columns(str(db_file), "local_messages")

    command.downgrade(cfg, PREVIOUS_REVISION)

    cols_after = _columns(str(db_file), "local_messages")
    assert "is_oneshot" not in cols_after
    assert "correlation_id" not in cols_after
    assert "reply_to_correlation_id" not in cols_after
    # session_id back to NOT NULL.
    assert _column_nullable(str(db_file), "local_messages", "session_id") is False


@pytest.mark.asyncio
async def test_oneshot_roundtrip(tmp_path):
    db_file = tmp_path / "oneshot_rt.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    engine = create_engine(f"sqlite:///{db_file}", future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                insert(LocalMessage).values(
                    msg_id="m-1",
                    session_id=None,
                    sender_agent_id="acme::a",
                    recipient_agent_id="acme::b",
                    payload_ciphertext="{}",
                    enqueued_at="2026-04-16T10:00:00Z",
                    is_oneshot=1,
                    correlation_id="c-1",
                    reply_to_correlation_id=None,
                )
            )
        with engine.connect() as conn:
            row = conn.execute(select(LocalMessage)).one()
    finally:
        engine.dispose()

    assert row.session_id is None
    assert row.is_oneshot == 1
    assert row.correlation_id == "c-1"
    assert row.reply_to_correlation_id is None


@pytest.mark.asyncio
async def test_null_multicolumn_unique_allows_multiple_oneshot_rows(tmp_path):
    """Two one-shot rows share (session_id=NULL, seq=NULL); the UNIQUE
    on (session_id, seq) must still accept both because NULLs are
    distinct in multicolumn UNIQUE indexes on SQLite + Postgres.
    """
    db_file = tmp_path / "null_uq.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    engine = create_engine(f"sqlite:///{db_file}", future=True)
    try:
        with engine.begin() as conn:
            for i in range(3):
                conn.execute(
                    insert(LocalMessage).values(
                        msg_id=f"m-{i}",
                        session_id=None,
                        sender_agent_id="acme::a",
                        recipient_agent_id="acme::b",
                        payload_ciphertext="{}",
                        enqueued_at="2026-04-16T10:00:00Z",
                        is_oneshot=1,
                        correlation_id=f"c-{i}",
                    )
                )
        with engine.connect() as conn:
            count = conn.execute(select(LocalMessage)).all()
    finally:
        engine.dispose()

    assert len(count) == 3


@pytest.mark.asyncio
async def test_session_rows_still_enforce_unique_seq(tmp_path):
    """Regression: two rows with the SAME (session_id, seq) must still
    collide — one-shot's NULL relaxation must not leak into session
    rows.
    """
    db_file = tmp_path / "session_uq.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    engine = create_engine(f"sqlite:///{db_file}", future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                insert(LocalMessage).values(
                    msg_id="m-1",
                    session_id="s-1",
                    seq=1,
                    sender_agent_id="acme::a",
                    recipient_agent_id="acme::b",
                    payload_ciphertext="{}",
                    enqueued_at="2026-04-16T10:00:00Z",
                )
            )
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(
                    insert(LocalMessage).values(
                        msg_id="m-2",
                        session_id="s-1",
                        seq=1,
                        sender_agent_id="acme::a",
                        recipient_agent_id="acme::c",
                        payload_ciphertext="{}",
                        enqueued_at="2026-04-16T10:00:01Z",
                    )
                )
    finally:
        engine.dispose()
