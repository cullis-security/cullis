"""Validate proxy Alembic migration 0016 — ADR-011 Phase 1 enrollment metadata.

Covers:
- Fresh deploy: columns present, head revision stamped.
- Upgrade over pre-0016 SQLite: legacy row survives and is backfilled
  with ``enrollment_method='admin'`` and ``enrolled_at=created_at``.
- Downgrade drops the three new columns cleanly.
- ``db.create_agent`` writes the new columns with the expected defaults.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig

from mcp_proxy.db import create_agent, dispose_db, init_db

HEAD_REVISION = "0023_audit_hash_chain"
PREVIOUS_REVISION = "0015_enrollment_dpop_jkt"
NEW_COLUMNS = {"enrollment_method", "spiffe_id", "enrolled_at"}


def _columns(path: str, table: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
    return {r[1] for r in rows}


def _alembic_cfg(url: str) -> AlembicConfig:
    ini = Path(__file__).resolve().parents[1] / "mcp_proxy" / "alembic.ini"
    cfg = AlembicConfig(str(ini))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


@pytest.mark.asyncio
async def test_migration_0016_upgrade_adds_columns(tmp_path):
    db_file = tmp_path / "0016_up.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    cols = _columns(str(db_file), "internal_agents")
    assert NEW_COLUMNS.issubset(cols), f"missing: {NEW_COLUMNS - cols}"

    conn = sqlite3.connect(str(db_file))
    try:
        version = conn.execute("SELECT version_num FROM alembic_version").fetchone()
    finally:
        conn.close()
    assert version == (HEAD_REVISION,)


def test_migration_0016_backfills_existing_rows(tmp_path):
    """Legacy row carried from the 0015 schema gets admin/created_at backfill.

    Sync so ``command.upgrade`` can drive its own asyncio loop without
    clashing with pytest-asyncio (see 0008 downgrade test).
    """
    db_file = tmp_path / "0016_backfill.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    cfg = _alembic_cfg(async_url)

    # Stamp at the previous head and insert a row in the pre-0016 shape.
    command.upgrade(cfg, PREVIOUS_REVISION)
    conn = sqlite3.connect(str(db_file))
    try:
        # Pre-0022 schema still has the NOT NULL ``api_key_hash``
        # column; we're stamped at 0015 here and exercising the 0016
        # backfill path. The 0022 migration drops the column later
        # (and rebuilds the row), so the placeholder hash never
        # survives the upgrade chain.
        conn.execute(
            """INSERT INTO internal_agents
               (agent_id, display_name, capabilities, api_key_hash,
                created_at, is_active)
               VALUES (?, ?, '[]', 'h', ?, 1)""",
            ("orga::legacy", "Legacy Bot", "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()
    finally:
        conn.close()

    # Upgrade to head — triggers the backfill statements in 0016.
    command.upgrade(cfg, "head")

    conn = sqlite3.connect(str(db_file))
    try:
        row = conn.execute(
            """SELECT enrollment_method, enrolled_at, spiffe_id, created_at
               FROM internal_agents WHERE agent_id = ?""",
            ("orga::legacy",),
        ).fetchone()
    finally:
        conn.close()

    method, enrolled_at, spiffe_id, created_at = row
    assert method == "admin"
    assert enrolled_at == created_at  # §7.3 of ADR-011
    assert spiffe_id is None  # legacy rows had no SPIFFE ID


def test_migration_0016_downgrade_drops_new_columns(tmp_path):
    """Sync — command.downgrade drives its own event loop."""
    db_file = tmp_path / "0016_down.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    cfg = _alembic_cfg(async_url)

    command.upgrade(cfg, "head")
    assert NEW_COLUMNS.issubset(_columns(str(db_file), "internal_agents"))

    command.downgrade(cfg, PREVIOUS_REVISION)
    cols = _columns(str(db_file), "internal_agents")
    assert NEW_COLUMNS.isdisjoint(cols), (
        f"downgrade left new columns behind: {NEW_COLUMNS & cols}"
    )


@pytest.mark.asyncio
async def test_create_agent_helper_writes_enrollment_metadata(tmp_path):
    """``db.create_agent`` defaults to ``admin`` and populates enrolled_at."""
    db_file = tmp_path / "create.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(async_url)

    try:
        await create_agent(
            agent_id="orga::test",
            display_name="Test",
            capabilities=["sandbox.read"],
        )
        await create_agent(
            agent_id="orga::spiffe-test",
            display_name="SPIFFE Test",
            capabilities=[],
            enrollment_method="spiffe",
            spiffe_id="spiffe://orga.test/spiffe-test",
        )
    finally:
        await dispose_db()

    conn = sqlite3.connect(str(db_file))
    try:
        default_row = conn.execute(
            """SELECT enrollment_method, spiffe_id, enrolled_at, created_at
               FROM internal_agents WHERE agent_id = ?""",
            ("orga::test",),
        ).fetchone()
        spiffe_row = conn.execute(
            """SELECT enrollment_method, spiffe_id
               FROM internal_agents WHERE agent_id = ?""",
            ("orga::spiffe-test",),
        ).fetchone()
    finally:
        conn.close()

    method, sid, enrolled_at, created_at = default_row
    assert method == "admin"
    assert sid is None
    assert enrolled_at == created_at  # helper sets both to the same ts

    assert spiffe_row == ("spiffe", "spiffe://orga.test/spiffe-test")
