"""Validate proxy Alembic bootstrap (ADR-001 Phase 1.3).

Covers the three startup paths:
- Fresh DB: alembic upgrade head creates every table.
- Legacy SQLite (pre-Phase-1 schema, no alembic_version): stamped at
  0001_initial_snapshot, then upgraded; existing rows survive.
- Postgres: same upgrade chain runs cleanly. Skipped unless
  TEST_POSTGRES_URL is set, mirroring tests/test_postgres_integration.py.
"""
from __future__ import annotations

import os
import sqlite3

import pytest
from sqlalchemy import create_engine, inspect

from mcp_proxy.db import dispose_db, init_db

EXPECTED_TABLES = {
    "internal_agents",
    "audit_log",
    "proxy_config",
    "local_sessions",
    "local_messages",
    "local_policies",
    "local_audit",
    "local_mcp_resources",
    "local_agent_resource_bindings",
    "pending_enrollments",
    "cached_federated_agents",
    "cached_policies",
    "cached_bindings",
    "federation_cursor",
    "mastio_keys",
    "pending_updates",
    "migration_state_backups",
    "agent_traffic_samples",
    "agent_hourly_baselines",
    "agent_quarantine_events",
    "alembic_version",
}


def _table_names_sqlite(path: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        conn.close()
    return {r[0] for r in rows}


@pytest.mark.asyncio
async def test_init_db_fresh_sqlite_runs_alembic_upgrade(tmp_path):
    db_file = tmp_path / "fresh.db"
    url = f"sqlite+aiosqlite:///{db_file}"

    await init_db(url)
    await dispose_db()

    tables = _table_names_sqlite(str(db_file))
    assert EXPECTED_TABLES.issubset(tables), (
        f"missing tables after upgrade: {EXPECTED_TABLES - tables}"
    )

    # alembic_version contains the head revision.
    conn = sqlite3.connect(str(db_file))
    try:
        rows = conn.execute("SELECT version_num FROM alembic_version").fetchall()
    finally:
        conn.close()
    assert rows == [("0023_audit_hash_chain",)]


@pytest.mark.asyncio
async def test_init_db_stamps_legacy_sqlite_then_upgrades(tmp_path):
    db_file = tmp_path / "legacy.db"

    # Seed the pre-Phase-1 schema (matches the old _SCHEMA_SQL byte for byte)
    # and a row that must survive the upgrade.
    seed = sqlite3.connect(str(db_file))
    try:
        seed.executescript(
            """
            CREATE TABLE IF NOT EXISTS internal_agents (
                agent_id TEXT PRIMARY KEY, display_name TEXT NOT NULL,
                capabilities TEXT NOT NULL DEFAULT '[]', api_key_hash TEXT NOT NULL,
                cert_pem TEXT, created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL, action TEXT NOT NULL, tool_name TEXT,
                status TEXT NOT NULL, detail TEXT, request_id TEXT,
                duration_ms REAL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_agent_id ON audit_log(agent_id);
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_log_request_id ON audit_log(request_id);
            CREATE TABLE IF NOT EXISTS proxy_config (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            """
        )
        seed.execute(
            "INSERT INTO internal_agents VALUES "
            "('legacy-agent','Legacy Agent','[]','hash',NULL,'2026-04-13',1)"
        )
        seed.commit()
    finally:
        seed.close()

    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    tables = _table_names_sqlite(str(db_file))
    assert EXPECTED_TABLES.issubset(tables)

    conn = sqlite3.connect(str(db_file))
    try:
        rows = conn.execute(
            "SELECT agent_id FROM internal_agents WHERE agent_id='legacy-agent'"
        ).fetchall()
        version = conn.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchall()
    finally:
        conn.close()

    assert rows == [("legacy-agent",)], "pre-existing row lost during stamp+upgrade"
    assert version == [("0023_audit_hash_chain",)]


@pytest.mark.asyncio
async def test_init_db_stamps_seed_only_proxy_config(tmp_path):
    """Smoke / proxy-init scenario: only proxy_config exists pre-boot.

    The demo_network proxy-init container writes broker uplink config rows
    to a fresh DB before the proxy starts. Alembic stamping must trigger
    on ANY legacy table presence, not just internal_agents — otherwise
    the upgrade tries to CREATE TABLE proxy_config on top of itself.
    """
    db_file = tmp_path / "seeded.db"
    seed = sqlite3.connect(str(db_file))
    try:
        seed.executescript(
            """
            CREATE TABLE IF NOT EXISTS proxy_config (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            """
        )
        seed.execute(
            "INSERT INTO proxy_config (key, value) VALUES ('broker_url', 'https://b.test')"
        )
        seed.commit()
    finally:
        seed.close()

    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    tables = _table_names_sqlite(str(db_file))
    assert EXPECTED_TABLES.issubset(tables)

    conn = sqlite3.connect(str(db_file))
    try:
        rows = conn.execute(
            "SELECT value FROM proxy_config WHERE key='broker_url'"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [("https://b.test",)], "seeded config row lost during stamp+upgrade"


@pytest.mark.asyncio
async def test_proxy_db_url_env_overrides_settings(monkeypatch, tmp_path):
    """PROXY_DB_URL beats MCP_PROXY_DATABASE_URL — Phase 1.3 contract."""
    from mcp_proxy.config import ProxySettings

    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", "sqlite+aiosqlite:///legacy.db")
    monkeypatch.setenv("PROXY_DB_URL", f"sqlite+aiosqlite:///{tmp_path / 'override.db'}")

    settings = ProxySettings()
    assert settings.database_url.endswith("override.db")


def _column_names_sqlite(path: str, table: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
    return {r[1] for r in rows}


@pytest.mark.asyncio
async def test_schema_parity_with_broker_columns_present(tmp_path):
    """ADR-006 Fase 0: local_* tables must carry broker-parity columns."""
    db_file = tmp_path / "parity.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    path = str(db_file)

    # ADR-010 Phase 6b dropped ``local_agents``; the remaining local_*
    # tables still need the ADR-006 schema-parity columns they gained in
    # migration 0005.
    sessions_cols = _column_names_sqlite(path, "local_sessions")
    assert {
        "target_agent_id",
        "initiator_org_id",
        "target_org_id",
        "requested_capabilities",
        "expires_at",
        "closed_at",
    }.issubset(sessions_cols)
    assert "responder_agent_id" not in sessions_cols

    messages_cols = _column_names_sqlite(path, "local_messages")
    assert {
        "seq",
        "nonce",
        "signature",
        "attempts",
        "expired_at",
        "delivery_status",
    }.issubset(messages_cols)
    assert "status" not in messages_cols

    policies_cols = _column_names_sqlite(path, "local_policies")
    assert {"org_id", "policy_type"}.issubset(policies_cols)

    audit_cols = _column_names_sqlite(path, "local_audit")
    assert {
        "event_type",
        "agent_id",
        "session_id",
        "org_id",
        "details",
        "result",
        "entry_hash",
        "previous_hash",
        "chain_seq",
        "peer_org_id",
        "peer_row_hash",
    }.issubset(audit_cols)
    assert "action" not in audit_cols
    assert "actor_agent_id" not in audit_cols
    assert "row_hash" not in audit_cols
    assert "prev_hash" not in audit_cols
    assert "detail_json" not in audit_cols
    assert "subject" not in audit_cols


@pytest.mark.skipif(
    not os.environ.get("TEST_POSTGRES_URL"),
    reason="TEST_POSTGRES_URL not set; skipping cross-dialect migration test",
)
@pytest.mark.asyncio
async def test_init_db_postgres_runs_alembic_upgrade():
    """Same upgrade chain runs cleanly on Postgres."""
    url = os.environ["TEST_POSTGRES_URL"]
    await init_db(url)
    await dispose_db()

    sync_url = url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
    sync_engine = create_engine(sync_url, future=True)
    try:
        with sync_engine.connect() as conn:
            tables = set(inspect(conn).get_table_names())
    finally:
        sync_engine.dispose()
    assert EXPECTED_TABLES.issubset(tables)
