"""Validate proxy Alembic migration 0007 — ADR-007 Phase 1 PR #1.

Covers schema-only deployment of local_mcp_resources and
local_agent_resource_bindings. Upgrade/downgrade idempotency and model
round-trip via SQLAlchemy. Audit hash chain parity is NOT re-asserted
here — that contract is owned by tests/test_proxy_audit_chain_parity.py
which runs in the same suite and must stay green regardless.
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
from mcp_proxy.db_models import LocalAgentResourceBinding, LocalMCPResource

HEAD_REVISION = "0024_bindings_principal_type"
PREVIOUS_REVISION = "0006_enrollment_api_key_hash"


def _table_names(path: str) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        conn.close()
    return {r[0] for r in rows}


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
    """Build an Alembic config that points at *url* (async driver required).

    env.py wraps migrations in asyncio.run, so only async URLs work.
    """
    ini = Path(__file__).resolve().parents[1] / "mcp_proxy" / "alembic.ini"
    cfg = AlembicConfig(str(ini))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


@pytest.mark.asyncio
async def test_migration_0007_upgrade_creates_tables(tmp_path):
    db_file = tmp_path / "0007_up.db"
    url = f"sqlite+aiosqlite:///{db_file}"

    await init_db(url)
    await dispose_db()

    tables = _table_names(str(db_file))
    assert "local_mcp_resources" in tables
    assert "local_agent_resource_bindings" in tables

    conn = sqlite3.connect(str(db_file))
    try:
        version = conn.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
    finally:
        conn.close()
    assert version == (HEAD_REVISION,)


@pytest.mark.asyncio
async def test_migration_0007_creates_expected_indexes(tmp_path):
    db_file = tmp_path / "0007_idx.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()
    path = str(db_file)

    res_idx = _index_names(path, "local_mcp_resources")
    assert "idx_local_mcp_resources_org_enabled" in res_idx

    # SQLite materializes named UNIQUE constraints inside the CREATE TABLE
    # SQL (they surface as sqlite_autoindex_* in sqlite_master). Verify the
    # constraint name by probing the schema SQL directly.
    conn = sqlite3.connect(path)
    try:
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name='local_mcp_resources'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert "uq_local_mcp_resources_org_name" in sql
    assert "UNIQUE" in sql.upper()

    bind_idx = _index_names(path, "local_agent_resource_bindings")
    assert "idx_local_bindings_agent_revoked" in bind_idx
    assert "idx_local_bindings_resource_revoked" in bind_idx
    assert "idx_local_bindings_org" in bind_idx


def test_migration_0007_downgrade_removes_tables(tmp_path):
    """env.py runs via asyncio — pass the async driver URL to Alembic."""
    db_file = tmp_path / "0007_down.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"

    cfg = _alembic_cfg(async_url)
    command.upgrade(cfg, "head")

    tables_up = _table_names(str(db_file))
    assert "local_mcp_resources" in tables_up
    assert "local_agent_resource_bindings" in tables_up

    command.downgrade(cfg, PREVIOUS_REVISION)

    tables_down = _table_names(str(db_file))
    assert "local_mcp_resources" not in tables_down
    assert "local_agent_resource_bindings" not in tables_down

    # Previous schema intact.
    assert "local_agents" in tables_down
    assert "pending_enrollments" in tables_down

    conn = sqlite3.connect(str(db_file))
    try:
        version = conn.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
    finally:
        conn.close()
    assert version == (PREVIOUS_REVISION,)


@pytest.mark.asyncio
async def test_local_mcp_resource_roundtrip(tmp_path):
    db_file = tmp_path / "resource_rt.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    engine = create_engine(f"sqlite:///{db_file}", future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                insert(LocalMCPResource).values(
                    resource_id="res-001",
                    org_id="acme",
                    name="postgres-prod",
                    description="Primary Postgres MCP",
                    endpoint_url="http://postgres-mcp:8080",
                    auth_type="bearer",
                    auth_secret_ref="vault:kv/proxy/postgres",
                    required_capability="sql.read",
                    allowed_domains='["postgres-mcp:8080"]',
                    created_at="2026-04-16T10:00:00Z",
                    updated_at="2026-04-16T10:00:00Z",
                )
            )
        with engine.connect() as conn:
            rows = list(conn.execute(select(LocalMCPResource)))
    finally:
        engine.dispose()

    assert len(rows) == 1
    row = rows[0]
    assert row.resource_id == "res-001"
    assert row.auth_type == "bearer"
    assert row.enabled == 1
    assert row.allowed_domains == '["postgres-mcp:8080"]'


@pytest.mark.asyncio
async def test_local_mcp_resource_defaults_applied(tmp_path):
    db_file = tmp_path / "resource_def.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    engine = create_engine(f"sqlite:///{db_file}", future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                insert(LocalMCPResource).values(
                    resource_id="res-min",
                    name="minimal",
                    endpoint_url="http://svc:80",
                    created_at="2026-04-16T10:00:00Z",
                    updated_at="2026-04-16T10:00:00Z",
                )
            )
        with engine.connect() as conn:
            row = conn.execute(select(LocalMCPResource)).one()
    finally:
        engine.dispose()

    assert row.auth_type == "none"
    assert row.allowed_domains == "[]"
    assert row.enabled == 1
    assert row.org_id is None
    assert row.required_capability is None


@pytest.mark.asyncio
async def test_local_agent_resource_binding_roundtrip(tmp_path):
    db_file = tmp_path / "binding_rt.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    engine = create_engine(f"sqlite:///{db_file}", future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                insert(LocalAgentResourceBinding).values(
                    binding_id="bind-001",
                    agent_id="acme::buyer",
                    resource_id="res-001",
                    org_id="acme",
                    granted_by="admin@acme",
                    granted_at="2026-04-16T10:05:00Z",
                )
            )
        with engine.connect() as conn:
            row = conn.execute(select(LocalAgentResourceBinding)).one()
    finally:
        engine.dispose()

    assert row.binding_id == "bind-001"
    assert row.revoked_at is None


@pytest.mark.asyncio
async def test_binding_unique_agent_resource_enforced(tmp_path):
    """Two bindings for the same (agent_id, resource_id) are rejected."""
    db_file = tmp_path / "binding_uq.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    engine = create_engine(f"sqlite:///{db_file}", future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                insert(LocalAgentResourceBinding).values(
                    binding_id="b1",
                    agent_id="a",
                    resource_id="r",
                    granted_by="admin",
                    granted_at="2026-04-16T10:00:00Z",
                )
            )
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(
                    insert(LocalAgentResourceBinding).values(
                        binding_id="b2",
                        agent_id="a",
                        resource_id="r",
                        granted_by="admin",
                        granted_at="2026-04-16T10:00:01Z",
                    )
                )
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_resource_unique_org_name_enforced(tmp_path):
    db_file = tmp_path / "resource_uq.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    await dispose_db()

    engine = create_engine(f"sqlite:///{db_file}", future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                insert(LocalMCPResource).values(
                    resource_id="r1",
                    org_id="acme",
                    name="dup",
                    endpoint_url="http://a",
                    created_at="2026-04-16T10:00:00Z",
                    updated_at="2026-04-16T10:00:00Z",
                )
            )
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(
                    insert(LocalMCPResource).values(
                        resource_id="r2",
                        org_id="acme",
                        name="dup",
                        endpoint_url="http://b",
                        created_at="2026-04-16T10:00:01Z",
                        updated_at="2026-04-16T10:00:01Z",
                    )
                )
    finally:
        engine.dispose()
