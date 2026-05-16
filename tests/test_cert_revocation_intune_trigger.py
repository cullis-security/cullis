"""``revoke_agent_cert`` direct unit coverage (ADR-032 F6)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import create_agent, dispose_db, get_db, init_db
from mcp_proxy.registry.revoke_cert import (
    REASON_ADMIN,
    REASON_INSUFFICIENT_COMPLIANCE,
    revoke_agent_cert,
)


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "revoke.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_revoke_marks_inactive_and_stamps_reason(db_engine):
    await create_agent(
        agent_id="acme::a", display_name="a",
        capabilities=[], cert_pem="x",
    )
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    transitioned = await revoke_agent_cert(
        "acme::a",
        reason_code=REASON_INSUFFICIENT_COMPLIANCE,
        reason_detail="device flipped",
        mdm="intune",
        now=now,
    )
    assert transitioned is True

    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT is_active, revoked_at, revoked_reason "
                "FROM internal_agents WHERE agent_id = :a"
            ),
            {"a": "acme::a"},
        )).mappings().first()
    assert row["is_active"] in (0, False)
    assert row["revoked_reason"] == REASON_INSUFFICIENT_COMPLIANCE
    assert row["revoked_at"] is not None


@pytest.mark.asyncio
async def test_revoke_is_idempotent_returns_false_second_time(db_engine):
    await create_agent(
        agent_id="acme::b", display_name="b",
        capabilities=[], cert_pem="x",
    )
    first = await revoke_agent_cert(
        "acme::b", reason_code=REASON_ADMIN, mdm=None,
    )
    second = await revoke_agent_cert(
        "acme::b", reason_code=REASON_ADMIN, mdm=None,
    )
    assert first is True
    assert second is False


@pytest.mark.asyncio
async def test_revoke_unknown_agent_returns_false(db_engine):
    transitioned = await revoke_agent_cert(
        "acme::ghost", reason_code=REASON_ADMIN,
    )
    assert transitioned is False


@pytest.mark.asyncio
async def test_revoke_emits_agent_revoked_audit_row(db_engine):
    await create_agent(
        agent_id="acme::c", display_name="c",
        capabilities=[], cert_pem="x",
    )
    await revoke_agent_cert(
        "acme::c",
        reason_code=REASON_INSUFFICIENT_COMPLIANCE,
        reason_detail="intune flip",
        mdm="intune",
    )
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT action, status, detail FROM audit_log "
                "WHERE agent_id = :a AND action = 'agent.revoked'"
            ),
            {"a": "acme::c"},
        )).mappings().all()
    assert len(rows) == 1
    assert rows[0]["status"] == "success"
    assert REASON_INSUFFICIENT_COMPLIANCE in rows[0]["detail"]


@pytest.mark.asyncio
async def test_revoke_bumps_federation_revision(db_engine):
    await create_agent(
        agent_id="acme::d", display_name="d",
        capabilities=[], cert_pem="x",
    )
    async with get_db() as conn:
        before = (await conn.execute(
            text("SELECT federation_revision FROM internal_agents "
                 "WHERE agent_id = :a"),
            {"a": "acme::d"},
        )).scalar()
    await revoke_agent_cert("acme::d", reason_code=REASON_ADMIN)
    async with get_db() as conn:
        after = (await conn.execute(
            text("SELECT federation_revision FROM internal_agents "
                 "WHERE agent_id = :a"),
            {"a": "acme::d"},
        )).scalar()
    assert after == before + 1
