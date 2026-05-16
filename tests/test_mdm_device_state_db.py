"""mdm_device_state DB CRUD + upsert semantics.

Driven through the same SQLite engine fixture the enrollment tests
use so migrations run end-to-end (0035_mdm_device_state included).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.mdm.poller import upsert_device_rows


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "mdm.sqlite"
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


def _graph_device(**overrides):
    base = {
        "id": "device-uuid-1",
        "complianceState": "compliant",
        "azureADDeviceId": "aad-1",
        "userPrincipalName": "alice@example.com",
        "deviceName": "alice-laptop",
        "manufacturer": "Infineon",
        "serialNumber": "SN-001",
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_upsert_inserts_new_rows(db_engine):
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    touched = await upsert_device_rows(
        [_graph_device(id="d1"), _graph_device(id="d2")],
        now=now,
    )
    assert touched == 2

    async with get_db() as conn:
        rows = (await conn.execute(
            text("SELECT mdm, device_id, compliance FROM mdm_device_state "
                 "ORDER BY device_id"),
        )).all()
    assert [(r[0], r[1], r[2]) for r in rows] == [
        ("intune", "d1", "compliant"),
        ("intune", "d2", "compliant"),
    ]


@pytest.mark.asyncio
async def test_upsert_updates_compliance_on_conflict(db_engine):
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    await upsert_device_rows(
        [_graph_device(id="d1", complianceState="compliant")], now=now,
    )

    later = now + timedelta(minutes=10)
    touched = await upsert_device_rows(
        [_graph_device(id="d1", complianceState="noncompliant",
                       deviceName="alice-laptop-renamed")],
        now=later,
    )
    assert touched == 1

    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT compliance, device_name, last_seen_at "
                "FROM mdm_device_state WHERE device_id = :d"
            ),
            {"d": "d1"},
        )).first()
    assert row[0] == "non_compliant"
    assert row[1] == "alice-laptop-renamed"
    # last_seen_at advanced; created_at did not (we don't assert exact
    # value, just that the row is still queryable).


@pytest.mark.asyncio
async def test_upsert_skips_devices_without_id(db_engine):
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    touched = await upsert_device_rows(
        [
            _graph_device(id="dgood"),
            {"complianceState": "compliant"},  # no id
            {"id": "", "complianceState": "compliant"},
        ],
        now=now,
    )
    assert touched == 1


@pytest.mark.asyncio
async def test_upsert_empty_list_is_noop(db_engine):
    touched = await upsert_device_rows([])
    assert touched == 0


@pytest.mark.asyncio
async def test_upsert_distinguishes_mdm_namespace(db_engine):
    """Same device_id under intune vs jamf are independent rows."""
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    await upsert_device_rows([_graph_device(id="d1")], mdm="intune", now=now)
    await upsert_device_rows([_graph_device(id="d1")], mdm="jamf", now=now)
    async with get_db() as conn:
        count = (await conn.execute(
            text("SELECT COUNT(*) FROM mdm_device_state WHERE device_id = :d"),
            {"d": "d1"},
        )).scalar()
    assert count == 2


@pytest.mark.asyncio
async def test_internal_agents_has_last_attestation_column(db_engine):
    """Migration 0035 must add ``last_attestation`` to internal_agents."""
    async with get_db() as conn:
        from sqlalchemy import inspect as _inspect
        # The async connection wraps a sync DBAPI; use run_sync to
        # introspect cleanly.
        cols = await conn.run_sync(
            lambda sync_conn: {
                c["name"] for c in _inspect(sync_conn).get_columns("internal_agents")
            }
        )
    assert "last_attestation" in cols
