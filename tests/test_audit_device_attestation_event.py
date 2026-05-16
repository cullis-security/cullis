"""audit_events helper coverage (ADR-032 F6 / schema sez. 4.2)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.attestation.audit_events import (
    ACTION_DEVICE_ATTESTATION,
    ACTION_MDM_POLLING_DEGRADED,
    emit_device_attestation_change_global,
    emit_polling_degraded,
    log_device_attestation_change,
)
from mcp_proxy.db import dispose_db, get_db, init_db


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "audit.sqlite"
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


def _claim():
    return {
        "mdm": "intune",
        "device_id": "dev-1",
        "compliance": "non_compliant",
        "hardware": None,
        "strength": "soft_only",
        "manufacturer": "Infineon",
        "verified_at": "2026-05-17T12:00:00Z",
        "stale_seconds": 0,
    }


@pytest.mark.asyncio
async def test_log_device_attestation_change_writes_canonical_row(db_engine):
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    async with get_db() as conn:
        await log_device_attestation_change(
            conn,
            agent_id="acme::alice",
            event_subtype="revoked",
            device_attestation=_claim(),
            effective_tier="untrusted",
            previous_compliance="compliant",
            trigger="polling",
            now=now,
        )
        row = (await conn.execute(
            text(
                "SELECT action, status, detail, device_attestation, "
                "       effective_tier FROM audit_log "
                "WHERE agent_id = :a ORDER BY id DESC LIMIT 1"
            ),
            {"a": "acme::alice"},
        )).mappings().first()

    assert row["action"] == ACTION_DEVICE_ATTESTATION
    assert row["status"] == "success"
    assert row["effective_tier"] == "untrusted"

    detail = json.loads(row["detail"])
    assert detail["event_subtype"] == "revoked"
    assert detail["trigger"] == "polling"
    assert detail["previous_compliance"] == "compliant"
    assert detail["device_attestation"]["device_id"] == "dev-1"

    column_claim = json.loads(row["device_attestation"])
    assert column_claim["mdm"] == "intune"


@pytest.mark.asyncio
async def test_unknown_subtype_falls_back(db_engine):
    """Defensive guard: an unknown subtype must not raise."""
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    async with get_db() as conn:
        await log_device_attestation_change(
            conn,
            agent_id="acme::bob",
            event_subtype="bogus",  # invalid
            device_attestation=_claim(),
            effective_tier="managed",
            previous_compliance="compliant",
            trigger="polling",
            now=now,
        )
        row = (await conn.execute(
            text(
                "SELECT detail FROM audit_log "
                "WHERE agent_id = :a ORDER BY id DESC LIMIT 1"
            ),
            {"a": "acme::bob"},
        )).mappings().first()
    detail = json.loads(row["detail"])
    # Falls back to 'verified' per audit_events.py contract.
    assert detail["event_subtype"] == "verified"


@pytest.mark.asyncio
async def test_global_path_uses_log_audit_chain(db_engine):
    await emit_device_attestation_change_global(
        agent_id="acme::carol",
        event_subtype="stale",
        device_attestation=_claim(),
        effective_tier="untrusted",
        previous_compliance="compliant",
        trigger="ttl_expired",
    )
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT action, detail FROM audit_log "
                "WHERE agent_id = :a ORDER BY id DESC LIMIT 1"
            ),
            {"a": "acme::carol"},
        )).mappings().first()
    assert row["action"] == ACTION_DEVICE_ATTESTATION
    detail = json.loads(row["detail"])
    assert detail["event_subtype"] == "stale"


@pytest.mark.asyncio
async def test_polling_degraded_emits_audit_row(db_engine):
    await emit_polling_degraded(
        mdm="intune",
        consecutive_failures=5,
        last_error_status=429,
        last_error_message="throttled",
    )
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT action, status, detail FROM audit_log "
                "WHERE action = :act ORDER BY id DESC LIMIT 1"
            ),
            {"act": ACTION_MDM_POLLING_DEGRADED},
        )).mappings().first()
    assert row is not None
    assert row["status"] == "failure"
    detail = json.loads(row["detail"])
    assert detail["mdm"] == "intune"
    assert detail["consecutive_failures"] == 5
    assert detail["last_error_status"] == 429
