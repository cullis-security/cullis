"""Compliance-change reconciler (ADR-032 F6).

Covers the diff logic + the four transitions the schema reserves:

* no prior row (first seen) → no-op
* same compliance → no-op
* compliant → non_compliant → revoke + audit
* non_compliant → compliant → audit only (no auto re-trust)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import create_agent, dispose_db, get_db, init_db
from mcp_proxy.mdm.compliance_change import (
    reconcile_devices_and_revoke,
)
from mcp_proxy.mdm.poller import upsert_device_rows


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "reconcile.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_ATTESTATION_STALE_THRESHOLD_SECONDS", "900")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()


def _graph_device(device_id="d1", compliance="compliant", **overrides):
    base = {
        "id": device_id,
        "complianceState": compliance,
        "azureADDeviceId": f"aad-{device_id}",
        "deviceName": "laptop",
        "manufacturer": "Infineon",
    }
    base.update(overrides)
    return base


async def _bind_agent_to_device(agent_id: str, device_id: str, compliance: str):
    """Set internal_agents.last_attestation pointing at the given device."""
    claim = {
        "device_attestation": {
            "mdm": "intune",
            "device_id": device_id,
            "compliance": compliance,
            "hardware": None,
            "strength": "soft_only",
            "manufacturer": "Infineon",
            "verified_at": "2026-05-17T12:00:00Z",
            "stale_seconds": 0,
        },
        "effective_tier": "managed" if compliance == "compliant" else "untrusted",
    }
    async with get_db() as conn:
        await conn.execute(
            text(
                "UPDATE internal_agents SET last_attestation = :c "
                "WHERE agent_id = :aid"
            ),
            {"c": json.dumps(claim, sort_keys=True), "aid": agent_id},
        )


@pytest.mark.asyncio
async def test_first_observation_no_transition(db_engine):
    """No cached row → no revocation, no audit."""
    summary = await _reconcile([_graph_device(compliance="noncompliant")])
    assert summary.devices_checked == 1
    assert summary.transitions == 0
    assert summary.revocations == 0


@pytest.mark.asyncio
async def test_same_compliance_no_transition(db_engine):
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    await upsert_device_rows(
        [_graph_device(compliance="compliant")], now=now,
    )
    summary = await _reconcile([_graph_device(compliance="compliant")], now=now)
    assert summary.transitions == 0
    assert summary.revocations == 0


@pytest.mark.asyncio
async def test_compliant_to_non_compliant_revokes_bound_agent(db_engine):
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    await upsert_device_rows([_graph_device(compliance="compliant")], now=now)
    await create_agent(
        agent_id="acme::agent-alice",
        display_name="agent-alice",
        capabilities=["cap.read"],
        cert_pem="dummy",
    )
    await _bind_agent_to_device("acme::agent-alice", "d1", "compliant")

    summary = await _reconcile(
        [_graph_device(compliance="noncompliant")], now=now,
    )

    assert summary.transitions == 1
    assert summary.revocations == 1

    async with get_db() as conn:
        agent_row = (await conn.execute(
            text(
                "SELECT is_active, revoked_at, revoked_reason "
                "FROM internal_agents WHERE agent_id = :a"
            ),
            {"a": "acme::agent-alice"},
        )).mappings().first()
        audit_rows = (await conn.execute(
            text(
                "SELECT action, status, detail FROM audit_log "
                "WHERE agent_id = :a ORDER BY id"
            ),
            {"a": "acme::agent-alice"},
        )).mappings().all()

    assert agent_row["is_active"] in (0, False)
    assert agent_row["revoked_at"] is not None
    assert agent_row["revoked_reason"] == "insufficient_compliance"

    actions = [r["action"] for r in audit_rows]
    assert "device_attestation" in actions
    assert "agent.revoked" in actions

    dev_attest_detail = json.loads(
        next(r["detail"] for r in audit_rows if r["action"] == "device_attestation"),
    )
    assert dev_attest_detail["event_subtype"] == "revoked"
    assert dev_attest_detail["previous_compliance"] == "compliant"
    assert dev_attest_detail["trigger"] == "polling"


@pytest.mark.asyncio
async def test_non_compliant_to_compliant_audits_without_unrevoking(db_engine):
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    await upsert_device_rows(
        [_graph_device(compliance="noncompliant")], now=now,
    )
    await create_agent(
        agent_id="acme::agent-bob",
        display_name="agent-bob",
        capabilities=[],
        cert_pem="dummy",
    )
    await _bind_agent_to_device("acme::agent-bob", "d1", "non_compliant")

    summary = await _reconcile(
        [_graph_device(compliance="compliant")], now=now,
    )

    assert summary.transitions == 1
    assert summary.reverifications == 1
    assert summary.revocations == 0  # no auto re-trust

    async with get_db() as conn:
        agent = (await conn.execute(
            text(
                "SELECT is_active, revoked_at FROM internal_agents "
                "WHERE agent_id = :a"
            ),
            {"a": "acme::agent-bob"},
        )).mappings().first()
        audit = (await conn.execute(
            text(
                "SELECT detail FROM audit_log "
                "WHERE agent_id = :a AND action = 'device_attestation'"
            ),
            {"a": "acme::agent-bob"},
        )).mappings().first()

    assert agent["is_active"] in (1, True)  # not revoked just because device became compliant
    detail = json.loads(audit["detail"])
    assert detail["event_subtype"] == "verified"


@pytest.mark.asyncio
async def test_revoke_is_idempotent_when_called_twice(db_engine):
    """A second reconcile run on the same flip must not re-emit audit/metric."""
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    await upsert_device_rows([_graph_device(compliance="compliant")], now=now)
    await create_agent(
        agent_id="acme::agent-c",
        display_name="agent-c",
        capabilities=[],
        cert_pem="dummy",
    )
    await _bind_agent_to_device("acme::agent-c", "d1", "compliant")

    await _reconcile([_graph_device(compliance="noncompliant")], now=now)
    # Simulate cache catching up.
    await upsert_device_rows([_graph_device(compliance="noncompliant")], now=now)

    second = await _reconcile(
        [_graph_device(compliance="noncompliant")], now=now,
    )
    assert second.transitions == 0
    assert second.revocations == 0


@pytest.mark.asyncio
async def test_unknown_transition_does_not_revoke(db_engine):
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    await upsert_device_rows([_graph_device(compliance="compliant")], now=now)
    await create_agent(
        agent_id="acme::agent-d",
        display_name="agent-d",
        capabilities=[],
        cert_pem="dummy",
    )
    await _bind_agent_to_device("acme::agent-d", "d1", "compliant")

    summary = await _reconcile(
        [_graph_device(compliance="error")],  # Graph 'error' -> claim 'unknown'
        now=now,
    )
    assert summary.transitions == 1
    assert summary.revocations == 0

    async with get_db() as conn:
        agent = (await conn.execute(
            text(
                "SELECT is_active FROM internal_agents WHERE agent_id = :a"
            ),
            {"a": "acme::agent-d"},
        )).mappings().first()
    assert agent["is_active"] in (1, True)


# ── helpers ──────────────────────────────────────────────────────────


async def _reconcile(graph_devices, now: datetime | None = None):
    async with get_db() as conn:
        return await reconcile_devices_and_revoke(
            conn, fresh_devices=graph_devices, mdm="intune", now=now,
        )
