"""CSR enrollment → MDM cache lookup → attestation claim stamped.

Drives the end-to-end shape: seed the ``mdm_device_state`` cache,
run the device-code approve path with a ``device_info`` hint that
matches, and verify:
  1. ``internal_agents.last_attestation`` populated with the claim.
  2. An ``audit_log`` row of action ``device_attestation`` written.
  3. When no cache match exists, enrollment succeeds without
     stamping (graceful no-op).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.enrollment import service
from mcp_proxy.mdm.poller import upsert_device_rows


def _ec_pubkey_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "enrol_attest.sqlite"
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


class _FakeAgentManager:
    """Minimal AgentManager stand-in for the approve path.

    The enrollment service only calls ``sign_external_pubkey`` plus
    reads ``ca_loaded`` / ``org_id`` / ``trust_domain``. We bypass
    the real Org CA by returning a hand-written placeholder PEM
    that the test never validates — the attestation hook does not
    touch it.
    """

    ca_loaded = True
    org_id = "acme"
    trust_domain = "cullis.test"

    def sign_external_pubkey(self, *, pubkey_pem: str, agent_name: str) -> str:
        return f"-----BEGIN CERTIFICATE-----\nFAKE-{agent_name}\n-----END CERTIFICATE-----\n"


async def _seed_pending(pubkey_pem: str, device_info_json: str) -> str:
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pubkey_pem,
            requester_name="Alice Tester",
            requester_email="alice@example.com",
            reason="attestation test",
            device_info=device_info_json,
        )
    return started.session_id


@pytest.mark.asyncio
async def test_enrollment_with_matching_intune_device_stamps_claim(db_engine):
    # 1. Seed the MDM cache with a device matching the Connector's hint.
    now = datetime.now(timezone.utc)
    await upsert_device_rows(
        [{
            "id": "intune-device-uuid-1",
            "complianceState": "compliant",
            "azureADDeviceId": "aad-1",
            "deviceName": "alice-laptop",
            "manufacturer": "Infineon",
            "serialNumber": "SN-001",
        }],
        now=now,
    )

    pubkey = _ec_pubkey_pem()
    device_info = json.dumps({
        "os": "linux",
        "azure_ad_device_id": "aad-1",
    })
    session_id = await _seed_pending(pubkey, device_info)

    # 2. Approve.
    async with get_db() as conn:
        record = await service.approve(
            conn,
            session_id=session_id,
            agent_id="alice-connector",
            capabilities=["mcp.read_public"],
            groups=[],
            admin_name="test-admin",
            agent_manager=_FakeAgentManager(),
        )

    canonical_id = record["agent_id_assigned"]
    assert canonical_id == "acme::alice-connector"

    # 3. Assert internal_agents.last_attestation populated.
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT last_attestation FROM internal_agents "
                 "WHERE agent_id = :a"),
            {"a": canonical_id},
        )).first()
    assert row is not None and row[0]
    claim = json.loads(row[0])
    assert claim["device_attestation"]["mdm"] == "intune"
    assert claim["device_attestation"]["device_id"] == "intune-device-uuid-1"
    assert claim["device_attestation"]["compliance"] == "compliant"
    assert claim["effective_tier"] == "managed"

    # 4. Audit row of action 'device_attestation' present.
    async with get_db() as conn:
        audit_rows = (await conn.execute(
            text("SELECT agent_id, action, status, detail FROM audit_log "
                 "WHERE action = 'device_attestation'"),
        )).all()
    assert len(audit_rows) >= 1
    audit_aid, audit_action, audit_status, audit_detail = audit_rows[0]
    assert audit_aid == canonical_id
    assert audit_action == "device_attestation"
    assert audit_status == "success"
    detail = json.loads(audit_detail)
    assert detail["event_subtype"] == "verified"
    assert detail["trigger"] == "enrollment"
    assert detail["device_attestation"]["mdm"] == "intune"


@pytest.mark.asyncio
async def test_enrollment_without_mdm_match_completes_without_stamping(db_engine):
    """No cache match → no last_attestation, no audit, no error."""
    pubkey = _ec_pubkey_pem()
    device_info = json.dumps({"os": "linux", "azure_ad_device_id": "unknown-aad"})
    session_id = await _seed_pending(pubkey, device_info)

    async with get_db() as conn:
        record = await service.approve(
            conn,
            session_id=session_id,
            agent_id="bob-connector",
            capabilities=[],
            groups=[],
            admin_name="test-admin",
            agent_manager=_FakeAgentManager(),
        )

    canonical_id = record["agent_id_assigned"]
    async with get_db() as conn:
        last_attest = (await conn.execute(
            text("SELECT last_attestation FROM internal_agents "
                 "WHERE agent_id = :a"),
            {"a": canonical_id},
        )).scalar()
        audit_count = (await conn.execute(
            text("SELECT COUNT(*) FROM audit_log "
                 "WHERE action = 'device_attestation' AND agent_id = :a"),
            {"a": canonical_id},
        )).scalar()
    assert last_attest is None
    assert audit_count == 0


@pytest.mark.asyncio
async def test_non_compliant_match_stamps_byod_attested_or_untrusted(db_engine):
    """A cached non_compliant device degrades the tier to byod_*/untrusted."""
    now = datetime.now(timezone.utc)
    await upsert_device_rows(
        [{
            "id": "intune-device-uuid-2",
            "complianceState": "noncompliant",
            "azureADDeviceId": "aad-2",
            "manufacturer": "Microsoft",
        }],
        now=now,
    )

    pubkey = _ec_pubkey_pem()
    device_info = json.dumps({"azure_ad_device_id": "aad-2"})
    session_id = await _seed_pending(pubkey, device_info)

    async with get_db() as conn:
        record = await service.approve(
            conn,
            session_id=session_id,
            agent_id="carol-connector",
            capabilities=[],
            groups=[],
            admin_name="test-admin",
            agent_manager=_FakeAgentManager(),
        )

    canonical_id = record["agent_id_assigned"]
    async with get_db() as conn:
        last_attest = (await conn.execute(
            text("SELECT last_attestation FROM internal_agents "
                 "WHERE agent_id = :a"),
            {"a": canonical_id},
        )).scalar()
    assert last_attest is not None
    claim = json.loads(last_attest)
    # MDM present but non-compliant → has_mdm=False in compute → soft_only
    # → untrusted (no hardware in Phase 1).
    assert claim["device_attestation"]["compliance"] == "non_compliant"
    assert claim["effective_tier"] == "untrusted"


@pytest.mark.asyncio
async def test_enrollment_hook_failure_does_not_break_approve(db_engine, monkeypatch):
    """If the attestation hook raises, approve still succeeds."""

    async def _boom(*args, **kwargs):
        raise RuntimeError("simulated MDM cache outage")

    monkeypatch.setattr(
        "mcp_proxy.attestation.enrollment_hook.stamp_attestation_on_enrollment",
        _boom,
    )

    pubkey = _ec_pubkey_pem()
    session_id = await _seed_pending(pubkey, "{}")

    async with get_db() as conn:
        record = await service.approve(
            conn,
            session_id=session_id,
            agent_id="dan-connector",
            capabilities=[],
            groups=[],
            admin_name="test-admin",
            agent_manager=_FakeAgentManager(),
        )
    assert record["status"] == "approved"
    assert record["agent_id_assigned"] == "acme::dan-connector"
