"""End-to-end-ish: full polling loop drives cert revocation (ADR-032 F6).

Sits between the F6 unit suite and the Docker-based e2e tests. Boots
nothing external: stubs the Intune Graph endpoint via httpx
MockTransport and drives the polling loop through one compliant
round + one non-compliant round, asserting:

1. cache row tracks the compliance flip
2. the bound agent's ``internal_agents`` row is revoked
3. an ``agent.revoked`` audit row exists
4. a ``device_attestation`` audit row with subtype ``revoked`` exists
5. the policy gate's ``is_active`` precondition for client_cert auth
   no longer holds (i.e. the agent is locked out at the DB level —
   the actual HTTP 401 is covered by the existing client_cert tests)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import create_agent, dispose_db, get_db, init_db
from mcp_proxy.mdm.intune import IntuneClient
from mcp_proxy.mdm.poller import intune_poll_once


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "flip.sqlite"
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


def _mock_intune(compliance: str) -> IntuneClient:
    """Build a client whose Graph endpoint returns one device with the
    given compliance state."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/oauth2/v2.0/token" in url:
            return httpx.Response(200, json={
                "access_token": "tok", "token_type": "Bearer",
                "expires_in": 3600,
            })
        # Any non-token URL is treated as the managedDevices endpoint —
        # covers both the initial /deviceManagement/managedDevices/delta
        # call and the persisted deltaLink follow-up.
        return httpx.Response(200, json={
            "value": [{
                "id": "alice-laptop",
                "complianceState": compliance,
                "azureADDeviceId": "aad-alice",
                "deviceName": "alice-laptop",
                "manufacturer": "Infineon",
            }],
            "@odata.deltaLink": f"https://graph.test/d?after={compliance}",
        })

    transport = httpx.MockTransport(handler)
    return IntuneClient(
        tenant_id="t", client_id="c", client_secret="s",
        http_client=httpx.AsyncClient(transport=transport),
    )


async def _bind_agent(agent_id: str, device_id: str):
    """Stamp internal_agents.last_attestation so the reconciler can
    walk the device_id -> agent_id bridge."""
    claim = {
        "device_attestation": {
            "mdm": "intune",
            "device_id": device_id,
            "compliance": "compliant",
            "hardware": None,
            "strength": "soft_only",
            "manufacturer": "Infineon",
            "verified_at": "2026-05-17T12:00:00Z",
            "stale_seconds": 0,
        },
        "effective_tier": "managed",
    }
    async with get_db() as conn:
        await conn.execute(
            text(
                "UPDATE internal_agents SET last_attestation = :c "
                "WHERE agent_id = :a"
            ),
            {"c": json.dumps(claim, sort_keys=True), "a": agent_id},
        )


@pytest.mark.asyncio
async def test_full_loop_revokes_agent_on_compliance_flip(db_engine):
    # Setup: agent enrolled and bound to a device that Intune currently
    # reports as compliant.
    await create_agent(
        agent_id="acme::alice", display_name="alice",
        capabilities=["cap.read"], cert_pem="DUMMYPEM",
    )
    await _bind_agent("acme::alice", "alice-laptop")

    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)

    # Round 1: compliant. Populates the cache.
    client_compliant = _mock_intune("compliant")
    await intune_poll_once(client_compliant, now=now)
    await client_compliant.aclose()

    async with get_db() as conn:
        cached = (await conn.execute(
            text(
                "SELECT compliance FROM mdm_device_state "
                "WHERE device_id = 'alice-laptop'"
            ),
        )).scalar()
        active = (await conn.execute(
            text(
                "SELECT is_active FROM internal_agents "
                "WHERE agent_id = 'acme::alice'"
            ),
        )).scalar()
    assert cached == "compliant"
    assert active in (1, True)

    # Round 2: Intune flips to non_compliant.
    client_flipped = _mock_intune("noncompliant")
    await intune_poll_once(client_flipped, now=now)
    await client_flipped.aclose()

    async with get_db() as conn:
        flipped_compliance = (await conn.execute(
            text(
                "SELECT compliance FROM mdm_device_state "
                "WHERE device_id = 'alice-laptop'"
            ),
        )).scalar()
        agent_row = (await conn.execute(
            text(
                "SELECT is_active, revoked_at, revoked_reason "
                "FROM internal_agents WHERE agent_id = 'acme::alice'"
            ),
        )).mappings().first()
        audit_actions = [
            r[0] for r in (await conn.execute(
                text(
                    "SELECT action FROM audit_log "
                    "WHERE agent_id = 'acme::alice' ORDER BY id"
                ),
            )).all()
        ]
        dev_attest_detail = (await conn.execute(
            text(
                "SELECT detail FROM audit_log "
                "WHERE agent_id = 'acme::alice' "
                "  AND action = 'device_attestation' "
                "ORDER BY id DESC LIMIT 1"
            ),
        )).scalar()

    assert flipped_compliance == "non_compliant"
    assert agent_row["is_active"] in (0, False)
    assert agent_row["revoked_at"] is not None
    assert agent_row["revoked_reason"] == "insufficient_compliance"
    assert "agent.revoked" in audit_actions
    assert "device_attestation" in audit_actions

    detail = json.loads(dev_attest_detail)
    assert detail["event_subtype"] == "revoked"
    assert detail["previous_compliance"] == "compliant"
    assert detail["device_attestation"]["compliance"] == "non_compliant"


@pytest.mark.asyncio
async def test_unbound_device_flip_does_not_affect_other_agents(db_engine):
    """Flipping a device with no bound agent must be a quiet no-op for
    other agents."""
    await create_agent(
        agent_id="acme::other", display_name="other",
        capabilities=[], cert_pem="X",
    )
    await _bind_agent("acme::other", "different-device")

    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    # Seed cache + flip an unrelated device.
    await intune_poll_once(_mock_intune("compliant"), now=now)
    await intune_poll_once(_mock_intune("noncompliant"), now=now)

    async with get_db() as conn:
        active = (await conn.execute(
            text(
                "SELECT is_active FROM internal_agents "
                "WHERE agent_id = 'acme::other'"
            ),
        )).scalar()
    assert active in (1, True)
