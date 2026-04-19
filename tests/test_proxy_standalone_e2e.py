"""ADR-006 Fase 1 — standalone proxy as a complete intra-org mini-broker.

Two internal agents enrolled in the same standalone proxy must be able to
open a session, exchange messages, ack delivery and close the session
without any broker uplink. The test is the acceptance criterion for the
"Trojan Horse" go-to-market: install the proxy in the customer's infra,
agents talk out of the box.

Previously (ADR-001 Phase 3) the wiring existed but only took effect when
``PROXY_INTRA_ORG`` was explicitly turned on. Standalone mode defaulted
to off, so egress endpoints fell through to a non-existent BrokerBridge
and returned 503. ADR-006 Fase 1 flips the default: standalone implies
intra-org routing unless the operator explicitly overrides.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def standalone_proxy(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    # Deliberately NOT setting PROXY_INTRA_ORG or PROXY_TRANSPORT_INTRA_ORG
    # — the defaults in standalone mode must flip them both on, otherwise
    # the point of this fixture is lost.
    monkeypatch.delenv("PROXY_INTRA_ORG", raising=False)
    monkeypatch.delenv("PROXY_TRANSPORT_INTRA_ORG", raising=False)
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_BROKER_JWKS_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield app, client
    get_settings.cache_clear()


async def _provision_agent(agent_id: str) -> str:
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import create_agent

    raw = generate_api_key(agent_id)
    await create_agent(
        agent_id=agent_id,
        display_name=agent_id,
        capabilities=["cap.read"],
        api_key_hash=hash_api_key(raw),
    )
    return raw


@pytest.mark.asyncio
async def test_standalone_defaults_to_intra_org_routing(standalone_proxy):
    """ADR-006: MCP_PROXY_STANDALONE implies PROXY_INTRA_ORG=true."""
    from mcp_proxy.config import get_settings

    settings = get_settings()
    assert settings.standalone is True
    assert settings.intra_org_routing is True, (
        "standalone mode must enable intra-org routing by default — "
        "without it /v1/egress/* 503s on missing bridge"
    )


@pytest.mark.asyncio
async def test_standalone_defaults_to_mtls_only_transport(standalone_proxy):
    """Standalone must default transport_intra_org to mtls-only.

    The envelope resolve handler does not populate target_cert_pem for
    intra-org peers, so SDK send_oneshot fails with a misleading
    "cross-org one-shot requires recipient public key" error on a
    fresh install. The mtls-only path short-circuits through the proxy
    itself and works out of the box.
    """
    from mcp_proxy.config import get_settings

    settings = get_settings()
    assert settings.standalone is True
    assert settings.transport_intra_org == "mtls-only", (
        "standalone mode must default to mtls-only transport — "
        "envelope leaves send_oneshot without target_cert_pem on "
        "intra-org peers, fresh installs get misleading errors"
    )


@pytest.mark.asyncio
async def test_standalone_intra_org_full_roundtrip(standalone_proxy):
    """Two agents on the same standalone proxy complete a full session
    lifecycle: open → accept → send → poll → ack → close. Zero broker."""
    app, client = standalone_proxy
    alice = await _provision_agent("alice-bot")
    bob = await _provision_agent("bob-bot")

    # 1. Alice opens a session to Bob (same org).
    open_resp = await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": alice},
        json={
            "target_agent_id": "bob-bot",
            "target_org_id": "acme",
            "capabilities": ["cap.read"],
        },
    )
    assert open_resp.status_code == 200, open_resp.text
    session_id = open_resp.json()["session_id"]

    # 2. Bob accepts.
    accept = await client.post(
        f"/v1/egress/sessions/{session_id}/accept",
        headers={"X-API-Key": bob},
    )
    assert accept.status_code == 200, accept.text

    # 3. Alice sends an envelope-mode message (opaque ciphertext).
    send = await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": alice},
        json={
            "session_id": session_id,
            "payload": {"hello": "bob"},
            "recipient_agent_id": "bob-bot",
            "mode": "envelope",
        },
    )
    assert send.status_code == 200, send.text
    assert send.json()["status"] == "sent"
    msg_id = send.json()["msg_id"]

    # 4. Bob polls and sees the message.
    poll = await client.get(
        f"/v1/egress/messages/{session_id}",
        headers={"X-API-Key": bob},
    )
    assert poll.status_code == 200, poll.text
    body = poll.json()
    assert body["scope"] == "local"
    assert body["count"] == 1
    msg = body["messages"][0]
    assert msg["msg_id"] == msg_id
    assert msg["sender_agent_id"] == "alice-bot"

    # 5. Bob acks — queue row flips to delivered.
    ack = await client.post(
        f"/v1/egress/sessions/{session_id}/messages/{msg_id}/ack",
        headers={"X-API-Key": bob},
    )
    assert ack.status_code == 200, ack.text

    # 6. Subsequent poll returns empty (the row is no longer pending).
    poll2 = await client.get(
        f"/v1/egress/messages/{session_id}",
        headers={"X-API-Key": bob},
    )
    assert poll2.json()["count"] == 0

    # 7. Alice closes.
    close = await client.post(
        f"/v1/egress/sessions/{session_id}/close",
        headers={"X-API-Key": alice},
    )
    assert close.status_code == 200, close.text


@pytest.mark.asyncio
async def test_standalone_cross_org_returns_400_not_503(standalone_proxy):
    """ADR-006 Fase 1: cross-org attempts in standalone surface as 400
    ("cross-org disabled") rather than the legacy 503 ("bridge not
    initialized"). The distinction matters for SDK error handling —
    503 implies transient, 400 implies "this deployment can't do it"."""
    _, client = standalone_proxy
    alice = await _provision_agent("alice-bot")

    resp = await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": alice},
        json={
            "target_agent_id": "stranger-bot",
            "target_org_id": "other-org",  # foreign org
            "capabilities": [],
        },
    )
    assert resp.status_code == 400, resp.text
    assert "standalone" in resp.text.lower()


@pytest.mark.asyncio
async def test_standalone_explicit_intra_org_false_still_wins(tmp_path, monkeypatch):
    """Operator opt-out: PROXY_INTRA_ORG=0 must override the standalone
    default. Useful for intentional "no-traffic" deployments (schema
    validation in CI, etc.)."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("PROXY_INTRA_ORG", "0")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.standalone is True
    assert settings.intra_org_routing is False
    get_settings.cache_clear()
