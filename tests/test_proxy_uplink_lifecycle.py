"""ADR-006 Fase 2 / PR #9 — end-to-end uplink → federated → unlink lifecycle.

Closes the acceptance chain for the Trojan Horse upsell: a proxy boots
standalone, admin links it at runtime to a broker, cross-org peers
become visible via /v1/agents/search, admin unlinks, standalone
behaviors (and intra-org state) remain intact.

The Docker federated smoke (``./demo_network/smoke.sh``) already
exercises a long-lived federated topology with real sender →
proxy → broker → proxy → checker traffic. This test covers the
delta that the smoke can't easily reproduce: the *transition* between
modes at runtime, via /v1/admin/link-broker and /v1/admin/unlink-broker.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import text

from tests._mtls_helpers import provision_internal_agent


@pytest_asyncio.fixture
async def standalone_proxy(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    # Fix org_id to "acme" so tests can compare against target_org_id="acme"
    # without having to recompute the deterministic hash. The derivation
    # path is exercised by tests/test_proxy_deterministic_org_id.py.
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.delenv("PROXY_INTRA_ORG", raising=False)
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_BROKER_JWKS_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            from mcp_proxy.dashboard.session import set_admin_password
            await set_admin_password("test-admin-pw")
            await client.post(
                "/proxy/login",
                data={"password": "test-admin-pw"},
                follow_redirects=False,
            )
            yield app, client
    get_settings.cache_clear()


def _patch_httpx_client(handler):
    import httpx

    class _FakeClient:
        def __init__(self, **kwargs): self._kwargs = kwargs
        async def __aenter__(self): return self
        async def __aexit__(self, *exc): return False

        async def post(self, url, json=None, **kwargs):
            return await handler("POST", url, json, kwargs)

        async def aclose(self): return None

    original = httpx.AsyncClient
    httpx.AsyncClient = _FakeClient
    return original


async def _provision_agent(agent_id: str) -> dict[str, str]:
    """Provision the agent via mTLS helper — the cert IS the credential
    after ADR-014. Returns the nginx-shaped headers ready for the test
    client to forward."""
    return await provision_internal_agent(
        agent_id, capabilities=["cap.read", "cap.write"],
    )


async def _seed_cached_federated_agent(agent_id: str, org_id: str) -> None:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(text("""
            INSERT INTO cached_federated_agents (
                agent_id, org_id, display_name, capabilities,
                thumbprint, revoked, updated_at
            ) VALUES (:aid, :org, :aid, '["cap.peer"]', NULL, 0,
                      '2026-04-16T00:00:00Z')
        """), {"aid": agent_id, "org": org_id})


# ── Full lifecycle ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_standalone_to_federated_to_standalone(standalone_proxy):
    """The ADR-006 Fase 2 acceptance scenario in one test.

      1. Standalone: intra-org messaging works, bridge is None.
      2. Link: attach-ca succeeds, bridge + reverse-proxy client live,
         cross-org discovery merges local + cached federated rows.
      3. Unlink: bridge teardown, cache cleared, intra-org STILL
         works, agents' API keys are unchanged.
    """
    app, client = standalone_proxy

    # 1. Standalone baseline.
    assert getattr(app.state, "broker_bridge", None) is None
    alice_headers = await _provision_agent("alice-bot")
    bob_headers = await _provision_agent("bob-bot")

    discover = await client.get("/v1/agents/search", headers=alice_headers)
    assert discover.status_code == 200
    ids = {a["agent_id"] for a in discover.json()["agents"]}
    assert ids == {"acme::alice-bot", "acme::bob-bot"}
    assert all(a["scope"] == "local" for a in discover.json()["agents"])

    # Intra-org open/send/ack/close roundtrip succeeds (sanity).
    open_resp = await client.post(
        "/v1/egress/sessions",
        headers=alice_headers,
        json={
            "target_agent_id": "acme::bob-bot",
            "target_org_id": "acme",
            "capabilities": ["cap.read"],
        },
    )
    assert open_resp.status_code == 200
    session_id = open_resp.json()["session_id"]
    await client.post(
        f"/v1/egress/sessions/{session_id}/accept",
        headers=bob_headers,
    )

    # 2. Link the proxy to a (mock) broker.
    async def attach_handler(method, url, json, kwargs):
        assert method == "POST"
        assert url.endswith("/v1/onboarding/attach")
        return Response(200, json={"org_id": "acme", "status": "attached"})

    import httpx
    original = _patch_httpx_client(attach_handler)
    try:
        link_resp = await client.post(
            "/v1/admin/link-broker",
            json={
                "broker_url": "https://broker.example.com",
                "invite_token": "tok-abc",
            },
        )
    finally:
        httpx.AsyncClient = original
    assert link_resp.status_code == 200, link_resp.text
    assert link_resp.json()["status"] == "linked"
    assert app.state.broker_bridge is not None
    assert app.state.reverse_proxy_broker_url == "https://broker.example.com"

    # Agents survived the uplink: their API keys still authenticate.
    re_discover = await client.get(
        "/v1/agents/search", headers=alice_headers,
    )
    assert re_discover.status_code == 200, re_discover.text
    assert "acme::alice-bot" in {a["agent_id"] for a in re_discover.json()["agents"]}

    # Cross-org peer visible once SSE subscriber populates the cache —
    # we simulate the subscriber by seeding cached_federated_agents.
    await _seed_cached_federated_agent("partner-bot", "contoso")
    merged = await client.get("/v1/agents/search", headers=alice_headers)
    by_id = {a["agent_id"]: a for a in merged.json()["agents"]}
    assert by_id["acme::alice-bot"]["scope"] == "local"
    assert by_id["partner-bot"]["scope"] == "federated"
    assert by_id["partner-bot"]["org_id"] == "contoso"

    # 3. Unlink the proxy. No active cross-org clients → no ?force=1 needed.
    unlink = await client.post("/v1/admin/unlink-broker", json={})
    assert unlink.status_code == 200, unlink.text
    assert unlink.json()["status"] == "unlinked"

    assert getattr(app.state, "broker_bridge", None) is None
    assert getattr(app.state, "reverse_proxy_client", None) is None

    # Federation cache wiped: partner-bot disappears from discovery.
    post_unlink = await client.get(
        "/v1/agents/search", headers=alice_headers,
    )
    ids_after = {a["agent_id"] for a in post_unlink.json()["agents"]}
    assert "partner-bot" not in ids_after
    # Intra-org rows still there — that was always the invariant.
    assert "acme::alice-bot" in ids_after
    assert "acme::bob-bot" in ids_after

    # Same cert, same session: intra-org send still works.
    send = await client.post(
        "/v1/egress/send",
        headers=alice_headers,
        json={
            "session_id": session_id,
            "payload": {"after": "unlink"},
            "recipient_agent_id": "acme::bob-bot",
            "mode": "envelope",
        },
    )
    assert send.status_code == 200, send.text


@pytest.mark.asyncio
async def test_unlink_refuses_when_attach_ca_returns_non_200(standalone_proxy):
    """If attach-ca fails, the proxy must stay standalone — no half-
    initialized bridge, no persisted config drift."""
    app, client = standalone_proxy

    async def attach_handler(method, url, json, kwargs):
        return Response(403, text="invite consumed")

    import httpx
    original = _patch_httpx_client(attach_handler)
    try:
        resp = await client.post(
            "/v1/admin/link-broker",
            json={
                "broker_url": "https://broker.example.com",
                "invite_token": "dead",
            },
        )
    finally:
        httpx.AsyncClient = original

    assert resp.status_code == 502
    assert getattr(app.state, "broker_bridge", None) is None

    # Config rows must NOT have been written — a later link attempt
    # can't inherit partial state.
    from mcp_proxy.db import get_config
    assert (await get_config("broker_url") or "") == ""


@pytest.mark.asyncio
async def test_agents_certs_survive_uplink_cycle(standalone_proxy):
    """The whole Trojan Horse pitch hinges on this: agents enrolled
    pre-uplink keep their creds after link *and* after unlink. No
    re-provisioning, no cert rotation, nothing."""
    app, client = standalone_proxy
    alice_headers = await _provision_agent("alice-bot")

    from mcp_proxy.db import get_agent
    before = await get_agent("acme::alice-bot")

    async def attach_handler(method, url, json, kwargs):
        return Response(200, json={"org_id": "acme", "status": "attached"})

    import httpx
    original = _patch_httpx_client(attach_handler)
    try:
        await client.post(
            "/v1/admin/link-broker",
            json={
                "broker_url": "https://broker.example.com",
                "invite_token": "tok",
            },
        )
    finally:
        httpx.AsyncClient = original

    after_link = await get_agent("acme::alice-bot")
    assert before["api_key_hash"] == after_link["api_key_hash"]
    assert before["cert_pem"] == after_link["cert_pem"]

    await client.post("/v1/admin/unlink-broker", json={})

    after_unlink = await get_agent("acme::alice-bot")
    assert before["api_key_hash"] == after_unlink["api_key_hash"]

    # And the cert still authenticates — proof the cred survived both
    # state transitions end-to-end.
    probe = await client.get("/v1/agents/search", headers=alice_headers)
    assert probe.status_code == 200
