"""Tests for /v1/egress/peers — Connector-friendly peer listing.

The endpoint powers the Connector's intent-level ``contact("name")``
flow. It must work under client-cert + DPoP auth (no broker JWT) so
that device-code-enrolled agents can use it on a standalone Mastio.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from tests._mtls_helpers import provision_internal_agent


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _provision_caller(agent_id: str = "caller-bot") -> dict[str, str]:
    """Insert a caller agent and return the mTLS headers nginx forwards."""
    return await provision_internal_agent(agent_id, capabilities=["cap.read"])


async def _provision_local_peer(agent_id: str, display_name: str = "", capabilities: str = "[]") -> None:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO internal_agents "
                "(agent_id, display_name, capabilities, api_key_hash, created_at, is_active) "
                "VALUES (:agent_id, :display_name, :capabilities, "
                " :api_key_hash, :created_at, :is_active)"
            ),
            {
                "agent_id": agent_id,
                "display_name": display_name,
                "capabilities": capabilities,
                "api_key_hash": "$2b$12$placeholder",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": 1,
            },
        )


@pytest.mark.asyncio
async def test_peers_lists_intra_org_excluding_caller(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller("caller-bot")
    await _provision_local_peer("mario", "Mario Rossi")
    await _provision_local_peer("maria", "Maria Bianchi")

    resp = await client.get(
        "/v1/egress/peers",
        headers=caller_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    handles = {p["agent_id"] for p in body["peers"]}
    assert "acme::mario" in handles
    assert "acme::maria" in handles
    # Caller never appears in their own contact list.
    assert "caller-bot" not in handles
    assert "acme::caller-bot" not in handles
    # All intra-org rows tagged accordingly.
    assert all(p["scope"] == "intra-org" for p in body["peers"])
    assert all(p["org_id"] == "acme" for p in body["peers"])


@pytest.mark.asyncio
async def test_peers_substring_filter(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller("caller-bot")
    await _provision_local_peer("mario", "Mario Rossi")
    await _provision_local_peer("salesbot", "Sales Bot")

    resp = await client.get(
        "/v1/egress/peers",
        headers=caller_headers,
        params={"q": "mario"},
    )
    assert resp.status_code == 200
    handles = [p["agent_id"] for p in resp.json()["peers"]]
    assert handles == ["acme::mario"]


@pytest.mark.asyncio
async def test_peers_filter_matches_display_name(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller("caller-bot")
    await _provision_local_peer("agent-x42", "Mario Rossi")

    resp = await client.get(
        "/v1/egress/peers",
        headers=caller_headers,
        params={"q": "Mario"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["peers"][0]["agent_id"] == "acme::agent-x42"
    assert body["peers"][0]["display_name"] == "Mario Rossi"


@pytest.mark.asyncio
async def test_peers_inactive_agents_excluded(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller("caller-bot")
    await _provision_local_peer("active-one", "Active")

    # Mark a second agent inactive directly.
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO internal_agents "
                "(agent_id, display_name, capabilities, api_key_hash, created_at, is_active) "
                "VALUES ('disabled-one', 'Disabled', '[]', '$2b$12$x', :ts, 0)"
            ),
            {"ts": datetime.now(timezone.utc).isoformat()},
        )

    resp = await client.get(
        "/v1/egress/peers",
        headers=caller_headers,
    )
    assert resp.status_code == 200
    handles = [p["agent_id"] for p in resp.json()["peers"]]
    assert "acme::active-one" in handles
    assert "acme::disabled-one" not in handles


@pytest.mark.asyncio
async def test_peers_requires_auth(proxy_app):
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers")
    # Same shape as every other /v1/egress/* endpoint without API-key.
    assert resp.status_code in (401, 403, 422)


# ── Reach filter (audit NEW #4) ─────────────────────────────────────
#
# The send-path reach gate is enforced in ``reach_guard.check_reach``;
# the listing path must apply the same discipline at the SQL layer so
# an intra-only agent never receives cross-org handles in the first
# place (layering defence-in-depth). These three cases pin the
# filter behaviour for intra / cross / both.

async def _set_reach(agent_id: str, reach: str) -> None:
    """Flip ``internal_agents.reach`` for an already-provisioned row."""
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text("UPDATE internal_agents SET reach = :reach WHERE agent_id = :aid"),
            {"reach": reach, "aid": agent_id},
        )


async def _seed_cross_org_peer(agent_id: str, org_id: str) -> None:
    """Seed a cached cross-org peer row the way federation would."""
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO cached_federated_agents (
                    agent_id, org_id, display_name, capabilities,
                    thumbprint, revoked, updated_at
                ) VALUES (:aid, :org, :aid, '["cap.peer"]', NULL, 0,
                          '2026-04-19T00:00:00Z')
                """
            ),
            {"aid": agent_id, "org": org_id},
        )


@pytest.mark.asyncio
async def test_peers_reach_intra_hides_cross_org(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller("caller-bot")
    await _set_reach("acme::caller-bot", "intra")
    await _provision_local_peer("mario", "Mario Rossi")
    await _seed_cross_org_peer("remote-bot", "orgb")

    resp = await client.get("/v1/egress/peers", headers=caller_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    scopes = {p["scope"] for p in body["peers"]}
    assert scopes == {"intra-org"}
    handles = {p["agent_id"] for p in body["peers"]}
    assert "acme::mario" in handles
    assert "remote-bot" not in handles


@pytest.mark.asyncio
async def test_peers_reach_cross_hides_intra_org(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller("caller-bot")
    await _set_reach("acme::caller-bot", "cross")
    await _provision_local_peer("mario", "Mario Rossi")
    await _seed_cross_org_peer("remote-bot", "orgb")

    resp = await client.get("/v1/egress/peers", headers=caller_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    scopes = {p["scope"] for p in body["peers"]}
    assert scopes == {"cross-org"}
    handles = {p["agent_id"] for p in body["peers"]}
    assert "remote-bot" in handles
    assert "acme::mario" not in handles


@pytest.mark.asyncio
async def test_peers_reach_both_returns_all(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller("caller-bot")
    # ``both`` is the DB default but pin it explicitly so the test
    # documents the contract rather than relying on a server_default.
    await _set_reach("acme::caller-bot", "both")
    await _provision_local_peer("mario", "Mario Rossi")
    await _seed_cross_org_peer("remote-bot", "orgb")

    resp = await client.get("/v1/egress/peers", headers=caller_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    scopes = {p["scope"] for p in body["peers"]}
    assert scopes == {"intra-org", "cross-org"}
    handles = {p["agent_id"] for p in body["peers"]}
    assert "acme::mario" in handles
    assert "remote-bot" in handles


@pytest.mark.asyncio
async def test_peers_writes_audit_entry(proxy_app):
    """Security audit NEW #6 — peer enumeration must land in the
    audit log. Before this fix, /v1/egress/peers had no audit write,
    so a Connector's discover_agents (which now routes through here
    instead of /v1/federation/agents/search) left no compliance
    trail of who listed whom.
    """
    from mcp_proxy.db import get_db

    _, client = proxy_app
    caller_headers = await _provision_caller("caller-bot")
    await _provision_local_peer("mario", "Mario Rossi")

    resp = await client.get(
        "/v1/egress/peers",
        headers=caller_headers,
        params={"q": "mar"},
    )
    assert resp.status_code == 200, resp.text

    async with get_db() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT agent_id, action, status, detail FROM audit_log "
                    "WHERE action = 'egress_peers_list' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
        ).first()
    assert row is not None, "expected an egress_peers_list audit row"
    assert row[0] == "acme::caller-bot"
    assert row[1] == "egress_peers_list"
    assert row[2] == "success"
    # detail should capture the query + result count so the audit is
    # useful without cross-referencing request logs.
    assert "q=mar" in row[3]
    assert "results=1" in row[3]
