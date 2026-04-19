"""Tests for /v1/egress/peers — Connector-friendly peer listing.

The endpoint powers the Connector's intent-level ``contact("name")``
flow. It must work under API-key + DPoP auth (no broker JWT) so that
device-code-enrolled agents can use it on a standalone Mastio.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text


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


async def _provision_caller(agent_id: str = "caller-bot") -> str:
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
    api_key = await _provision_caller("caller-bot")
    await _provision_local_peer("mario", "Mario Rossi")
    await _provision_local_peer("maria", "Maria Bianchi")

    resp = await client.get(
        "/v1/egress/peers",
        headers={"X-API-Key": api_key},
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
    api_key = await _provision_caller("caller-bot")
    await _provision_local_peer("mario", "Mario Rossi")
    await _provision_local_peer("salesbot", "Sales Bot")

    resp = await client.get(
        "/v1/egress/peers",
        headers={"X-API-Key": api_key},
        params={"q": "mario"},
    )
    assert resp.status_code == 200
    handles = [p["agent_id"] for p in resp.json()["peers"]]
    assert handles == ["acme::mario"]


@pytest.mark.asyncio
async def test_peers_filter_matches_display_name(proxy_app):
    _, client = proxy_app
    api_key = await _provision_caller("caller-bot")
    await _provision_local_peer("agent-x42", "Mario Rossi")

    resp = await client.get(
        "/v1/egress/peers",
        headers={"X-API-Key": api_key},
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
    api_key = await _provision_caller("caller-bot")
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
        headers={"X-API-Key": api_key},
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
