"""#114 — MCP_PROXY_STANDALONE flag.

Standalone deploy skips broker uplink entirely: no BrokerBridge, no
reverse-proxy httpx client, /readyz does not fail on missing JWKS, and
the reverse-proxy catch-all returns 503 since there is nothing to
forward to.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def standalone_proxy(tmp_path, monkeypatch):
    """Proxy ASGI app booted with MCP_PROXY_STANDALONE=true and no broker_url."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
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


@pytest.mark.asyncio
async def test_standalone_lifespan_skips_broker_bridge(standalone_proxy):
    app, _ = standalone_proxy
    assert getattr(app.state, "broker_bridge", None) is None, (
        "BrokerBridge must not initialize in standalone mode"
    )
    assert getattr(app.state, "reverse_proxy_broker_url", None) is None
    assert getattr(app.state, "reverse_proxy_client", None) is None


@pytest.mark.asyncio
async def test_standalone_readyz_is_ready_without_jwks(standalone_proxy):
    _, client = standalone_proxy
    resp = await client.get("/readyz")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["jwks_cache"] == "standalone"


@pytest.mark.asyncio
async def test_standalone_reverse_proxy_returns_503(standalone_proxy):
    """With no broker uplink, /v1/auth/token has nowhere to forward to."""
    _, client = standalone_proxy
    resp = await client.post("/v1/auth/token", json={})
    assert resp.status_code == 503
    assert "reverse proxy not configured" in resp.text


@pytest.mark.asyncio
async def test_standalone_mode_header_on_health(standalone_proxy):
    _, client = standalone_proxy
    resp = await client.get("/health")
    assert resp.headers.get("x-cullis-mode") == "standalone"


@pytest.mark.asyncio
async def test_federation_mode_default_header(tmp_path, monkeypatch):
    """Default boot (no STANDALONE) advertises federation mode."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.delenv("MCP_PROXY_STANDALONE", raising=False)
    # Give it a broker URL so BrokerBridge spins up cleanly.
    monkeypatch.setenv("MCP_PROXY_BROKER_URL", "http://broker.example")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
            assert resp.headers.get("x-cullis-mode") == "federation"
    get_settings.cache_clear()
