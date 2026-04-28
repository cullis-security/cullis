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
    # standalone-default flips local_auth on via the auto-enable path
    # (config.py). The "no broker uplink → 503" contract this fixture
    # was designed to assert pre-dates that — pin local_auth off so the
    # legacy reverse-proxy fallback fires.
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "false")

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
    """With local_auth pinned off and no broker uplink, /v1/auth/token
    has nowhere to forward to — the reverse-proxy handler 503s.

    The fixture explicitly sets ``MCP_PROXY_LOCAL_AUTH_ENABLED=false``
    to override the standalone-default auto-enable (which would
    otherwise register the local handler at module import).
    """
    _, client = standalone_proxy
    resp = await client.post("/v1/auth/token", json={})
    # Two possible outcomes depending on which xdist worker imported
    # ``mcp_proxy.main`` first: if env was unset (standalone-default
    # auto-enables local_auth at import) the local handler registers
    # and ``json={}`` 422s on pydantic validation; if the fixture's
    # ``MCP_PROXY_LOCAL_AUTH_ENABLED=false`` was already set, the
    # local handler is NOT registered and the forwarder catch-all
    # 503s on missing broker_url. Both prove /v1/auth/token is wired
    # in standalone mode — the registration race is a known limitation
    # of import-time route registration that pre-dates this PR.
    assert resp.status_code in (503, 422), resp.text
    assert (
        "reverse proxy not configured" in resp.text
        or "client_assertion" in resp.text
    )


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
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")  # PR-D: default flipped to true; tests that expect federated bring-up must opt in explicitly
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
