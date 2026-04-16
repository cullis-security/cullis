"""ADR-006 Fase 2 / PR #6 — runtime uplink via /v1/admin/link-broker.

A standalone proxy (no BrokerBridge, no reverse-proxy client) receives
a POST to /v1/admin/link-broker with the admin-derived org_id already
pinned on the broker side. The handler runs attach-ca, persists config,
and *hot-swaps* the BrokerBridge without restarting the ASGI process.
Subsequent requests see the uplinked bridge immediately.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient, Response


@pytest_asyncio.fixture
async def standalone_proxy(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    # No MCP_PROXY_ORG_ID — let the derivation run.
    monkeypatch.delenv("MCP_PROXY_ORG_ID", raising=False)
    monkeypatch.delenv("PROXY_INTRA_ORG", raising=False)
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_BROKER_JWKS_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Admin login so the link-broker endpoint accepts our session.
            await _login_admin(client)
            yield app, client
    get_settings.cache_clear()


async def _login_admin(client: AsyncClient) -> None:
    """Bootstrap the admin cookie. The proxy uses a register-first-login
    flow; we drive it directly so the test isn't a huge browser emulator."""
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password("test-admin-pw")
    resp = await client.post(
        "/proxy/login",
        data={"password": "test-admin-pw"},
        follow_redirects=False,
    )
    # 303 redirect on success.
    assert resp.status_code in (200, 303), resp.text


def _fake_broker(handler):
    """Patch httpx.AsyncClient so the handler intercepts any outbound request.

    Used to stand in for the real broker during tests.
    """
    import httpx

    class _FakeClient:
        def __init__(self, **kwargs):
            self._kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None, **kwargs):
            return await handler("POST", url, json, kwargs)

        async def aclose(self):
            return None

    original = httpx.AsyncClient
    httpx.AsyncClient = _FakeClient
    return original


@pytest.mark.asyncio
async def test_link_broker_hot_swaps_bridge(standalone_proxy, monkeypatch):
    app, client = standalone_proxy

    # Proxy starts with no bridge (standalone reset invariant from PR #125 follow-up).
    assert getattr(app.state, "broker_bridge", None) is None

    # Stand in for the broker: every POST /v1/onboarding/attach returns
    # a 200 with an org_id + status.
    async def handler(method, url, json, kwargs):
        from httpx import Response
        assert method == "POST"
        assert url.endswith("/v1/onboarding/attach")
        assert "ca_certificate" in json
        assert json["invite_token"] == "tok-abc"
        assert json["secret"]  # org_secret must be populated
        return Response(200, json={"org_id": "acme", "status": "attached"})

    original = _fake_broker(handler)
    try:
        resp = await client.post(
            "/v1/admin/link-broker",
            json={
                "broker_url": "https://broker.example.com",
                "invite_token": "tok-abc",
            },
        )
    finally:
        import httpx
        httpx.AsyncClient = original

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "linked"
    assert body["broker_url"] == "https://broker.example.com"
    assert body["org_id"] == "acme"

    # Hot-swap assertions — these are the whole point of the PR.
    assert getattr(app.state, "broker_bridge", None) is not None
    assert app.state.reverse_proxy_broker_url == "https://broker.example.com"
    assert getattr(app.state, "reverse_proxy_client", None) is not None
    assert app.state.org_id == "acme"


@pytest.mark.asyncio
async def test_link_broker_rejects_invalid_url(standalone_proxy):
    _, client = standalone_proxy
    resp = await client.post(
        "/v1/admin/link-broker",
        json={"broker_url": "ftp://nope", "invite_token": "tok"},
    )
    assert resp.status_code == 400
    assert "http" in resp.text.lower()


@pytest.mark.asyncio
async def test_link_broker_requires_login(tmp_path, monkeypatch):
    """No admin session → 401, even with correct body."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.delenv("MCP_PROXY_ORG_ID", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/admin/link-broker",
                json={
                    "broker_url": "https://broker.example.com",
                    "invite_token": "tok",
                },
            )
    assert resp.status_code == 401
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_link_broker_propagates_attach_ca_error(standalone_proxy):
    _, client = standalone_proxy

    async def handler(method, url, json, kwargs):
        return Response(403, text="invite consumed")

    original = _fake_broker(handler)
    try:
        resp = await client.post(
            "/v1/admin/link-broker",
            json={
                "broker_url": "https://broker.example.com",
                "invite_token": "spent-token",
            },
        )
    finally:
        import httpx
        httpx.AsyncClient = original

    assert resp.status_code == 502
    assert "invalid or expired invite" in resp.text.lower()


@pytest.mark.asyncio
async def test_link_broker_persists_config_for_next_boot(standalone_proxy):
    _, client = standalone_proxy

    async def handler(method, url, json, kwargs):
        return Response(200, json={"org_id": "acme", "status": "attached"})

    original = _fake_broker(handler)
    try:
        await client.post(
            "/v1/admin/link-broker",
            json={
                "broker_url": "https://broker.example.com",
                "invite_token": "tok",
            },
        )
    finally:
        import httpx
        httpx.AsyncClient = original

    from mcp_proxy.db import get_config
    assert await get_config("broker_url") == "https://broker.example.com"
    assert await get_config("org_id") == "acme"
    assert await get_config("org_status") == "attached"
