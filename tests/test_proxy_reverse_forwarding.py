"""ADR-004 PR A — proxy reverse-proxy forwarding for /v1/broker, /v1/auth, /v1/registry.

Verifies that the SDK can hit the proxy at ``http://proxy`` and the request is
transparently forwarded to the broker with auth headers (DPoP, client_assertion
x5c) and Host preserved, so the broker's DPoP ``htu`` check still passes.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.main import app as broker_app  # ensures conftest side-effects load
from tests.cert_factory import get_org_ca_pem, make_assertion
from tests.conftest import ADMIN_HEADERS


# SDK base + broker target share the same URL so scope["server"] and the
# forwarded X-Forwarded-Host/Proto all reconstruct the same htu that the SDK
# signed. uvicorn's --proxy-headers promotion of X-Forwarded-* is out of scope
# under ASGITransport, so matching the URLs is the simplest way to keep the
# DPoP htu comparison honest in-test.
BROKER_TARGET = "http://test"


@pytest_asyncio.fixture
async def proxy_forwarding(tmp_path, monkeypatch):
    """Spin up the proxy app wired to forward /v1/* to the in-memory broker app."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    # Any value — we overwrite app.state.reverse_proxy_client below anyway.
    monkeypatch.setenv("MCP_PROXY_BROKER_URL", BROKER_TARGET)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    # standalone-default flips local_auth on; this test exercises the
    # forward-to-broker reverse-proxy path, so pin local_auth off.
    monkeypatch.setenv("MCP_PROXY_LOCAL_AUTH_ENABLED", "false")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app as proxy_app

    async with proxy_app.router.lifespan_context(proxy_app):
        # Point the proxy's reverse-proxy httpx client at the in-memory broker.
        broker_client = AsyncClient(
            transport=ASGITransport(app=broker_app),
            base_url=BROKER_TARGET,
        )
        proxy_app.state.reverse_proxy_client = broker_client
        proxy_app.state.reverse_proxy_broker_url = BROKER_TARGET

        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://test") as c:
            try:
                yield proxy_app, c
            finally:
                await broker_client.aclose()
    get_settings.cache_clear()


async def _register_agent_on_broker(agent_id: str, org_id: str) -> None:
    """Provision org + CA + agent + approved binding directly on the broker app.

    ADR-010 Phase 6a-4 — ``POST /v1/registry/agents`` is gone. We seed
    the agent row via the direct-DB helper ``seed_court_agent`` (same
    pattern as all the other 6a-3 test migrations) and keep the HTTP
    path only for org + CA + binding, which still flow through public
    endpoints.
    """
    from tests.conftest import seed_court_agent

    async with AsyncClient(
        transport=ASGITransport(app=broker_app), base_url="http://test",
    ) as broker:
        org_secret = org_id + "-secret"
        await broker.post(
            "/v1/registry/orgs",
            json={"org_id": org_id, "display_name": org_id, "secret": org_secret},
            headers=ADMIN_HEADERS,
        )
        await broker.post(
            f"/v1/registry/orgs/{org_id}/certificate",
            json={"ca_certificate": get_org_ca_pem(org_id)},
            headers={"x-org-id": org_id, "x-org-secret": org_secret},
        )
        await seed_court_agent(
            agent_id=agent_id, org_id=org_id,
            display_name=agent_id, capabilities=["test.read"],
        )
        resp = await broker.post(
            "/v1/registry/bindings",
            json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
            headers={"x-org-id": org_id, "x-org-secret": org_secret},
        )
        binding_id = resp.json()["id"]
        await broker.post(
            f"/v1/registry/bindings/{binding_id}/approve",
            headers={"x-org-id": org_id, "x-org-secret": org_secret},
        )


@pytest.mark.asyncio
async def test_reverse_proxy_tags_role_header(proxy_forwarding):
    """Any reverse-proxied response must carry x-cullis-role=proxy."""
    _, client = proxy_forwarding

    # /v1/federation/agents/search without DPoP returns 401 from the broker; we
    # only need to verify the proxy tagged the response and forwarded the path.
    resp = await client.get("/v1/federation/agents/search?pattern=*")
    assert resp.status_code in (401, 422), resp.text
    assert resp.headers.get("x-cullis-role") == "proxy"


