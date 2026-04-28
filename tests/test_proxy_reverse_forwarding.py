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


@pytest.mark.skip(
    reason="ADR-012 + PR-D: standalone-default boots the local /v1/auth/token "
           "handler at module import, so /v1/auth/token never falls through to "
           "the reverse-proxy forwarder. DPoP htu / x5c propagation is now "
           "tested via the local handler path (test_proxy_local_token.py)."
)
@pytest.mark.asyncio
async def test_auth_token_via_proxy(proxy_forwarding, dpop):
    """Agent auth via proxy: DPoP htu and x5c both propagate so broker accepts."""
    _, client = proxy_forwarding

    org_id = f"rp-org-{uuid.uuid4().hex[:6]}"
    agent_id = f"{org_id}::agent-1"
    await _register_agent_on_broker(agent_id, org_id)

    # Prime the DPoP nonce via the proxy (health endpoint lives on the proxy
    # itself, so prime directly from the broker to match the DPoP helper).
    async with AsyncClient(
        transport=ASGITransport(app=broker_app), base_url="http://test",
    ) as broker:
        prime = await broker.get("/health")
        dpop._update_nonce(prime)

    assertion = make_assertion(agent_id, org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "DPoP"
    assert body["access_token"]
    # The proxy tags every reverse-proxied response so SDKs can detect role.
    assert resp.headers.get("x-cullis-role") == "proxy"


@pytest.mark.skip(
    reason="ADR-012 + PR-D: see test_auth_token_via_proxy. /v1/auth/token "
           "doesn't reach the reverse-proxy forwarder; the local handler "
           "is responsible for DPoP-Nonce now."
)
@pytest.mark.asyncio
async def test_dpop_nonce_header_propagates(proxy_forwarding, dpop):
    """Broker-issued DPoP-Nonce header must survive reverse-proxy forwarding."""
    _, client = proxy_forwarding

    org_id = f"rp-nonce-{uuid.uuid4().hex[:6]}"
    agent_id = f"{org_id}::agent-1"
    await _register_agent_on_broker(agent_id, org_id)

    # Send a proof without a nonce — the broker replies 401 use_dpop_nonce
    # with a fresh DPoP-Nonce header. The proxy must forward that header
    # verbatim so the SDK can retry with it.
    dpop._nonce = None
    assertion = make_assertion(agent_id, org_id)
    proof_no_nonce = dpop.proof("POST", "/v1/auth/token", nonce=None)
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof_no_nonce},
    )
    assert resp.status_code == 401
    assert "use_dpop_nonce" in resp.text
    assert resp.headers.get("dpop-nonce"), "proxy dropped DPoP-Nonce header"
    assert resp.headers.get("x-cullis-role") == "proxy"


@pytest.mark.asyncio
async def test_reverse_proxy_tags_role_header(proxy_forwarding):
    """Any reverse-proxied response must carry x-cullis-role=proxy."""
    _, client = proxy_forwarding

    # /v1/federation/agents/search without DPoP returns 401 from the broker; we
    # only need to verify the proxy tagged the response and forwarded the path.
    resp = await client.get("/v1/federation/agents/search?pattern=*")
    assert resp.status_code in (401, 422), resp.text
    assert resp.headers.get("x-cullis-role") == "proxy"


@pytest.mark.skip(
    reason="ADR-012 + PR-D: see test_auth_token_via_proxy. The 503 "
           "broker_url-missing short-circuit no longer fires for /v1/auth/token "
           "(local handler intercepts). The reverse-proxy 503 path is still "
           "exercised on other forwarded routes."
)
@pytest.mark.asyncio
async def test_reverse_proxy_503_when_broker_url_unset(proxy_forwarding):
    """With no broker_url configured, the reverse proxy short-circuits 503."""
    proxy_app, client = proxy_forwarding
    proxy_app.state.reverse_proxy_broker_url = None

    resp = await client.post("/v1/auth/token", json={})
    assert resp.status_code == 503, resp.text
