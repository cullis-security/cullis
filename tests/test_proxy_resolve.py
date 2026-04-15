"""ADR-001 §10 — /v1/egress/resolve endpoint.

Verifies the SDK-facing routing decision: given a recipient, the proxy
returns the path (intra-org vs cross-org) plus the wire format the SDK
should use (envelope vs mtls-only) plus target metadata when relevant.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    """Spin up the proxy ASGI app with a fresh sqlite DB and intra-org on."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _provision_internal_agent(agent_id: str = "sender-bot") -> str:
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


async def _provision_local_target(agent_id: str, cert_pem: str | None = "DUMMY-CERT") -> None:
    """Insert a local_agents row so intra-org resolve can find a cert."""
    from datetime import datetime, timezone
    from sqlalchemy import text
    from mcp_proxy.db import get_db

    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO local_agents "
                "(agent_id, display_name, capabilities, cert_pem, api_key_hash, "
                " scope, created_at, is_active) "
                "VALUES (:agent_id, :display_name, :capabilities, :cert_pem, "
                " :api_key_hash, :scope, :created_at, :is_active)"
            ),
            {
                "agent_id": agent_id,
                "display_name": agent_id,
                "capabilities": "[]",
                "cert_pem": cert_pem,
                "api_key_hash": None,
                "scope": "local",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": 1,
            },
        )


@pytest.mark.asyncio
async def test_resolve_cross_org(proxy_app):
    _, client = proxy_app
    api_key = await _provision_internal_agent("sender-bot")

    resp = await client.post(
        "/v1/egress/resolve",
        headers={"X-API-Key": api_key},
        json={"recipient_id": "spiffe://cullis.local/other-org/bob"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["path"] == "cross-org"
    assert body["transport"] == "envelope"
    assert body["target_agent_id"] == "bob"
    assert body["target_org_id"] == "other-org"
    assert body["target_cert_pem"] is None


@pytest.mark.asyncio
async def test_resolve_intra_default_stays_envelope(proxy_app):
    _, client = proxy_app
    api_key = await _provision_internal_agent("sender-bot")

    resp = await client.post(
        "/v1/egress/resolve",
        headers={"X-API-Key": api_key},
        json={"recipient_id": "acme::peer-bot"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["path"] == "intra-org"
    assert body["transport"] == "envelope"
    assert body["target_cert_pem"] is None


@pytest.mark.asyncio
async def test_resolve_intra_mtls_only_returns_cert(proxy_app, monkeypatch):
    app, client = proxy_app
    monkeypatch.setenv("PROXY_TRANSPORT_INTRA_ORG", "mtls-only")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    api_key = await _provision_internal_agent("sender-bot")
    await _provision_local_target("peer-bot", cert_pem="-----BEGIN CERT-----\nX\n-----END CERT-----")

    resp = await client.post(
        "/v1/egress/resolve",
        headers={"X-API-Key": api_key},
        json={"recipient_id": "acme::peer-bot"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["path"] == "intra-org"
    assert body["transport"] == "mtls-only"
    assert body["target_cert_pem"].startswith("-----BEGIN CERT-----")


@pytest.mark.asyncio
async def test_resolve_intra_mtls_only_missing_target(proxy_app, monkeypatch):
    _, client = proxy_app
    monkeypatch.setenv("PROXY_TRANSPORT_INTRA_ORG", "mtls-only")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    api_key = await _provision_internal_agent("sender-bot")
    # deliberately do NOT provision the target

    resp = await client.post(
        "/v1/egress/resolve",
        headers={"X-API-Key": api_key},
        json={"recipient_id": "acme::ghost-bot"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_resolve_rejects_malformed_recipient(proxy_app):
    _, client = proxy_app
    api_key = await _provision_internal_agent("sender-bot")

    resp = await client.post(
        "/v1/egress/resolve",
        headers={"X-API-Key": api_key},
        json={"recipient_id": "not-a-valid-id"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_resolve_reflects_egress_inspection_flag(proxy_app, monkeypatch):
    _, client = proxy_app
    monkeypatch.setenv("PROXY_EGRESS_INSPECTION_ENABLED", "true")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    api_key = await _provision_internal_agent("sender-bot")
    resp = await client.post(
        "/v1/egress/resolve",
        headers={"X-API-Key": api_key},
        json={"recipient_id": "spiffe://cullis.local/other/bob"},
    )
    assert resp.status_code == 200
    assert resp.json()["egress_inspection"] is True
