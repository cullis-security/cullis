"""Tests for ``GET /v1/egress/agents/{agent_id}/public-key``.

Companion endpoint to ``/v1/egress/resolve`` that returns the target
agent's PEM cert behind the same client-cert + DPoP auth profile
(ADR-014). Used by the Connector SDK's ``decrypt_oneshot`` fetcher
to avoid the broker-JWT path device-code enrollments cannot use.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from tests._mtls_helpers import provision_internal_agent


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    """Fresh sqlite-backed proxy with intra-org routing on."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")  # PR-D: default flipped to true; tests that expect federated bring-up must opt in explicitly
    monkeypatch.delenv("PROXY_TRANSPORT_INTRA_ORG", raising=False)

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


async def _provision_target(
    agent_id: str,
    cert_pem: str | None = "-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----",
    is_active: bool = True,
) -> None:
    from datetime import datetime, timezone
    from sqlalchemy import text
    from mcp_proxy.db import get_db

    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO internal_agents "
                "(agent_id, display_name, capabilities, cert_pem, "
                " created_at, is_active) "
                "VALUES (:agent_id, :display_name, :capabilities, :cert_pem, "
                " :created_at, :is_active)"
            ),
            {
                "agent_id": agent_id,
                "display_name": agent_id,
                "capabilities": "[]",
                "cert_pem": cert_pem,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": 1 if is_active else 0,
            },
        )


@pytest.mark.asyncio
async def test_pubkey_intra_org_canonical_form(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller()
    await _provision_target("acme::alice", cert_pem="INTRA-ALICE-CERT")

    resp = await client.get(
        "/v1/egress/agents/acme::alice/public-key",
        headers=caller_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == "acme::alice"
    assert body["cert_pem"] == "INTRA-ALICE-CERT"


@pytest.mark.asyncio
async def test_pubkey_intra_org_bare_legacy_row(proxy_app):
    """Legacy fixtures still store ``agent_id = 'alice'`` without the
    ``<org>::`` prefix. ``/resolve`` falls back to the bare row, so the
    pubkey endpoint must too — otherwise Connectors pointed at an
    upgraded proxy can't decrypt messages from legacy senders."""
    _, client = proxy_app
    caller_headers = await _provision_caller()
    await _provision_target("alice", cert_pem="LEGACY-ALICE-CERT")

    resp = await client.get(
        "/v1/egress/agents/acme::alice/public-key",
        headers=caller_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == "acme::alice"
    assert body["cert_pem"] == "LEGACY-ALICE-CERT"


@pytest.mark.asyncio
async def test_pubkey_intra_org_not_found(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller()

    resp = await client.get(
        "/v1/egress/agents/acme::ghost/public-key",
        headers=caller_headers,
    )
    assert resp.status_code == 404
    assert "acme::ghost" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_pubkey_intra_org_inactive(proxy_app):
    _, client = proxy_app
    caller_headers = await _provision_caller()
    await _provision_target("acme::retired", cert_pem="OLD", is_active=False)

    resp = await client.get(
        "/v1/egress/agents/acme::retired/public-key",
        headers=caller_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_pubkey_cross_org_standalone_no_bridge(proxy_app):
    """Pure standalone (no broker_bridge): cross-org target returns
    ``cert_pem=None`` rather than 400 — mirrors ``/resolve``'s contract
    so callers don't need to branch on standalone detection."""
    _, client = proxy_app
    caller_headers = await _provision_caller()

    resp = await client.get(
        "/v1/egress/agents/other-org::bob/public-key",
        headers=caller_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == "other-org::bob"
    assert body["cert_pem"] is None


@pytest.mark.asyncio
async def test_pubkey_cross_org_bridge_fetches(proxy_app):
    """When a broker bridge is wired, cross-org lookups delegate to
    ``bridge.get_peer_public_key`` exactly like ``/resolve``."""
    app, client = proxy_app
    caller_headers = await _provision_caller()

    class _StubBridge:
        async def get_peer_public_key(self, caller_agent_id, target):
            assert target == "other-org::bob"
            return "-----BEGIN CERTIFICATE-----\nCROSS-BOB\n-----END CERTIFICATE-----"

    app.state.broker_bridge = _StubBridge()
    try:
        resp = await client.get(
            "/v1/egress/agents/other-org::bob/public-key",
            headers=caller_headers,
        )
    finally:
        app.state.broker_bridge = None
    assert resp.status_code == 200, resp.text
    assert "CROSS-BOB" in resp.json()["cert_pem"]


@pytest.mark.asyncio
async def test_pubkey_cross_org_bridge_error_502(proxy_app):
    """Bridge fetch errors surface as 502 so callers can retry."""
    app, client = proxy_app
    caller_headers = await _provision_caller()

    class _FailingBridge:
        async def get_peer_public_key(self, caller_agent_id, target):
            raise RuntimeError("broker unreachable")

    app.state.broker_bridge = _FailingBridge()
    try:
        resp = await client.get(
            "/v1/egress/agents/other-org::bob/public-key",
            headers=caller_headers,
        )
    finally:
        app.state.broker_bridge = None
    assert resp.status_code == 502
    assert "broker unreachable" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_pubkey_rejects_bare_agent_id(proxy_app):
    """Bare ``<name>`` with no ``::`` is ambiguous server-side —
    parse_recipient raises InvalidRecipient, handler returns 400."""
    _, client = proxy_app
    caller_headers = await _provision_caller()

    resp = await client.get(
        "/v1/egress/agents/bob/public-key",
        headers=caller_headers,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_pubkey_rejects_anonymous(proxy_app):
    """No client cert → ``get_agent_from_client_cert`` returns 401."""
    _, client = proxy_app

    resp = await client.get("/v1/egress/agents/acme::alice/public-key")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_pubkey_rate_limit_shared_with_egress_budget(
    proxy_app, monkeypatch,
):
    """The endpoint inherits the per-agent egress rate-limit from
    ``get_agent_from_client_cert`` — burning through the quota on this path
    still returns 429 before the handler runs (so an enumeration-probing
    caller cannot scan the agent namespace any faster than any other
    ``/v1/egress/*`` call)."""
    _, client = proxy_app
    caller_headers = await _provision_caller()
    await _provision_target("acme::alice")

    # Collapse the per-minute quota to a tiny budget so the test runs
    # fast. ``rate_limit_per_minute`` is read from settings at request
    # time via ``get_settings()``.
    monkeypatch.setenv("MCP_PROXY_RATE_LIMIT_PER_MINUTE", "3")
    from mcp_proxy.config import get_settings
    from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter
    get_settings.cache_clear()
    reset_agent_rate_limiter()

    try:
        headers = caller_headers
        statuses = []
        for _ in range(5):
            resp = await client.get(
                "/v1/egress/agents/acme::alice/public-key",
                headers=headers,
            )
            statuses.append(resp.status_code)
        # First 3 succeed, the rest are 429.
        assert statuses[:3] == [200, 200, 200], statuses
        assert 429 in statuses[3:], statuses
    finally:
        monkeypatch.delenv("MCP_PROXY_RATE_LIMIT_PER_MINUTE", raising=False)
        get_settings.cache_clear()
        reset_agent_rate_limiter()


# ── Audit 2026-04-30 lane 3 M2 — reach gate on cross-org public-key ─


async def _set_caller_reach(agent_id: str, reach: str) -> None:
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text("UPDATE internal_agents SET reach=:r WHERE agent_id=:aid"),
            {"r": reach, "aid": agent_id},
        )


@pytest.mark.asyncio
async def test_pubkey_cross_org_blocked_when_caller_reach_is_intra(proxy_app):
    """Audit 2026-04-30 lane 3 M2 — an ``intra``-only agent must NOT
    fetch cross-org peer public keys, even though the call is
    nominally read-only. Without the gate, intra agents can pre-cache
    cross-org keys ahead of paths that would later refuse send.
    """
    app, client = proxy_app
    caller_headers = await _provision_caller("acme::intra-bot")
    await _set_caller_reach("acme::intra-bot", "intra")

    class _StubBridge:
        async def get_peer_public_key(self, caller_agent_id, target):
            raise AssertionError("bridge MUST NOT be reached for reach=intra")

    app.state.broker_bridge = _StubBridge()
    try:
        resp = await client.get(
            "/v1/egress/agents/other-org::bob/public-key",
            headers=caller_headers,
        )
    finally:
        app.state.broker_bridge = None

    assert resp.status_code == 403, resp.text
    assert "reach" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_pubkey_cross_org_allowed_when_caller_reach_is_both(proxy_app):
    """Default reach=both keeps the cross-org cert fetch working."""
    app, client = proxy_app
    caller_headers = await _provision_caller("acme::both-bot")
    # reach default is "both"; explicit set just to pin the contract.
    await _set_caller_reach("acme::both-bot", "both")

    class _StubBridge:
        async def get_peer_public_key(self, caller_agent_id, target):
            return "-----BEGIN CERTIFICATE-----\nCROSS\n-----END CERTIFICATE-----"

    app.state.broker_bridge = _StubBridge()
    try:
        resp = await client.get(
            "/v1/egress/agents/other-org::bob/public-key",
            headers=caller_headers,
        )
    finally:
        app.state.broker_bridge = None
    assert resp.status_code == 200, resp.text
    assert "CROSS" in resp.json()["cert_pem"]


# ── Audit 2026-04-30 lane 3 H5 — discover reach gate ────────────────


@pytest.mark.asyncio
async def test_discover_returns_empty_when_caller_reach_is_intra(proxy_app):
    """Audit 2026-04-30 lane 3 H5 — discover always queries the Court
    (cross-org by definition). An intra-only agent must NOT receive a
    ready-made cross-org agent list."""
    app, client = proxy_app
    caller_headers = await _provision_caller("acme::intra-disc")
    await _set_caller_reach("acme::intra-disc", "intra")

    class _StubBridge:
        async def discover_agents(self, *args, **kwargs):
            raise AssertionError("bridge MUST NOT be reached for reach=intra")

    app.state.broker_bridge = _StubBridge()
    try:
        resp = await client.post(
            "/v1/egress/discover",
            headers=caller_headers,
            json={"capabilities": ["cap.read"]},
        )
    finally:
        app.state.broker_bridge = None

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agents"] == []
    assert body["count"] == 0


@pytest.mark.asyncio
async def test_discover_calls_bridge_when_caller_reach_is_both(proxy_app):
    """reach=both: discover delegates to the broker bridge as before."""
    app, client = proxy_app
    caller_headers = await _provision_caller("acme::both-disc")
    await _set_caller_reach("acme::both-disc", "both")

    seen: list[str] = []

    class _StubBridge:
        async def discover_agents(self, agent_id, *, capabilities=None, q=None):
            seen.append(agent_id)
            return [{"agent_id": "other-org::peer", "capabilities": ["cap.read"]}]

    app.state.broker_bridge = _StubBridge()
    try:
        resp = await client.post(
            "/v1/egress/discover",
            headers=caller_headers,
            json={"capabilities": ["cap.read"]},
        )
    finally:
        app.state.broker_bridge = None

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 1
    assert body["agents"][0]["agent_id"] == "other-org::peer"
    assert seen == ["acme::both-disc"]
