"""ADR-029 Phase D-2, cross-org federation of tool-call PDP decisions.

Pins:

- Same-org call: no federation, the local decision is the final one
  (Phase C behaviour unchanged).
- Cross-org call with no federation URL configured: default-deny.
- Cross-org call with federation URL + remote allow: final allow,
  audit row marks the row as `federated`.
- Cross-org call with federation URL + remote deny: final deny.
- Cross-org call with federation URL + remote transport error: deny
  fail-safe.
- Cross-org call with federation URL + remote 404 (target Mastio has
  PDP disabled): final decision falls back to the local one.
- Intersection helpers (tools_allowed, tools_denied, duration,
  rate_limit, obligations) under the source ∩ target rule.
"""
from __future__ import annotations

import json

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "tool_pdp_fed.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_TOOL_PDP_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", "")
    monkeypatch.setenv(
        "MCP_PROXY_TOOL_PDP_FEDERATION_URLS",
        json.dumps({"competitor": "https://mastio.competitor.local/v1/policy/tool-call"}),
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def proxy_app_phaseg(tmp_path, monkeypatch):
    """Same as ``proxy_app`` but with an empty env map and a Court
    base URL set on ``app.state.reverse_proxy_broker_url``. Exercises
    ADR-029 Phase G — the catalog must resolve the peer URL through
    Court rather than the env override.
    """
    db_file = tmp_path / "tool_pdp_fed_phaseg.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_TOOL_PDP_ENABLED", "true")
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", "")
    monkeypatch.setenv("MCP_PROXY_TOOL_PDP_FEDERATION_URLS", "{}")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            # Override whatever the lifespan set (which is ``None`` for
            # an unconfigured broker) with the fake Court base URL the
            # tests want to hit.
            app.state.reverse_proxy_broker_url = "https://court.test.local"
            # Drop any cached catalog so the next PDP call picks up the
            # fresh broker_url + empty env map.
            if hasattr(app.state, "federation_catalog"):
                delattr(app.state, "federation_catalog")
            yield app, client
    get_settings.cache_clear()


def _payload_cross_org(
    *,
    principal_id: str = "acme::user::mario@acme.local",
    tool_name: str = "competitor.catalog.search",
    target_org: str = "competitor",
):
    return {
        "principal": {"id": principal_id, "type": "user", "org": "acme"},
        "model": {"id": "claude-haiku-4-5", "provider": "anthropic"},
        "target": {
            "id": f"{target_org}::workload::catalog-mcp",
            "type": "workload",
            "org": target_org,
        },
        "invocation": {
            "kind": "session_tool_call",
            "tool_name": tool_name,
            "mcp_server_id": "competitor-catalog-prod",
        },
    }


def _payload_same_org():
    return {
        "principal": {"id": "acme::user::mario@acme.local", "type": "user", "org": "acme"},
        "model": {"id": "claude-haiku-4-5"},
        "target": {"id": "acme::workload::catalog-mcp", "type": "workload", "org": "acme"},
        "invocation": {
            "kind": "session_tool_call",
            "tool_name": "acme.catalog.search",
        },
    }


async def _set_tool_rules(rules: dict) -> None:
    from mcp_proxy.db import set_config
    await set_config("policy_rules", json.dumps({"tool_rules": rules}))


# ── Same-org keeps Phase C behaviour ────────────────────────────────


@pytest.mark.asyncio
async def test_same_org_keeps_phase_c_behaviour(proxy_app, monkeypatch):
    """When target.org == self org_id, the federation path is skipped
    entirely and no HTTP call is made even if a federation URL exists
    for some other org."""
    fed_called = {"hit": False}

    def _fed_handler(request: httpx.Request) -> httpx.Response:
        fed_called["hit"] = True
        return httpx.Response(200, json={"decision": "deny", "reason": "should not reach"})

    transport = httpx.MockTransport(_fed_handler)

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("mcp_proxy.policy.federation.httpx.AsyncClient", _Client)

    _, client = proxy_app
    await _set_tool_rules({
        "acme.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
        }
    })

    resp = await client.post("/v1/policy/tool-call", json=_payload_same_org())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert fed_called["hit"] is False


# ── Cross-org missing federation URL ────────────────────────────────


@pytest.mark.asyncio
async def test_cross_org_without_federation_url_denies(proxy_app, monkeypatch):
    """Target org for which no entry exists in
    MCP_PROXY_TOOL_PDP_FEDERATION_URLS means default-deny."""
    _, client = proxy_app
    # Local rule would allow, but cross-org without federation URL must deny.
    await _set_tool_rules({
        "stranger.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
        }
    })
    p = _payload_cross_org(target_org="stranger", tool_name="stranger.catalog.search")
    resp = await client.post("/v1/policy/tool-call", json=p)
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert "stranger" in body["reason"]
    assert "federation URL" in body["reason"]


# ── Cross-org with remote allow ─────────────────────────────────────


@pytest.mark.asyncio
async def test_cross_org_remote_allow_lands_final_allow(proxy_app, monkeypatch):
    captured: dict = {}

    def _fed_handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "decision": "allow",
            "reason": "competitor allows the call",
            "scope": {"tools_allowed": ["competitor.catalog.search"]},
        })

    transport = httpx.MockTransport(_fed_handler)

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("mcp_proxy.policy.federation.httpx.AsyncClient", _Client)

    _, client = proxy_app
    await _set_tool_rules({
        "competitor.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
            "scope": {"tools_allowed": ["competitor.catalog.search", "competitor.catalog.list"]},
        }
    })

    resp = await client.post("/v1/policy/tool-call", json=_payload_cross_org())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    # Federation reached: the remote got the same payload shape.
    assert captured["body"]["target"]["org"] == "competitor"
    assert captured["body"]["invocation"]["tool_name"] == "competitor.catalog.search"
    # Intersection: local allows [search, list], remote allows [search],
    # final is just [search].
    assert body["scope"]["tools_allowed"] == ["competitor.catalog.search"]

    # Audit row marked federated.
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        result = await conn.execute(text(
            "SELECT detail FROM audit_log WHERE action='policy.tool_call' "
            "ORDER BY chain_seq DESC LIMIT 1"
        ))
        row = result.fetchone()
    assert row is not None
    assert '"federated":true' in row.detail


# ── Cross-org with remote deny ──────────────────────────────────────


@pytest.mark.asyncio
async def test_cross_org_remote_deny_lands_final_deny(proxy_app, monkeypatch):
    def _fed_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "decision": "deny",
            "reason": "competitor policy: stranger principals not allowed",
        })

    transport = httpx.MockTransport(_fed_handler)

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("mcp_proxy.policy.federation.httpx.AsyncClient", _Client)

    _, client = proxy_app
    await _set_tool_rules({
        "competitor.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
        }
    })

    resp = await client.post("/v1/policy/tool-call", json=_payload_cross_org())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert "competitor policy" in body["reason"]


# ── Cross-org with remote transport error ───────────────────────────


@pytest.mark.asyncio
async def test_cross_org_remote_transport_error_denies(proxy_app, monkeypatch):
    def _fed_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated DNS failure")

    transport = httpx.MockTransport(_fed_handler)

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("mcp_proxy.policy.federation.httpx.AsyncClient", _Client)

    _, client = proxy_app
    await _set_tool_rules({
        "competitor.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
        }
    })

    resp = await client.post("/v1/policy/tool-call", json=_payload_cross_org())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny"
    assert "transport error" in body["reason"]


# ── Cross-org with remote 404 (target Mastio has PDP off) ───────────


@pytest.mark.asyncio
async def test_cross_org_remote_404_falls_back_to_local(proxy_app, monkeypatch):
    """If the target Mastio returns 404 (its own tool PDP is disabled),
    the originator's local decision stands. This mirrors the Connector
    SDK behaviour against a legacy Mastio."""
    def _fed_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "tool-level PDP disabled"})

    transport = httpx.MockTransport(_fed_handler)

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("mcp_proxy.policy.federation.httpx.AsyncClient", _Client)

    _, client = proxy_app
    await _set_tool_rules({
        "competitor.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
        }
    })

    resp = await client.post("/v1/policy/tool-call", json=_payload_cross_org())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"


# ── Unit tests for intersection helpers ─────────────────────────────


def test_intersect_decisions_allow_only_if_both_allow():
    from mcp_proxy.policy.federation import intersect_decisions
    from mcp_proxy.policy.tool_call import ToolCallDecision
    local = ToolCallDecision(allowed=True, reason="local ok")
    remote_deny = ToolCallDecision(allowed=False, reason="remote no")
    assert intersect_decisions(local, remote_deny).allowed is False
    assert intersect_decisions(remote_deny, local).allowed is False


def test_intersect_decisions_intersects_tools_allowed():
    from mcp_proxy.policy.federation import intersect_decisions
    from mcp_proxy.policy.tool_call import ToolCallDecision
    a = ToolCallDecision(allowed=True, reason="a", scope={"tools_allowed": ["x", "y", "z"]})
    b = ToolCallDecision(allowed=True, reason="b", scope={"tools_allowed": ["y", "z", "w"]})
    out = intersect_decisions(a, b)
    assert out.allowed is True
    assert out.scope is not None
    assert out.scope["tools_allowed"] == ["y", "z"]


def test_intersect_decisions_unions_tools_denied():
    from mcp_proxy.policy.federation import intersect_decisions
    from mcp_proxy.policy.tool_call import ToolCallDecision
    a = ToolCallDecision(allowed=True, reason="a", scope={"tools_denied": ["a", "b"]})
    b = ToolCallDecision(allowed=True, reason="b", scope={"tools_denied": ["b", "c"]})
    out = intersect_decisions(a, b)
    assert out.scope is not None
    assert out.scope["tools_denied"] == ["a", "b", "c"]


def test_intersect_decisions_takes_min_duration():
    from mcp_proxy.policy.federation import intersect_decisions
    from mcp_proxy.policy.tool_call import ToolCallDecision
    a = ToolCallDecision(allowed=True, reason="a", scope={"max_session_duration_s": 3600})
    b = ToolCallDecision(allowed=True, reason="b", scope={"max_session_duration_s": 900})
    out = intersect_decisions(a, b)
    assert out.scope is not None
    assert out.scope["max_session_duration_s"] == 900


def test_intersect_decisions_rate_limit_min_per_axis():
    from mcp_proxy.policy.federation import intersect_decisions
    from mcp_proxy.policy.tool_call import ToolCallDecision
    a = ToolCallDecision(allowed=True, reason="a", rate_limit={"per_minute": 60, "per_day": 1000})
    b = ToolCallDecision(allowed=True, reason="b", rate_limit={"per_minute": 30, "per_day": 2000})
    out = intersect_decisions(a, b)
    assert out.rate_limit is not None
    assert out.rate_limit["per_minute"] == 30
    assert out.rate_limit["per_day"] == 1000


def test_intersect_decisions_obligations_restrictive_wins():
    from mcp_proxy.policy.federation import intersect_decisions
    from mcp_proxy.policy.tool_call import ToolCallDecision
    a = ToolCallDecision(allowed=True, reason="a",
                          obligations={"trace_visibility": "full",
                                       "require_user_confirmation": False})
    b = ToolCallDecision(allowed=True, reason="b",
                          obligations={"trace_visibility": "redacted",
                                       "require_user_confirmation": True})
    out = intersect_decisions(a, b)
    assert out.obligations is not None
    assert out.obligations["trace_visibility"] == "redacted"
    assert out.obligations["require_user_confirmation"] is True


# ── ADR-029 Phase G, Court catalog ──────────────────────────────────


@pytest.mark.asyncio
async def test_phaseg_court_catalog_publishes_url(proxy_app_phaseg, monkeypatch):
    """No env entry for target org; Court returns the URL; the
    federation peer allows. End-to-end: PDP final allow comes from the
    catalog-resolved URL."""
    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/v1/federation/orgs/competitor/mastio-url"):
            return httpx.Response(200, json={
                "org_id": "competitor",
                "mastio_url": "https://mastio.competitor.dynamic/v1/policy/tool-call",
            })
        if "mastio.competitor.dynamic" in url:
            captured["peer_url"] = url
            captured["peer_body"] = json.loads(request.content)
            return httpx.Response(200, json={
                "decision": "allow",
                "reason": "competitor approves",
            })
        return httpx.Response(500, content=b"unexpected")

    transport = httpx.MockTransport(_handler)

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("mcp_proxy.policy.federation.httpx.AsyncClient", _Client)
    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient", _Client,
    )

    _, client = proxy_app_phaseg
    await _set_tool_rules({
        "competitor.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
        }
    })

    resp = await client.post("/v1/policy/tool-call", json=_payload_cross_org())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow", body
    # The catalog-resolved peer received the call.
    assert "mastio.competitor.dynamic" in captured["peer_url"]
    assert captured["peer_body"]["target"]["org"] == "competitor"


@pytest.mark.asyncio
async def test_phaseg_court_404_default_deny(proxy_app_phaseg, monkeypatch):
    """No env entry and Court has not published a URL for the target →
    default-deny. The federation peer is never reached."""
    peer_hit = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/v1/federation/orgs/competitor/mastio-url"):
            return httpx.Response(404, json={"detail": "no mastio_url"})
        peer_hit["n"] += 1
        return httpx.Response(200, json={"decision": "allow"})

    transport = httpx.MockTransport(_handler)

    class _Client(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("mcp_proxy.policy.federation.httpx.AsyncClient", _Client)
    monkeypatch.setattr(
        "mcp_proxy.policy.federation_catalog.httpx.AsyncClient", _Client,
    )

    _, client = proxy_app_phaseg
    await _set_tool_rules({
        "competitor.catalog.search": {
            "allowed_principals": ["acme::user::mario@acme.local"],
        }
    })

    resp = await client.post("/v1/policy/tool-call", json=_payload_cross_org())
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "deny", body
    assert "no federation URL" in body["reason"]
    assert peer_hit["n"] == 0
