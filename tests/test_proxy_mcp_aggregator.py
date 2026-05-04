"""ADR-007 Phase 1 PR #3 — aggregated MCP endpoint + resource forwarder.

Unit tests for ``mcp_proxy/ingress/mcp_aggregator.py`` and
``mcp_proxy/tools/mcp_resource_forwarder.py``. The FastAPI app is
booted with dependency overrides so the DPoP auth dance is bypassed
and every test can assert against a deterministic authenticated
agent. The forwarder's outbound HTTP is intercepted with
``httpx.MockTransport`` so no real network is touched.
"""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.local.audit import verify_local_chain
from mcp_proxy.models import TokenPayload
from mcp_proxy.tools.registry import ToolDefinition, tool_registry
from mcp_proxy.tools.resource_loader import load_resources_into_registry


# ── Fixtures ────────────────────────────────────────────────────────

def _fake_agent(
    agent_id: str = "acme::buyer",
    org: str = "acme",
    scope: list[str] | None = None,
) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{agent_id}",
        agent_id=agent_id,
        org=org,
        exp=9_999_999_999,
        iat=0,
        jti=f"jti-{agent_id}",
        scope=scope or [],
        cnf={"jkt": "fake-jkt"},
    )


@pytest.fixture
def clean_registry():
    """Snapshot + restore the singleton registry to keep tests isolated."""
    saved = dict(tool_registry._tools)
    tool_registry._tools.clear()
    yield tool_registry
    tool_registry._tools.clear()
    tool_registry._tools.update(saved)


@pytest.fixture
async def proxy_db(tmp_path, monkeypatch):
    """Init a fresh SQLite DB with full migrations, yield its url.

    The URL is exported via ``PROXY_DB_URL`` so any subsequent
    ``init_db(settings.database_url)`` — e.g. the lifespan triggered by
    ``TestClient(app)`` in ``app_client`` — reuses this DB rather than
    falling back to the default and overwriting the engine.
    """
    db_file = tmp_path / "mcp_agg.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    # Force-reload settings so the fresh env var is picked up by lifespan.
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()  # type: ignore[attr-defined]
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()  # type: ignore[attr-defined]


@pytest.fixture
def app_client(proxy_db):
    """TestClient with get_authenticated_agent overridden per-test.

    Depends on ``proxy_db`` so settings' database_url points at the test
    DB before the lifespan fires.
    """
    from mcp_proxy.main import app
    app.dependency_overrides[get_authenticated_agent] = lambda: _fake_agent()
    with TestClient(app) as client:
        yield client, app
    app.dependency_overrides.pop(get_authenticated_agent, None)


async def _seed_resource(
    *,
    resource_id: str,
    name: str,
    org_id: str | None = "acme",
    description: str = "seeded",
    endpoint_url: str = "http://mcp-svc:8080",
    auth_type: str = "none",
    auth_secret_ref: str | None = None,
    required_capability: str | None = None,
    allowed_domains: str = '["mcp-svc:8080"]',
    enabled: int = 1,
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_mcp_resources (
                    resource_id, org_id, name, description, endpoint_url,
                    auth_type, auth_secret_ref, required_capability,
                    allowed_domains, enabled, created_at, updated_at
                ) VALUES (
                    :resource_id, :org_id, :name, :description, :endpoint_url,
                    :auth_type, :auth_secret_ref, :required_capability,
                    :allowed_domains, :enabled,
                    '2026-04-16T10:00:00Z', '2026-04-16T10:00:00Z'
                )
                """
            ),
            {
                "resource_id": resource_id,
                "org_id": org_id,
                "name": name,
                "description": description,
                "endpoint_url": endpoint_url,
                "auth_type": auth_type,
                "auth_secret_ref": auth_secret_ref,
                "required_capability": required_capability,
                "allowed_domains": allowed_domains,
                "enabled": enabled,
            },
        )


async def _seed_binding(
    *,
    agent_id: str,
    resource_id: str,
    org_id: str | None = "acme",
    revoked_at: str | None = None,
    binding_id: str | None = None,
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_agent_resource_bindings (
                    binding_id, agent_id, resource_id, org_id,
                    granted_by, granted_at, revoked_at
                ) VALUES (
                    :binding_id, :agent_id, :resource_id, :org_id,
                    'admin', '2026-04-16T10:05:00Z', :revoked_at
                )
                """
            ),
            {
                "binding_id": binding_id or f"bind-{agent_id}-{resource_id}",
                "agent_id": agent_id,
                "resource_id": resource_id,
                "org_id": org_id,
                "revoked_at": revoked_at,
            },
        )


def _patch_whitelist_transport(monkeypatch, handler):
    """Replace WhitelistedTransport with httpx.MockTransport for forwarder tests."""
    from mcp_proxy.tools import mcp_resource_forwarder as fwd

    class _MockWT(httpx.MockTransport):
        def __init__(self, allowed_domains: list[str]) -> None:
            super().__init__(handler)

    monkeypatch.setattr(fwd, "WhitelistedTransport", _MockWT)


# ── Aggregator endpoint tests (no DB I/O for initialize) ────────────

def test_initialize_returns_protocol_info(app_client):
    client, _ = app_client
    resp = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    assert body["result"]["protocolVersion"] == "2024-11-05"
    assert body["result"]["serverInfo"]["name"] == "cullis-proxy"
    assert "tools" in body["result"]["capabilities"]


def test_notifications_initialized_returns_204(app_client):
    client, _ = app_client
    resp = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "method": "notifications/initialized",
    })
    assert resp.status_code == 204


def test_method_not_found(app_client):
    client, _ = app_client
    resp = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 9, "method": "tools/unknown",
    })
    body = resp.json()
    assert body["error"]["code"] == -32601
    assert "tools/unknown" in body["error"]["message"]


def test_invalid_json_body_returns_parse_error(app_client):
    client, _ = app_client
    resp = client.post("/v1/mcp", content=b"not json", headers={"content-type": "application/json"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32700


def test_non_object_body_returns_invalid_request(app_client):
    client, _ = app_client
    resp = client.post("/v1/mcp", json=["not", "an", "object"])
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32600


# ── tools/list: binding-aware discovery ─────────────────────────────

@pytest.mark.asyncio
async def test_tools_list_returns_only_bound_resources(
    proxy_db, clean_registry, app_client,
):
    await _seed_resource(resource_id="res-x", name="postgres-prod")
    await _seed_resource(resource_id="res-y", name="github-mcp")
    await _seed_binding(agent_id="acme::buyer", resource_id="res-x")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/list",
    }).json()
    names = [t["name"] for t in body["result"]["tools"]]
    assert "postgres-prod" in names
    assert "github-mcp" not in names


@pytest.mark.asyncio
async def test_tools_list_excludes_revoked_bindings(
    proxy_db, clean_registry, app_client,
):
    await _seed_resource(resource_id="res-rev", name="revoked-one")
    await _seed_binding(
        agent_id="acme::buyer", resource_id="res-rev",
        revoked_at="2026-04-15T09:00:00Z",
    )
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/list",
    }).json()
    assert body["result"]["tools"] == []


@pytest.mark.asyncio
async def test_tools_list_includes_builtin_for_capability_match(
    proxy_db, clean_registry,
):
    from mcp_proxy.main import app
    clean_registry.register_definition(ToolDefinition(
        name="builtin_x",
        description="a builtin",
        required_capability="cap.x",
        allowed_domains=[],
        handler=lambda ctx: None,  # unused
    ))
    app.dependency_overrides[get_authenticated_agent] = (
        lambda: _fake_agent(scope=["cap.x"])
    )
    with TestClient(app) as client:
        body = client.post("/v1/mcp", json={
            "jsonrpc": "2.0", "id": 4, "method": "tools/list",
        }).json()
    app.dependency_overrides.pop(get_authenticated_agent, None)

    names = [t["name"] for t in body["result"]["tools"]]
    assert "builtin_x" in names


@pytest.mark.asyncio
async def test_tools_list_excludes_builtin_without_capability(
    proxy_db, clean_registry, app_client,
):
    clean_registry.register_definition(ToolDefinition(
        name="builtin_y",
        description="a builtin",
        required_capability="cap.y",
        allowed_domains=[],
        handler=lambda ctx: None,
    ))
    client, _ = app_client  # fake agent has scope=[]
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 5, "method": "tools/list",
    }).json()
    assert body["result"]["tools"] == []


# ── tools/call: binding enforcement ─────────────────────────────────

@pytest.mark.asyncio
async def test_tools_call_without_binding_is_denied(
    proxy_db, clean_registry, app_client,
):
    await _seed_resource(resource_id="res-nb", name="no-binding")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    resp = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 10, "method": "tools/call",
        "params": {"name": "no-binding", "arguments": {}},
    })
    body = resp.json()
    assert body["error"]["code"] == -32000
    assert "res-nb" in body["error"]["message"]

    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT event_type, result, details FROM local_audit "
            "ORDER BY id DESC LIMIT 1"
        ))).first()
    assert row.event_type == "resource_call"
    assert row.result == "denied"
    details = json.loads(row.details)
    assert details["reason"] == "no_binding"
    assert details["resource_id"] == "res-nb"


@pytest.mark.asyncio
async def test_tools_call_unknown_tool_returns_jsonrpc_error(
    proxy_db, clean_registry, app_client,
):
    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 11, "method": "tools/call",
        "params": {"name": "nope", "arguments": {}},
    }).json()
    assert body["error"]["code"] == -32004


@pytest.mark.asyncio
async def test_tools_call_missing_name_returns_invalid_params(
    proxy_db, clean_registry, app_client,
):
    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 12, "method": "tools/call",
        "params": {"arguments": {}},
    }).json()
    assert body["error"]["code"] == -32602


# ── tools/call: forwarding through mcp_resource_forwarder ───────────

@pytest.mark.asyncio
async def test_tools_call_forwards_to_mock_mcp_server(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": captured["body"]["id"],
                  "result": {"content": [{"type": "text", "text": "hello"}]}},
        )

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-fw", name="echo-svc",
        endpoint_url="http://echo-svc:8080/",
        allowed_domains='["echo-svc:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-fw")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    resp = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 20, "method": "tools/call",
        "params": {"name": "echo-svc", "arguments": {"x": 1}},
    })
    body = resp.json()
    assert body["result"]["isError"] is False
    assert captured["body"]["method"] == "tools/call"
    assert captured["body"]["params"]["arguments"] == {"x": 1}
    # content includes upstream response
    text_out = body["result"]["content"][0]["text"]
    assert "hello" in text_out


@pytest.mark.asyncio
async def test_tools_call_injects_bearer_auth_header(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    monkeypatch.setenv("TEST_MCP_TOKEN", "abc123")
    captured_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x",
                                         "result": {"ok": True}})

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-auth", name="auth-svc",
        endpoint_url="http://auth-svc:8080/",
        allowed_domains='["auth-svc:8080"]',
        auth_type="bearer", auth_secret_ref="env://TEST_MCP_TOKEN",
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-auth")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 21, "method": "tools/call",
        "params": {"name": "auth-svc", "arguments": {}},
    })
    assert captured_headers.get("authorization") == "Bearer abc123"


@pytest.mark.asyncio
async def test_tools_call_injects_api_key_header(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    monkeypatch.setenv("TEST_MCP_KEY", "xyz789")
    captured_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.update(dict(request.headers))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x",
                                         "result": {"ok": True}})

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-apikey", name="key-svc",
        endpoint_url="http://key-svc:8080/",
        allowed_domains='["key-svc:8080"]',
        auth_type="api_key", auth_secret_ref="env://TEST_MCP_KEY",
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-apikey")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 22, "method": "tools/call",
        "params": {"name": "key-svc", "arguments": {}},
    })
    assert captured_headers.get("x-api-key") == "xyz789"
    assert "authorization" not in captured_headers


@pytest.mark.asyncio
async def test_tools_call_timeout_surfaces_error(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-down", name="down-svc",
        endpoint_url="http://down-svc:8080/",
        allowed_domains='["down-svc:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-down")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 23, "method": "tools/call",
        "params": {"name": "down-svc", "arguments": {}},
    }).json()
    assert body["error"]["code"] == -32003

    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT result, details FROM local_audit ORDER BY id DESC LIMIT 1"
        ))).first()
    assert row.result == "error"
    assert json.loads(row.details)["error"] == "unreachable"


@pytest.mark.asyncio
async def test_tools_call_remote_401_marked_denied(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "unauthorized"})

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-401", name="reject-svc",
        endpoint_url="http://reject-svc:8080/",
        allowed_domains='["reject-svc:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-401")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 24, "method": "tools/call",
        "params": {"name": "reject-svc", "arguments": {}},
    })

    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT result, details FROM local_audit ORDER BY id DESC LIMIT 1"
        ))).first()
    assert row.result == "denied"
    assert json.loads(row.details)["http_status"] == 401


@pytest.mark.asyncio
async def test_tools_call_remote_rpc_error_audited(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": "x",
            "error": {"code": -32603, "message": "boom"},
        })

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-boom", name="boom-svc",
        endpoint_url="http://boom-svc:8080/",
        allowed_domains='["boom-svc:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-boom")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 25, "method": "tools/call",
        "params": {"name": "boom-svc", "arguments": {}},
    }).json()
    assert body["error"]["code"] == -32003

    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT result, details FROM local_audit ORDER BY id DESC LIMIT 1"
        ))).first()
    assert row.result == "error"
    details = json.loads(row.details)
    assert details["rpc_error"]["message"] == "boom"


@pytest.mark.asyncio
async def test_audit_row_has_resource_id_in_details_on_success(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x",
                                         "result": {"value": 42}})

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-ok", name="ok-svc",
        endpoint_url="http://ok-svc:8080/",
        allowed_domains='["ok-svc:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-ok")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 26, "method": "tools/call",
        "params": {"name": "ok-svc", "arguments": {}},
    })

    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT event_type, result, details FROM local_audit "
            "WHERE event_type = 'resource_call' ORDER BY id DESC LIMIT 1"
        ))).first()
    assert row.result == "ok"
    details = json.loads(row.details)
    assert details["resource_id"] == "res-ok"
    assert details["endpoint_url"] == "http://ok-svc:8080/"
    assert details["tool"] == "ok-svc"
    # Canonical form intact: no new keys bleed into colonne hashate
    assert set(json.loads(row.details).keys()) == {"resource_id", "endpoint_url", "tool"}


@pytest.mark.asyncio
async def test_audit_hash_chain_intact_after_resource_calls(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "x",
                                         "result": {"ok": True}})

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-chain", name="chain-svc",
        endpoint_url="http://chain-svc:8080/",
        allowed_domains='["chain-svc:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-chain")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    for _ in range(5):
        client.post("/v1/mcp", json={
            "jsonrpc": "2.0", "id": 50, "method": "tools/call",
            "params": {"name": "chain-svc", "arguments": {}},
        })

    ok, broken_at = await verify_local_chain("acme")
    assert ok, f"hash chain broken at seq={broken_at}"


# ── Three-backend smoke (github / slack / postgres) ──────────────────


@pytest.mark.asyncio
async def test_three_backends_visible_after_seed_and_binding(
    proxy_db, clean_registry, app_client,
):
    """The sandbox-mcp setup registers three backends with distinct
    auth_type and capability values. Once the agent is bound to all
    three, tools/list must surface them as a single set the proxy
    presents to the agent."""
    backends = [
        ("res-gh", "github", "bearer", "github.write"),
        ("res-sl", "slack", "bearer", "slack.post"),
        ("res-pg", "postgres", "api_key", "sql.read"),
    ]
    for rid, name, auth_type, cap in backends:
        await _seed_resource(
            resource_id=rid, name=name,
            endpoint_url=f"http://mock-mcp:9100/{name}",
            auth_type=auth_type,
            required_capability=cap,
            allowed_domains='["mock-mcp:9100"]',
        )
        await _seed_binding(agent_id="acme::buyer", resource_id=rid)

    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 100, "method": "tools/list",
    }).json()
    names = sorted(t["name"] for t in body["result"]["tools"])
    assert "github" in names
    assert "slack" in names
    assert "postgres" in names


# ── Streamable HTTP forwarder behavior ──────────────────────────────


@pytest.mark.asyncio
async def test_forwarder_sends_streamable_http_accept_header(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    """Forwarder must advertise both JSON and SSE so Streamable HTTP
    MCP servers (e.g. sparfenyuk mcp-proxy) accept the POST."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["accept"] = request.headers.get("accept")
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        )

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-shttp", name="shttp-svc",
        endpoint_url="http://shttp-svc:8080/mcp",
        allowed_domains='["shttp-svc:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-shttp")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "shttp-svc", "arguments": {}},
    })

    accept = captured.get("accept", "")
    assert "application/json" in accept
    assert "text/event-stream" in accept


@pytest.mark.asyncio
async def test_forwarder_decodes_sse_framed_response(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    """When the upstream replies with text/event-stream (single data:
    frame), the forwarder must extract the JSON-RPC envelope from it."""
    sse_body = (
        'event: message\n'
        'data: {"jsonrpc":"2.0","id":1,"result":'
        '{"content":[{"type":"text","text":"sse-hello"}],"isError":false}}\n'
        '\n'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=sse_body.encode("utf-8"),
            headers={"content-type": "text/event-stream"},
        )

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-sse", name="sse-svc",
        endpoint_url="http://sse-svc:8080/mcp",
        allowed_domains='["sse-svc:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-sse")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "sse-svc", "arguments": {}},
    }).json()

    assert body["result"]["isError"] is False
    text_out = body["result"]["content"][0]["text"]
    assert "sse-hello" in text_out


@pytest.mark.asyncio
async def test_forwarder_rejects_malformed_sse_body(
    proxy_db, clean_registry, app_client, monkeypatch,
):
    """A text/event-stream body with no parseable data: line is treated
    as malformed and bubbles up as an error result."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"event: ping\n\n",
            headers={"content-type": "text/event-stream"},
        )

    _patch_whitelist_transport(monkeypatch, handler)

    await _seed_resource(
        resource_id="res-sse-bad", name="sse-bad-svc",
        endpoint_url="http://sse-bad:8080/mcp",
        allowed_domains='["sse-bad:8080"]',
    )
    await _seed_binding(agent_id="acme::buyer", resource_id="res-sse-bad")
    await load_resources_into_registry(clean_registry)

    client, _ = app_client
    body = client.post("/v1/mcp", json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "sse-bad-svc", "arguments": {}},
    }).json()

    assert "error" in body
    assert "non-JSON" in body["error"]["message"] or "malformed" in body["error"]["message"].lower()
