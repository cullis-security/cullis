"""CRIT-2 — REST /v1/ingress/execute MCP-resource binding gate.

Audit ref: imp/audits/2026-05-11-track-3-audit-pdp.md finding F-1.

Pre-fix the executor short-circuited the binding check entirely for
``principal_type != "agent"``. A user / workload token could call any
MCP-resource tool by name on the REST surface, regardless of which
resources their admin had bound. The JSON-RPC ``tools/call`` aggregator
already enforced the gate; the REST surface did not.

These tests pin the post-fix contract on both ingress paths.
"""
from __future__ import annotations

import os

# Match the conftest env baseline so this file can run standalone.
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import text

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.models import TokenPayload
from mcp_proxy.tools.registry import ToolDefinition, tool_registry


# ── Fixtures ────────────────────────────────────────────────────────


def _fake_agent(
    *,
    agent_id: str = "acme::daniele",
    org: str = "acme",
    scope: list[str] | None = None,
    principal_type: str = "agent",
) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{agent_id}",
        agent_id=agent_id,
        org=org,
        exp=9_999_999_999,
        iat=0,
        jti=f"jti-{agent_id}-{principal_type}",
        scope=scope or [],
        cnf={"jkt": "fake-jkt"},
        principal_type=principal_type,
    )


@pytest.fixture
def clean_registry():
    """Snapshot + restore the singleton registry to keep tests isolated."""
    saved = dict(tool_registry._tools)
    tool_registry._tools.clear()
    yield tool_registry
    tool_registry._tools.clear()
    tool_registry._tools.update(saved)


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "crit2.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


@pytest.fixture
def app_client_factory(proxy_db, clean_registry):
    """Returns ``make_client(agent)`` helper — each test picks the
    authenticated agent envelope it wants. The factory uses TestClient
    as a context manager so the FastAPI lifespan fires (sets
    ``app.state.secret_provider``, ``agent_manager``, etc.)."""
    from mcp_proxy.main import app

    clients: list[TestClient] = []

    def _make(agent: TokenPayload) -> TestClient:
        app.dependency_overrides[get_authenticated_agent] = lambda: agent
        client = TestClient(app)
        client.__enter__()  # start lifespan
        clients.append(client)
        return client

    yield _make
    for c in clients:
        c.__exit__(None, None, None)
    app.dependency_overrides.pop(get_authenticated_agent, None)


async def _register_mcp_resource_tool(
    *,
    name: str = "github_mcp",
    resource_id: str = "github",
    capability: str = "github.read",
) -> None:
    """Register an MCP-resource-shaped tool with a no-op handler.

    The handler is just enough to prove the executor reached step 5
    (handler invocation) when the binding gate didn't block it.
    """
    async def _ok_handler(ctx):
        return {"ok": True, "via": "mcp_resource_test_handler"}

    tool_def = ToolDefinition(
        name=name,
        description="MCP resource test tool",
        required_capability=capability,
        allowed_domains=[],
        handler=_ok_handler,
        resource_id=resource_id,
        endpoint_url="http://test-mcp:8080",
    )
    tool_registry.register_definition(tool_def)


async def _register_builtin_tool(
    *,
    name: str = "builtin_echo",
    capability: str = "echo.run",
) -> None:
    """Register a non-MCP-resource (builtin) tool — no resource_id, so
    the binding gate must NOT apply, only the capability gate does."""
    async def _echo_handler(ctx):
        return {"echo": ctx.parameters}

    tool_def = ToolDefinition(
        name=name,
        description="builtin echo",
        required_capability=capability,
        allowed_domains=[],
        handler=_echo_handler,
    )
    tool_registry.register_definition(tool_def)


async def _seed_binding(
    *,
    agent_id: str,
    resource_id: str,
    principal_type: str,
    org_id: str = "acme",
) -> None:
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_agent_resource_bindings (
                    binding_id, agent_id, principal_type, resource_id,
                    org_id, granted_by, granted_at, revoked_at
                ) VALUES (
                    :bid, :aid, :pt, :rid, :org, 'admin',
                    '2026-05-11T18:00:00Z', NULL
                )
                """
            ),
            {
                "bid": f"bind-{principal_type}-{agent_id}-{resource_id}",
                "aid": agent_id, "pt": principal_type,
                "rid": resource_id, "org": org_id,
            },
        )


# ── Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_principal_no_binding_denied(app_client_factory):
    """CRIT-2 — the headline gap. User token, MCP-resource tool, no
    binding row. Pre-fix returned 200 (executor skipped binding check
    for non-agent). Post-fix returns the "no active binding" error."""
    await _register_mcp_resource_tool()
    agent = _fake_agent(principal_type="user", scope=[])
    client = app_client_factory(agent)

    resp = client.post(
        "/v1/ingress/execute",
        json={
            "tool": "github_mcp",
            "parameters": {},
            "request_id": "rq-user-noband",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "error"
    assert "binding" in body["error"].lower()
    assert "github" in body["error"]


@pytest.mark.asyncio
async def test_workload_principal_no_binding_denied(app_client_factory):
    """CRIT-2 mirror for workload — same gap, same fix."""
    await _register_mcp_resource_tool()
    agent = _fake_agent(
        agent_id="acme::workload::etl-job",
        principal_type="workload", scope=[],
    )
    client = app_client_factory(agent)

    resp = client.post(
        "/v1/ingress/execute",
        json={
            "tool": "github_mcp",
            "parameters": {},
            "request_id": "rq-wl-noband",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "error"
    assert "binding" in body["error"].lower()


@pytest.mark.asyncio
async def test_user_principal_with_binding_proceeds(app_client_factory):
    """User token with active binding for the resource — the binding
    gate passes, the handler runs, response is success."""
    await _register_mcp_resource_tool()
    await _seed_binding(
        agent_id="acme::user::daniele",
        resource_id="github",
        principal_type="user",
    )
    agent = _fake_agent(
        agent_id="acme::user::daniele",
        principal_type="user", scope=[],
    )
    client = app_client_factory(agent)

    resp = client.post(
        "/v1/ingress/execute",
        json={
            "tool": "github_mcp",
            "parameters": {},
            "request_id": "rq-user-bound",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success", body
    assert body["result"] == {
        "ok": True, "via": "mcp_resource_test_handler",
    }


@pytest.mark.asyncio
async def test_agent_principal_with_binding_but_no_capability_denied(
    app_client_factory,
):
    """Agent-typed: capability gate runs first; even with a binding row
    the agent without the capability is denied. Confirms the new
    binding gate doesn't accidentally short-circuit the capability gate
    for agent-typed callers."""
    await _register_mcp_resource_tool(capability="github.read")
    await _seed_binding(
        agent_id="acme::daniele",
        resource_id="github",
        principal_type="agent",
    )
    agent = _fake_agent(
        agent_id="acme::daniele",
        principal_type="agent",
        scope=[],  # missing github.read
    )
    client = app_client_factory(agent)

    resp = client.post(
        "/v1/ingress/execute",
        json={
            "tool": "github_mcp",
            "parameters": {},
            "request_id": "rq-agent-nocap",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "error"
    # Capability gate runs before binding — error refers to capability.
    assert "capability" in body["error"].lower()


@pytest.mark.asyncio
async def test_builtin_tool_no_binding_check_required(app_client_factory):
    """Built-in tool (resource_id=None) — the binding gate must NOT
    fire. Only the capability gate applies. With matching capability,
    user-typed callers can run builtins (e.g. observability tools)
    without any per-resource binding row."""
    await _register_builtin_tool()
    agent = _fake_agent(
        agent_id="acme::user::ops",
        principal_type="user",
        scope=["echo.run"],
    )
    client = app_client_factory(agent)

    resp = client.post(
        "/v1/ingress/execute",
        json={
            "tool": "builtin_echo",
            "parameters": {"hello": "world"},
            "request_id": "rq-builtin",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success", body
    assert body["result"] == {"echo": {"hello": "world"}}


@pytest.mark.asyncio
async def test_audit_row_records_no_binding_reason(app_client_factory):
    """The denied path writes an audit row with the resource_id and the
    no-binding reason — actionable forensic signal for ops."""
    await _register_mcp_resource_tool()
    agent = _fake_agent(principal_type="user", scope=[])
    client = app_client_factory(agent)

    resp = client.post(
        "/v1/ingress/execute",
        json={
            "tool": "github_mcp",
            "parameters": {},
            "request_id": "rq-audit",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "error"

    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT detail, status FROM audit_log "
                " WHERE request_id = :rid"
            ),
            {"rid": "rq-audit"},
        )).mappings().all()

    # At least one denied row referencing the resource + reason.
    denied = [r for r in rows if r["status"] == "denied"]
    assert denied, f"expected denied audit row, got {list(rows)}"
    detail = denied[0]["detail"] or ""
    assert "github" in detail
    assert "binding" in detail.lower()
    assert "user" in detail
