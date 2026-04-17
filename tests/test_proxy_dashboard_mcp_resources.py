"""ADR-007 Phase 1 PR #5a — dashboard CRUD for MCP resources + bindings.

Exercises the admin UI at /proxy/backends: list, create/update/
toggle/delete resources, binding create/revoke/reapprove/delete, and
the hot-reload of the tool_registry after any mutation.
"""
from __future__ import annotations

import re

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text


@pytest_asyncio.fixture
async def proxy_logged_in(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "test.local")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            from mcp_proxy.dashboard.session import set_admin_password
            await set_admin_password("test-password-1234")
            await client.post(
                "/proxy/login",
                data={"password": "test-password-1234"},
                follow_redirects=False,
            )
            yield client
    get_settings.cache_clear()


async def _csrf(client) -> str:
    page = await client.get("/proxy/backends")
    assert page.status_code == 200, page.text
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "csrf_token not found"
    return m.group(1)


async def _create_resource(
    client,
    *,
    name: str,
    endpoint_url: str = "http://mcp-svc:8080/",
    auth_type: str = "none",
    org_id: str = "acme",
    enabled: str = "1",
    allowed_domains: str = '["mcp-svc:8080"]',
    required_capability: str = "",
    auth_secret_ref: str = "",
    description: str = "",
) -> str:
    csrf = await _csrf(client)
    resp = await client.post(
        "/proxy/backends/create",
        data={
            "csrf_token": csrf,
            "name": name,
            "description": description,
            "endpoint_url": endpoint_url,
            "auth_type": auth_type,
            "auth_secret_ref": auth_secret_ref,
            "required_capability": required_capability,
            "allowed_domains": allowed_domains,
            "org_id": org_id,
            "enabled": enabled,
        },
        follow_redirects=False,
    )
    return resp


async def _resource_id(name: str) -> str:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rid = (await conn.execute(
            text("SELECT resource_id FROM local_mcp_resources WHERE name = :n"),
            {"n": name},
        )).scalar()
    assert rid is not None, f"resource '{name}' not in DB"
    return rid


async def _seed_local_agent(agent_id: str, display: str = "Agent") -> None:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_agents (
                    agent_id, display_name, capabilities, scope,
                    created_at, is_active
                ) VALUES (
                    :aid, :disp, '[]', 'local',
                    '2026-04-16T10:00:00Z', 1
                )
                """
            ),
            {"aid": agent_id, "disp": display},
        )


# ── List + render ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_page_renders_empty(proxy_logged_in):
    page = await proxy_logged_in.get("/proxy/backends")
    assert page.status_code == 200
    assert "Backends" in page.text
    assert "No backends yet" in page.text


# ── Resource create ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_resource_persists(proxy_logged_in):
    resp = await _create_resource(
        proxy_logged_in, name="github-mcp",
        endpoint_url="https://api.example.com/mcp",
        auth_type="bearer", auth_secret_ref="env://GH_TOKEN",
    )
    assert resp.status_code == 303

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT name, endpoint_url, auth_type, auth_secret_ref, enabled "
                 "FROM local_mcp_resources WHERE name='github-mcp'")
        )).mappings().first()
    assert row is not None
    assert row["endpoint_url"] == "https://api.example.com/mcp"
    assert row["auth_type"] == "bearer"
    assert row["auth_secret_ref"] == "env://GH_TOKEN"
    assert row["enabled"] == 1


@pytest.mark.asyncio
async def test_create_rejects_invalid_name(proxy_logged_in):
    resp = await _create_resource(proxy_logged_in, name="bad name!!")
    assert resp.status_code == 400
    assert "must match" in resp.text.lower()


@pytest.mark.asyncio
async def test_create_rejects_invalid_allowed_domains(proxy_logged_in):
    resp = await _create_resource(
        proxy_logged_in, name="bad-dom",
        allowed_domains="not-json",
    )
    assert resp.status_code == 400
    assert "allowed_domains" in resp.text.lower()


@pytest.mark.asyncio
async def test_create_rejects_invalid_endpoint(proxy_logged_in):
    resp = await _create_resource(
        proxy_logged_in, name="bad-endpoint",
        endpoint_url="ftp://oops",
    )
    assert resp.status_code == 400
    assert "endpoint_url" in resp.text.lower()


@pytest.mark.asyncio
async def test_create_duplicate_returns_409(proxy_logged_in):
    r1 = await _create_resource(proxy_logged_in, name="dup")
    assert r1.status_code == 303
    r2 = await _create_resource(proxy_logged_in, name="dup")
    assert r2.status_code == 409
    assert "already exists" in r2.text.lower()


# ── Resource update / toggle / delete ───────────────────────────────

@pytest.mark.asyncio
async def test_update_changes_fields(proxy_logged_in):
    await _create_resource(proxy_logged_in, name="edit-me")
    rid = await _resource_id("edit-me")

    csrf = await _csrf(proxy_logged_in)
    resp = await proxy_logged_in.post(
        f"/proxy/backends/{rid}/update",
        data={
            "csrf_token": csrf,
            "description": "updated",
            "endpoint_url": "https://new.example.com/mcp",
            "auth_type": "api_key",
            "auth_secret_ref": "env://NEW",
            "required_capability": "x.read",
            "allowed_domains": '["new.example.com"]',
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT description, endpoint_url, auth_type, required_capability "
                 "FROM local_mcp_resources WHERE resource_id = :r"),
            {"r": rid},
        )).mappings().first()
    assert row["description"] == "updated"
    assert row["endpoint_url"] == "https://new.example.com/mcp"
    assert row["auth_type"] == "api_key"
    assert row["required_capability"] == "x.read"


@pytest.mark.asyncio
async def test_toggle_flips_enabled(proxy_logged_in):
    await _create_resource(proxy_logged_in, name="toggle-me")
    rid = await _resource_id("toggle-me")

    csrf = await _csrf(proxy_logged_in)
    resp = await proxy_logged_in.post(
        f"/proxy/backends/{rid}/toggle",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        enabled = (await conn.execute(
            text("SELECT enabled FROM local_mcp_resources WHERE resource_id = :r"),
            {"r": rid},
        )).scalar()
    assert enabled == 0


@pytest.mark.asyncio
async def test_delete_removes_resource_and_cascade_bindings(proxy_logged_in):
    await _seed_local_agent("acme::buyer")
    await _create_resource(proxy_logged_in, name="with-bindings")
    rid = await _resource_id("with-bindings")

    # Create one binding for the resource.
    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/backends/bindings/create",
        data={"csrf_token": csrf, "agent_id": "acme::buyer", "resource_id": rid},
        follow_redirects=False,
    )

    csrf = await _csrf(proxy_logged_in)
    resp = await proxy_logged_in.post(
        f"/proxy/backends/{rid}/delete",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        r_count = (await conn.execute(
            text("SELECT COUNT(*) FROM local_mcp_resources WHERE resource_id = :r"),
            {"r": rid},
        )).scalar()
        b_count = (await conn.execute(
            text("SELECT COUNT(*) FROM local_agent_resource_bindings WHERE resource_id = :r"),
            {"r": rid},
        )).scalar()
    assert r_count == 0
    assert b_count == 0


# ── SPIFFE rendering ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_spiffe_uri_shown_on_list(proxy_logged_in):
    await _create_resource(proxy_logged_in, name="pg-svc")
    page = await proxy_logged_in.get("/proxy/backends")
    assert "spiffe://test.local/acme/mcp/pg-svc" in page.text


# ── Bindings ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_binding_persists(proxy_logged_in):
    await _seed_local_agent("acme::buyer")
    await _create_resource(proxy_logged_in, name="res1")
    rid = await _resource_id("res1")

    csrf = await _csrf(proxy_logged_in)
    resp = await proxy_logged_in.post(
        "/proxy/backends/bindings/create",
        data={"csrf_token": csrf, "agent_id": "acme::buyer", "resource_id": rid},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT agent_id, granted_by, revoked_at "
                 "FROM local_agent_resource_bindings WHERE resource_id = :r"),
            {"r": rid},
        )).mappings().first()
    assert row["agent_id"] == "acme::buyer"
    assert row["granted_by"] == "admin"
    assert row["revoked_at"] is None


@pytest.mark.asyncio
async def test_create_binding_duplicate_returns_409(proxy_logged_in):
    await _seed_local_agent("acme::buyer")
    await _create_resource(proxy_logged_in, name="dup-bind")
    rid = await _resource_id("dup-bind")

    csrf = await _csrf(proxy_logged_in)
    r1 = await proxy_logged_in.post(
        "/proxy/backends/bindings/create",
        data={"csrf_token": csrf, "agent_id": "acme::buyer", "resource_id": rid},
        follow_redirects=False,
    )
    assert r1.status_code == 303

    csrf = await _csrf(proxy_logged_in)
    r2 = await proxy_logged_in.post(
        "/proxy/backends/bindings/create",
        data={"csrf_token": csrf, "agent_id": "acme::buyer", "resource_id": rid},
        follow_redirects=False,
    )
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_revoke_and_reapprove_binding(proxy_logged_in):
    await _seed_local_agent("acme::buyer")
    await _create_resource(proxy_logged_in, name="rev-bind")
    rid = await _resource_id("rev-bind")

    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/backends/bindings/create",
        data={"csrf_token": csrf, "agent_id": "acme::buyer", "resource_id": rid},
        follow_redirects=False,
    )

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        bid = (await conn.execute(
            text("SELECT binding_id FROM local_agent_resource_bindings "
                 "WHERE resource_id = :r"),
            {"r": rid},
        )).scalar()

    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        f"/proxy/backends/bindings/{bid}/revoke",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    async with get_db() as conn:
        rev = (await conn.execute(
            text("SELECT revoked_at FROM local_agent_resource_bindings "
                 "WHERE binding_id = :b"),
            {"b": bid},
        )).scalar()
    assert rev is not None

    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        f"/proxy/backends/bindings/{bid}/reapprove",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    async with get_db() as conn:
        rev = (await conn.execute(
            text("SELECT revoked_at FROM local_agent_resource_bindings "
                 "WHERE binding_id = :b"),
            {"b": bid},
        )).scalar()
    assert rev is None


@pytest.mark.asyncio
async def test_list_shows_binding_counts(proxy_logged_in):
    await _seed_local_agent("acme::buyer")
    await _seed_local_agent("acme::seller")
    await _create_resource(proxy_logged_in, name="counts")
    rid = await _resource_id("counts")

    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/backends/bindings/create",
        data={"csrf_token": csrf, "agent_id": "acme::buyer", "resource_id": rid},
        follow_redirects=False,
    )
    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/backends/bindings/create",
        data={"csrf_token": csrf, "agent_id": "acme::seller", "resource_id": rid},
        follow_redirects=False,
    )
    # Revoke one so active=1, total=2.
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        bid = (await conn.execute(
            text(
                "SELECT binding_id FROM local_agent_resource_bindings "
                "WHERE resource_id = :r AND agent_id = 'acme::buyer'"
            ),
            {"r": rid},
        )).scalar()
    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        f"/proxy/backends/bindings/{bid}/revoke",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )

    page = await proxy_logged_in.get("/proxy/backends")
    assert "1 / 2" in page.text


# ── Registry hot-reload ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_registry_reloaded_on_create(proxy_logged_in):
    from mcp_proxy.tools.registry import tool_registry
    await _create_resource(proxy_logged_in, name="hotload")
    td = tool_registry.get("hotload")
    assert td is not None
    assert td.is_mcp_resource is True


@pytest.mark.asyncio
async def test_registry_reloaded_on_delete(proxy_logged_in):
    from mcp_proxy.tools.registry import tool_registry
    await _create_resource(proxy_logged_in, name="goneload")
    rid = await _resource_id("goneload")
    assert tool_registry.get("goneload") is not None

    csrf = await _csrf(proxy_logged_in)
    await proxy_logged_in.post(
        f"/proxy/backends/{rid}/delete",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert tool_registry.get("goneload") is None


# ── Auth guards ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_requires_login(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/proxy/backends", follow_redirects=False)
            assert resp.status_code == 303
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_csrf_enforced_on_create(proxy_logged_in):
    resp = await proxy_logged_in.post(
        "/proxy/backends/create",
        data={
            "csrf_token": "bogus",
            "name": "no-csrf",
            "endpoint_url": "http://x:80/",
            "auth_type": "none",
            "allowed_domains": "[]",
            "org_id": "acme",
            "enabled": "1",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 403
