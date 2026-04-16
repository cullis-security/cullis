"""ADR-006 PR #2b — dashboard CRUD for local_policies.

The policy engine shipped in #126; this suite covers the admin UI
that replaces raw SQL inserts: create, toggle, delete, and the
list/read path.
"""
from __future__ import annotations

import json

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
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            from mcp_proxy.dashboard.session import set_admin_password
            await set_admin_password("test-password-1234")
            await client.post("/proxy/login",
                              data={"password": "test-password-1234"},
                              follow_redirects=False)
            yield client
    get_settings.cache_clear()


async def _csrf_from_list(client) -> str:
    page = await client.get("/proxy/local-policies")
    assert page.status_code == 200, page.text
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "csrf_token not found on page"
    return m.group(1)


@pytest.mark.asyncio
async def test_list_page_renders_empty(proxy_logged_in):
    page = await proxy_logged_in.get("/proxy/local-policies")
    assert page.status_code == 200
    assert "Intra-org Policies" in page.text
    assert "No local policies yet" in page.text


@pytest.mark.asyncio
async def test_create_persists_and_shows_on_list(proxy_logged_in):
    csrf = await _csrf_from_list(proxy_logged_in)
    resp = await proxy_logged_in.post(
        "/proxy/local-policies/create",
        data={
            "csrf_token": csrf,
            "name": "block-secrets",
            "policy_type": "message",
            "org_id": "acme",
            "enabled": "1",
            "rules_json": json.dumps({
                "effect": "allow",
                "conditions": {"blocked_fields": ["admin_override"]},
            }),
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    # Row must be queryable + active by the policy engine.
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT name, org_id, enabled, policy_type, rules_json "
                 "FROM local_policies WHERE name = 'block-secrets'")
        )).mappings().first()
    assert row is not None
    assert row["enabled"] == 1
    assert row["org_id"] == "acme"
    assert row["policy_type"] == "message"
    assert "admin_override" in row["rules_json"]

    page = await proxy_logged_in.get("/proxy/local-policies")
    assert "block-secrets" in page.text


@pytest.mark.asyncio
async def test_create_rejects_invalid_json(proxy_logged_in):
    csrf = await _csrf_from_list(proxy_logged_in)
    resp = await proxy_logged_in.post(
        "/proxy/local-policies/create",
        data={
            "csrf_token": csrf,
            "name": "bad",
            "policy_type": "message",
            "rules_json": "{not json",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "invalid rules_json" in resp.text.lower()


@pytest.mark.asyncio
async def test_toggle_flips_enabled(proxy_logged_in):
    csrf = await _csrf_from_list(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/local-policies/create",
        data={
            "csrf_token": csrf, "name": "p1", "policy_type": "message",
            "enabled": "1",
            "rules_json": json.dumps({"effect": "allow", "conditions": {}}),
        },
        follow_redirects=False,
    )

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        pid = (await conn.execute(
            text("SELECT policy_id FROM local_policies WHERE name='p1'")
        )).scalar()

    csrf = await _csrf_from_list(proxy_logged_in)
    resp = await proxy_logged_in.post(
        f"/proxy/local-policies/{pid}/toggle",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    async with get_db() as conn:
        enabled = (await conn.execute(
            text("SELECT enabled FROM local_policies WHERE policy_id=:pid"),
            {"pid": pid},
        )).scalar()
    assert enabled == 0  # flipped off


@pytest.mark.asyncio
async def test_delete_removes_row(proxy_logged_in):
    csrf = await _csrf_from_list(proxy_logged_in)
    await proxy_logged_in.post(
        "/proxy/local-policies/create",
        data={
            "csrf_token": csrf, "name": "to-delete", "policy_type": "message",
            "rules_json": json.dumps({"effect": "allow", "conditions": {}}),
        },
        follow_redirects=False,
    )

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        pid = (await conn.execute(
            text("SELECT policy_id FROM local_policies WHERE name='to-delete'")
        )).scalar()

    csrf = await _csrf_from_list(proxy_logged_in)
    resp = await proxy_logged_in.post(
        f"/proxy/local-policies/{pid}/delete",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    async with get_db() as conn:
        count = (await conn.execute(
            text("SELECT COUNT(*) FROM local_policies WHERE policy_id=:pid"),
            {"pid": pid},
        )).scalar()
    assert count == 0


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
            resp = await client.get("/proxy/local-policies",
                                    follow_redirects=False)
            # Not logged in → redirect to login.
            assert resp.status_code == 303
    get_settings.cache_clear()
