"""Proxy /v1/admin/mcp-resources JSON API — CRUD + bindings.

Covers the Connector-facing API that complements the HTML form admin.
Auth is X-Admin-Secret (Connector prompts for it on-demand).
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


async def _spin_proxy(tmp_path, monkeypatch, org_id: str):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def _admin_headers():
    from mcp_proxy.config import get_settings
    return {"X-Admin-Secret": get_settings().admin_secret}


# ── resources CRUD ─────────────────────────────────────────────────────

async def test_create_list_delete_resource(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "mcp-crud")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _admin_headers()

            # create
            r = await cli.post(
                "/v1/admin/mcp-resources",
                headers=h,
                json={
                    "name": "catalog",
                    "endpoint_url": "http://mcp-catalog:9300/",
                    "description": "Catalog MCP",
                    "auth_type": "none",
                    "org_id": "mcp-crud",
                    "enabled": True,
                },
            )
            assert r.status_code == 201, r.text
            resource_id = r.json()["resource_id"]

            # list
            r = await cli.get("/v1/admin/mcp-resources", headers=h)
            assert r.status_code == 200
            names = [x["name"] for x in r.json()]
            assert "catalog" in names

            # delete
            r = await cli.delete(
                f"/v1/admin/mcp-resources/{resource_id}", headers=h,
            )
            assert r.status_code == 204

            r = await cli.get("/v1/admin/mcp-resources", headers=h)
            assert r.status_code == 200
            assert all(x["name"] != "catalog" for x in r.json())

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_rejects_invalid(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "mcp-invalid")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _admin_headers()

            # name with spaces
            r = await cli.post(
                "/v1/admin/mcp-resources",
                headers=h,
                json={"name": "bad name", "endpoint_url": "http://x/"},
            )
            assert r.status_code == 400

            # non-http endpoint
            r = await cli.post(
                "/v1/admin/mcp-resources",
                headers=h,
                json={"name": "valid", "endpoint_url": "ftp://x/"},
            )
            assert r.status_code == 400

            # bad auth_type
            r = await cli.post(
                "/v1/admin/mcp-resources",
                headers=h,
                json={
                    "name": "valid",
                    "endpoint_url": "http://x/",
                    "auth_type": "psk",
                },
            )
            assert r.status_code == 400

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_conflict_on_duplicate(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "mcp-dup")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _admin_headers()
            body = {
                "name": "catalog",
                "endpoint_url": "http://x/",
                "org_id": "mcp-dup",
            }
            r = await cli.post("/v1/admin/mcp-resources", headers=h, json=body)
            assert r.status_code == 201
            r = await cli.post("/v1/admin/mcp-resources", headers=h, json=body)
            assert r.status_code == 409

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── auth ───────────────────────────────────────────────────────────────

async def test_requires_admin_secret(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "mcp-auth")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            # missing header
            r = await cli.get("/v1/admin/mcp-resources")
            assert r.status_code == 422
            # wrong secret
            r = await cli.get(
                "/v1/admin/mcp-resources",
                headers={"X-Admin-Secret": "wrong"},
            )
            assert r.status_code == 403

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── bindings ───────────────────────────────────────────────────────────

async def test_binding_lifecycle(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "mcp-bind")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _admin_headers()

            r = await cli.post(
                "/v1/admin/mcp-resources",
                headers=h,
                json={
                    "name": "catalog",
                    "endpoint_url": "http://x/",
                    "org_id": "mcp-bind",
                },
            )
            rid = r.json()["resource_id"]

            # bind agent
            r = await cli.post(
                "/v1/admin/mcp-resources/bindings",
                headers=h,
                json={"agent_id": "mcp-bind::alice", "resource_id": rid},
            )
            assert r.status_code == 201, r.text
            bid = r.json()["binding_id"]

            # duplicate → 409
            r = await cli.post(
                "/v1/admin/mcp-resources/bindings",
                headers=h,
                json={"agent_id": "mcp-bind::alice", "resource_id": rid},
            )
            assert r.status_code == 409

            # revoke
            r = await cli.delete(
                f"/v1/admin/mcp-resources/bindings/{bid}", headers=h,
            )
            assert r.status_code == 204

            # revoke again → 404
            r = await cli.delete(
                f"/v1/admin/mcp-resources/bindings/{bid}", headers=h,
            )
            assert r.status_code == 404

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_binding_unknown_resource(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "mcp-bind-404")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _admin_headers()
            r = await cli.post(
                "/v1/admin/mcp-resources/bindings",
                headers=h,
                json={"agent_id": "x::a", "resource_id": "does-not-exist"},
            )
            assert r.status_code == 404

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── ADR-020 — typed-principal bindings via admin API ─────────────────


async def test_binding_user_principal_separate_from_agent(
    tmp_path, monkeypatch,
):
    """Admin creates two bindings: one for ``daniele`` as ``agent`` and one
    for the *same* canonical name as ``user``. Both succeed (the unique
    constraint is on ``(agent_id, principal_type, resource_id)``) and the
    response echoes ``principal_type`` back."""
    app = await _spin_proxy(tmp_path, monkeypatch, "mcp-bind-typed")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _admin_headers()

            r = await cli.post(
                "/v1/admin/mcp-resources",
                headers=h,
                json={
                    "name": "postgres",
                    "endpoint_url": "http://pg/",
                    "org_id": "mcp-bind-typed",
                },
            )
            rid = r.json()["resource_id"]

            # Default (agent).
            r = await cli.post(
                "/v1/admin/mcp-resources/bindings",
                headers=h,
                json={
                    "agent_id": "mcp-bind-typed::daniele",
                    "resource_id": rid,
                },
            )
            assert r.status_code == 201, r.text
            assert r.json()["principal_type"] == "agent"

            # Same name, principal_type=user → no collision.
            r = await cli.post(
                "/v1/admin/mcp-resources/bindings",
                headers=h,
                json={
                    "agent_id": "mcp-bind-typed::daniele",
                    "resource_id": rid,
                    "principal_type": "user",
                },
            )
            assert r.status_code == 201, r.text
            assert r.json()["principal_type"] == "user"

            # Re-creating the user one is the duplicate that 409s.
            r = await cli.post(
                "/v1/admin/mcp-resources/bindings",
                headers=h,
                json={
                    "agent_id": "mcp-bind-typed::daniele",
                    "resource_id": rid,
                    "principal_type": "user",
                },
            )
            assert r.status_code == 409, r.text

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_binding_rejects_unknown_principal_type(
    tmp_path, monkeypatch,
):
    """``principal_type`` must be one of agent/user/workload — anything
    else is a 422 from the request validator."""
    app = await _spin_proxy(tmp_path, monkeypatch, "mcp-bind-bad-pt")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _admin_headers()
            r = await cli.post(
                "/v1/admin/mcp-resources",
                headers=h,
                json={
                    "name": "x",
                    "endpoint_url": "http://x/",
                    "org_id": "mcp-bind-bad-pt",
                },
            )
            rid = r.json()["resource_id"]

            r = await cli.post(
                "/v1/admin/mcp-resources/bindings",
                headers=h,
                json={
                    "agent_id": "mcp-bind-bad-pt::a",
                    "resource_id": rid,
                    "principal_type": "service",
                },
            )
            assert r.status_code == 422, r.text

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
