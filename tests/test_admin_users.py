"""Mastio admin API for user principals — POST + GET + auth + filters."""
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


async def _headers():
    from mcp_proxy.config import get_settings
    return {"X-Admin-Secret": get_settings().admin_secret}


# ── create ─────────────────────────────────────────────────────────────


async def test_create_user_writes_row(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "users-create")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/users",
                headers=h,
                json={
                    "user_name": "claim-officer",
                    "display_name": "Marco Conti",
                    "reach": "intra",
                    "surface": "cullis-chat",
                },
            )
            assert r.status_code == 201, r.text
            data = r.json()
            assert data["principal_id"] == "users-create::user::claim-officer"
            assert data["display_name"] == "Marco Conti"
            assert data["reach"] == "intra"
            assert data["surface"] == "cullis-chat"
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_idempotent_on_repost(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "users-idem")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "kenji", "display_name": "Kenji Watanabe"},
            )
            # Re-POST with a different display_name; existing row wins.
            r = await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "kenji", "display_name": "Different"},
            )
            assert r.status_code == 201
            assert r.json()["display_name"] == "Kenji Watanabe"
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_rejects_bad_reach(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "users-reach")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "x", "reach": "global"},
            )
            assert r.status_code == 400
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── list + filter ──────────────────────────────────────────────────────


async def test_list_returns_created_users(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "users-list")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            for spec in (
                {"user_name": "officer", "display_name": "Marco",
                 "reach": "intra", "surface": "cullis-chat"},
                {"user_name": "manager", "display_name": "Lucia",
                 "reach": "both", "surface": "cullis-chat"},
                {"user_name": "liaison", "display_name": "Kenji",
                 "reach": "cross", "surface": "frontdesk"},
            ):
                await cli.post("/v1/admin/users", headers=h, json=spec)

            r = await cli.get("/v1/admin/users", headers=h)
            assert r.status_code == 200
            data = r.json()
            assert data["total"] == 3
            names = {u["user_name"] for u in data["users"]}
            assert names == {"officer", "manager", "liaison"}

            # Reach filter.
            r2 = await cli.get(
                "/v1/admin/users?reach=cross", headers=h,
            )
            assert {u["user_name"] for u in r2.json()["users"]} == {"liaison"}

            # Surface filter.
            r3 = await cli.get(
                "/v1/admin/users?surface=frontdesk", headers=h,
            )
            assert {u["user_name"] for u in r3.json()["users"]} == {"liaison"}

            # q filter on display_name.
            r4 = await cli.get(
                "/v1/admin/users?q=lucia", headers=h,
            )
            assert {u["user_name"] for u in r4.json()["users"]} == {"manager"}
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── auth ───────────────────────────────────────────────────────────────


async def test_auth_required(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "users-auth")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get("/v1/admin/users")
            assert r.status_code == 422  # header missing
            r = await cli.get(
                "/v1/admin/users",
                headers={"X-Admin-Secret": "wrong"},
            )
            assert r.status_code == 403
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── upsert from CSR sign ───────────────────────────────────────────────


async def test_upsert_from_csr_creates_row(tmp_path, monkeypatch):
    """``upsert_from_csr`` is the runtime helper the CSR endpoint calls
    after a successful signature. Verifies the side-effect directly,
    keeping the unit test below the HTTP layer because exercising the
    full CSR path requires DPoP-bound auth fixtures the rest of the
    suite already covers separately."""
    app = await _spin_proxy(tmp_path, monkeypatch, "users-csr")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            from mcp_proxy.admin.users import upsert_from_csr
            await upsert_from_csr(
                principal_id="users-csr.cullis.test/users-csr/user/jane",
                org_id="users-csr",
                cert_thumbprint="sha256:" + "0" * 16,
            )
            h = await _headers()
            r = await cli.get("/v1/admin/users", headers=h)
            data = r.json()
            assert data["total"] == 1
            assert data["users"][0]["user_name"] == "jane"
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
