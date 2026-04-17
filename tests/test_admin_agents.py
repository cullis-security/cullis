"""ADR-010 Phase 2 — Mastio ``/v1/admin/agents`` admin API.

Covers:
  - POST creates agent + emits api_key + cert
  - POST with federated=true writes the flag
  - GET list returns all agents with federated info
  - PATCH flip federated bumps ``federation_revision``
  - DELETE soft-deletes (is_active=0)
  - Auth: missing / wrong ``X-Admin-Secret`` rejected
  - Duplicate agent_name → 409
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


async def _headers():
    from mcp_proxy.config import get_settings
    return {"X-Admin-Secret": get_settings().admin_secret}


# ── create ─────────────────────────────────────────────────────────────

async def test_create_agent_emits_key_and_cert(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-create")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/agents",
                headers=h,
                json={
                    "agent_name": "alice",
                    "display_name": "Alice the explorer",
                    "capabilities": ["order.read"],
                    "federated": False,
                },
            )
            assert r.status_code == 201, r.text
            data = r.json()
            assert data["agent_id"] == "aa-create::alice"
            assert data["capabilities"] == ["order.read"]
            assert data["federated"] is False
            assert data["api_key"].startswith("sk_local_alice_")
            assert "BEGIN CERTIFICATE" in data["cert_pem"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_accepts_pre_generated_cert(tmp_path, monkeypatch):
    """ADR-010 Phase 4 — bootstrap-style path: caller provides an already-
    minted cert+key (signed by the same Org CA), Mastio stores them
    verbatim instead of minting new ones."""
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-preout")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            mgr = app.state.agent_manager
            # Mint externally, then re-submit via API.
            cert_pem, key_pem = mgr._generate_agent_cert("ext-alice")
            h = await _headers()
            r = await cli.post(
                "/v1/admin/agents", headers=h,
                json={
                    "agent_name": "ext-alice",
                    "cert_pem": cert_pem,
                    "private_key_pem": key_pem,
                    "federated": True,
                },
            )
            assert r.status_code == 201, r.text
            # The returned cert_pem must be the exact bytes we submitted —
            # proving the Mastio didn't re-mint.
            assert r.json()["cert_pem"] == cert_pem
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_rejects_half_pre_generated_material(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-half")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/agents", headers=h,
                json={
                    "agent_name": "half-bob",
                    "cert_pem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
                },
            )
            assert r.status_code == 400
            assert "provided together" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_with_federated_flag(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-fed")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/agents", headers=h,
                json={"agent_name": "bob", "federated": True},
            )
            assert r.status_code == 201
            assert r.json()["federated"] is True
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_duplicate_returns_409(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-dup")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            body = {"agent_name": "charlie"}
            r1 = await cli.post("/v1/admin/agents", headers=h, json=body)
            assert r1.status_code == 201
            r2 = await cli.post("/v1/admin/agents", headers=h, json=body)
            assert r2.status_code == 409
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── list / patch / delete ──────────────────────────────────────────────

async def test_list_shows_federated_info(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-list")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post("/v1/admin/agents", headers=h,
                           json={"agent_name": "dave", "federated": False})
            await cli.post("/v1/admin/agents", headers=h,
                           json={"agent_name": "eve", "federated": True})
            r = await cli.get("/v1/admin/agents", headers=h)
            assert r.status_code == 200
            rows = r.json()
            by_name = {row["agent_id"]: row for row in rows}
            assert by_name["aa-list::dave"]["federated"] is False
            assert by_name["aa-list::eve"]["federated"] is True
            assert all(row["federation_revision"] >= 1 for row in rows)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_patch_federated_bumps_revision(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-patch")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post("/v1/admin/agents", headers=h,
                           json={"agent_name": "frank", "federated": False})
            r = await cli.patch(
                "/v1/admin/agents/aa-patch::frank/federated",
                headers=h, json={"federated": True},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["federated"] is True
            assert body["federation_revision"] >= 2
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_patch_unknown_agent_returns_404(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-p404")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.patch(
                "/v1/admin/agents/aa-p404::ghost/federated",
                headers=h, json={"federated": True},
            )
            assert r.status_code == 404
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_delete_deactivates(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-del")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post("/v1/admin/agents", headers=h,
                           json={"agent_name": "gina"})
            r = await cli.delete(
                "/v1/admin/agents/aa-del::gina", headers=h,
            )
            assert r.status_code == 204
            # Second delete should 404 (already inactive).
            r2 = await cli.delete(
                "/v1/admin/agents/aa-del::gina", headers=h,
            )
            assert r2.status_code == 404
            # list still shows the row with is_active=false.
            rl = await cli.get("/v1/admin/agents", headers=h)
            row = next(r for r in rl.json() if r["agent_id"] == "aa-del::gina")
            assert row["is_active"] is False
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── auth ───────────────────────────────────────────────────────────────

async def test_auth_required(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "aa-auth")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get("/v1/admin/agents")
            assert r.status_code == 422  # header missing
            r = await cli.get(
                "/v1/admin/agents",
                headers={"X-Admin-Secret": "wrong"},
            )
            assert r.status_code == 403
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
