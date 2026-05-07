"""Mastio admin API for workload principals — POST + GET + auth + filters."""
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


async def test_create_workload_writes_row(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "wl-create")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/workloads", headers=h,
                json={
                    "workload_name": "frontdesk-container",
                    "display_name": "Asia-Pacific Frontdesk",
                    "image_digest": "sha256:abc",
                    "runtime_status": "running",
                },
            )
            assert r.status_code == 201, r.text
            data = r.json()
            assert data["principal_id"] == "wl-create::workload::frontdesk-container"
            assert data["display_name"] == "Asia-Pacific Frontdesk"
            assert data["image_digest"] == "sha256:abc"
            assert data["runtime_status"] == "running"
            assert data["hosted_principals_count"] == 0
            assert data["hosted_principals_sample"] == []
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_idempotent_on_repost(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "wl-idem")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post(
                "/v1/admin/workloads", headers=h,
                json={"workload_name": "fd",
                      "display_name": "Original"},
            )
            r = await cli.post(
                "/v1/admin/workloads", headers=h,
                json={"workload_name": "fd", "display_name": "Different"},
            )
            assert r.status_code == 201
            assert r.json()["display_name"] == "Original"
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_rejects_bad_status(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "wl-status")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/workloads", headers=h,
                json={"workload_name": "x", "runtime_status": "exploded"},
            )
            assert r.status_code == 400
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── list + filter ──────────────────────────────────────────────────────


async def test_list_returns_created_workloads(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "wl-list")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            for spec in (
                {"workload_name": "fd-tokyo",
                 "display_name": "Frontdesk Tokyo",
                 "runtime_status": "running"},
                {"workload_name": "fd-osaka",
                 "display_name": "Frontdesk Osaka",
                 "runtime_status": "stopped"},
            ):
                await cli.post("/v1/admin/workloads", headers=h, json=spec)

            r = await cli.get("/v1/admin/workloads", headers=h)
            data = r.json()
            assert data["total"] == 2

            r2 = await cli.get(
                "/v1/admin/workloads?runtime_status=running", headers=h,
            )
            names = {w["workload_name"] for w in r2.json()["workloads"]}
            assert names == {"fd-tokyo"}

            r3 = await cli.get(
                "/v1/admin/workloads?q=osaka", headers=h,
            )
            names = {w["workload_name"] for w in r3.json()["workloads"]}
            assert names == {"fd-osaka"}
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_hosted_principals_count_reflects_users(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "wl-hosted")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            # Two users on this Mastio.
            for name in ("alice", "bob"):
                await cli.post(
                    "/v1/admin/users", headers=h,
                    json={"user_name": name, "display_name": name.title()},
                )
            await cli.post(
                "/v1/admin/workloads", headers=h,
                json={"workload_name": "fd",
                      "display_name": "Frontdesk",
                      "runtime_status": "running"},
            )

            r = await cli.get("/v1/admin/workloads", headers=h)
            wl = r.json()["workloads"][0]
            assert wl["hosted_principals_count"] == 2
            assert len(wl["hosted_principals_sample"]) == 2
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── auth ───────────────────────────────────────────────────────────────


async def test_auth_required(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "wl-auth")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get("/v1/admin/workloads")
            assert r.status_code == 422
            r = await cli.get(
                "/v1/admin/workloads",
                headers={"X-Admin-Secret": "wrong"},
            )
            assert r.status_code == 403
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
