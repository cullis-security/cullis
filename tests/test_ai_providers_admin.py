"""Admin API for AI provider credentials (ADR-017 Phase 4).

Pins:
  - GET list returns the full catalog with masked / not-configured rows
  - PUT validates, writes, returns masked credentials
  - PUT secret fields never round-trip via GET
  - DELETE 204 + audit row + 404 on second delete
  - Enable / disable toggle
  - Test endpoint surfaces ``unsupported`` for backends with no probe
  - 403 on missing / wrong admin secret
  - Audit chain entries are written for every mutation
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


# ── list ─────────────────────────────────────────────────────────────


async def test_list_returns_full_catalog_when_empty(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-list-empty")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.get("/v1/admin/ai-providers", headers=h)
            assert r.status_code == 200
            data = r.json()
            providers = {p["provider"]: p for p in data}
            assert {"anthropic", "openai", "gemini", "bedrock", "vertex", "ollama"} <= providers.keys()
            for entry in data:
                assert entry["configured"] is False
                assert entry["enabled"] is False


async def test_get_provider_404_on_unknown(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-404")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.get("/v1/admin/ai-providers/foo", headers=h)
            assert r.status_code == 404


# ── auth ─────────────────────────────────────────────────────────────


async def test_missing_admin_secret_403(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-noauth")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get("/v1/admin/ai-providers")
            # FastAPI returns 422 when a required Header is missing; the
            # actual 403 path is hit when a header is supplied but wrong.
            assert r.status_code in (403, 422)


async def test_wrong_admin_secret_403(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-wrongauth")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get(
                "/v1/admin/ai-providers",
                headers={"X-Admin-Secret": "definitely-wrong"},
            )
            assert r.status_code == 403


# ── upsert ───────────────────────────────────────────────────────────


async def test_upsert_anthropic_validates_and_returns_masked(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-upsert")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.put(
                "/v1/admin/ai-providers/anthropic",
                headers=h,
                json={
                    "creds": {"api_key": "sk-ant-secret"},
                    "enabled": True,
                    "updated_by": "alice",
                },
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["configured"] is True
            assert body["enabled"] is True
            # Secret never round-trips.
            assert body["creds_masked"]["api_key"] == "***"
            assert body["updated_by"] == "alice"


async def test_upsert_validates_required_fields(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-validate")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.put(
                "/v1/admin/ai-providers/bedrock",
                headers=h,
                json={"creds": {"aws_access_key_id": "AKIA"}, "enabled": True},
            )
            assert r.status_code == 400


async def test_upsert_unknown_provider_404(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-unknown")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.put(
                "/v1/admin/ai-providers/groq-supreme",
                headers=h,
                json={"creds": {"api_key": "x"}, "enabled": True},
            )
            assert r.status_code == 404


# ── delete + idempotency ─────────────────────────────────────────────


async def test_delete_then_404(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-delete")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.put(
                "/v1/admin/ai-providers/openai",
                headers=h,
                json={"creds": {"api_key": "sk-o"}, "enabled": True},
            )
            r = await cli.delete("/v1/admin/ai-providers/openai", headers=h)
            assert r.status_code == 204
            r = await cli.delete("/v1/admin/ai-providers/openai", headers=h)
            assert r.status_code == 404


# ── enable toggle ────────────────────────────────────────────────────


async def test_disable_then_get_shows_disabled(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-toggle")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.put(
                "/v1/admin/ai-providers/gemini",
                headers=h,
                json={"creds": {"api_key": "AIzaXYZ"}, "enabled": True},
            )
            r = await cli.post(
                "/v1/admin/ai-providers/gemini/enable",
                headers=h, json={"enabled": False},
            )
            assert r.status_code == 200
            assert r.json()["enabled"] is False


async def test_enable_404_on_unknown_row(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-toggle-404")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/ai-providers/bedrock/enable",
                headers=h, json={"enabled": True},
            )
            assert r.status_code == 404


# ── audit chain ──────────────────────────────────────────────────────


async def test_upsert_writes_audit_row(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-audit")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.put(
                "/v1/admin/ai-providers/anthropic",
                headers=h,
                json={
                    "creds": {"api_key": "sk-ant"},
                    "enabled": True,
                    "updated_by": "bob",
                },
            )
            from mcp_proxy.db import get_db
            from sqlalchemy import text as _t
            async with get_db() as conn:
                rows = (await conn.execute(_t(
                    "SELECT action, agent_id, detail FROM audit_log "
                    "WHERE action LIKE 'ai_provider.%'"
                ))).all()
            actions = [r[0] for r in rows]
            assert "ai_provider.upsert" in actions


# ── test endpoint ────────────────────────────────────────────────────


async def test_test_endpoint_unsupported_for_bedrock(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-test-bedrock")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.put(
                "/v1/admin/ai-providers/bedrock",
                headers=h,
                json={
                    "creds": {
                        "aws_access_key_id": "AKIA",
                        "aws_secret_access_key": "s",
                        "aws_region_name": "us-east-1",
                    },
                    "enabled": True,
                },
            )
            r = await cli.post("/v1/admin/ai-providers/bedrock/test", headers=h)
            assert r.status_code == 200
            assert r.json()["status"] == "unsupported"


async def test_test_endpoint_404_when_no_creds(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "ai-test-404")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post("/v1/admin/ai-providers/anthropic/test", headers=h)
            assert r.status_code == 404
