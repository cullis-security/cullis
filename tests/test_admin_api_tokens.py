"""Admin REST API for user API tokens (ADR-027 Phase 1, PR 3).

Pins on the wire-level behaviour:

  * POST mint returns cleartext token in the 201 body
  * Subsequent GETs never expose ``token`` or ``token_hash``
  * GET list filters by ``principal_id`` and respects ``include_revoked``
  * GET single returns 404 on unknown id
  * DELETE 204 + audit row, idempotent on already-revoked
  * 403 on missing / wrong ``X-Admin-Secret``
  * End-to-end: mint via REST + use the token to auth a ``/v1/models``
    call (closes the loop with PR 2's resolver)

Uses the full app with both PR 2 (auth resolver) and PR 3 (admin
endpoints) mounted. DB is a tmp sqlite migrated through 0029.
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


async def _seed_common_users(org_id: str | None = None) -> None:
    """Wave A C3 (audit 2026-05-11) — mint_user_api_token now requires
    the principal_id row to exist. Seed the common test names against
    the current org (from ``get_settings().org_id`` when not passed)
    so existing mint POSTs continue to work without each test
    pre-creating the row via /v1/admin/users. Call inside the
    ``async with app.router.lifespan_context(app):`` block (after
    init_db has fired) and before the first mint."""
    if org_id is None:
        from mcp_proxy.config import get_settings
        org_id = get_settings().org_id
    from tests._token_test_helpers import seed_test_principal
    for name in (
        "alice", "bob", "carol", "dave", "eve", "erin",
        "frank", "ferris", "grace", "heidi", "ivan",
        "jane", "ken", "leo", "mia",
    ):
        await seed_test_principal(f"{org_id}::user::{name}")


async def _headers():
    from mcp_proxy.config import get_settings
    return {"X-Admin-Secret": get_settings().admin_secret}


# ── auth ─────────────────────────────────────────────────────────────


async def test_missing_admin_secret_rejected(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-auth-1")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get("/v1/admin/api-tokens")
            # FastAPI returns 422 for missing required Header param.
            assert r.status_code in (403, 422), r.text


async def test_wrong_admin_secret_rejected(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-auth-2")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get(
                "/v1/admin/api-tokens",
                headers={"X-Admin-Secret": "wrong-secret"},
            )
            assert r.status_code == 403, r.text


# ── mint ─────────────────────────────────────────────────────────────


async def test_mint_returns_cleartext_token_once(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-mint-1")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            r = await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={
                    "principal_id": "tok-mint-1::user::alice",
                    "label": "Cursor laptop",
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["token"].startswith("culk_")
            assert len(body["token"]) == 57
            assert body["token_last4"] == body["token"][-4:]
            assert body["principal_id"] == "tok-mint-1::user::alice"
            assert body["label"] == "Cursor laptop"
            token_id = body["id"]

            # GET single never shows cleartext
            r2 = await cli.get(f"/v1/admin/api-tokens/{token_id}", headers=h)
            assert r2.status_code == 200
            body2 = r2.json()
            assert "token" not in body2
            assert "token_hash" not in body2
            assert body2["token_last4"] == body["token_last4"]


async def test_mint_with_scope_and_expiry(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-mint-2")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            r = await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={
                    "principal_id": "tok-mint-2::user::bob",
                    "label": "LibreChat anthropic-only",
                    "scope_providers": ["anthropic"],
                    "expires_at": "2027-01-01T00:00:00+00:00",
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["scope_providers"] == ["anthropic"]
            assert body["expires_at"] == "2027-01-01T00:00:00+00:00"


async def test_mint_rejects_empty_label(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-mint-3")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            r = await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={
                    "principal_id": "tok-mint-3::user::eve",
                    "label": "",
                },
            )
            # Pydantic Field min_length=1 -> 422
            assert r.status_code == 422, r.text


# ── list ─────────────────────────────────────────────────────────────


async def test_list_filters_by_principal(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-list-1")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={"principal_id": "tok-list-1::user::alice", "label": "a1"},
            )
            await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={"principal_id": "tok-list-1::user::bob", "label": "b1"},
            )

            r = await cli.get(
                "/v1/admin/api-tokens?principal_id=tok-list-1::user::alice",
                headers=h,
            )
            assert r.status_code == 200
            body = r.json()
            assert body["total"] == 1
            assert body["tokens"][0]["principal_id"] == "tok-list-1::user::alice"

            r_all = await cli.get("/v1/admin/api-tokens", headers=h)
            assert r_all.json()["total"] == 2


async def test_list_excludes_revoked_by_default(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-list-2")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            r1 = await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={"principal_id": "tok-list-2::user::carol", "label": "active"},
            )
            r2 = await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={"principal_id": "tok-list-2::user::carol", "label": "to-revoke"},
            )
            await cli.delete(
                f"/v1/admin/api-tokens/{r2.json()['id']}",
                headers=h,
            )
            r_default = await cli.get(
                "/v1/admin/api-tokens?principal_id=tok-list-2::user::carol",
                headers=h,
            )
            assert r_default.json()["total"] == 1
            assert r_default.json()["tokens"][0]["id"] == r1.json()["id"]

            r_all = await cli.get(
                "/v1/admin/api-tokens?principal_id=tok-list-2::user::carol&include_revoked=true",
                headers=h,
            )
            assert r_all.json()["total"] == 2


# ── revoke ───────────────────────────────────────────────────────────


async def test_revoke_204_and_idempotent(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-revoke-1")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            r = await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={"principal_id": "tok-revoke-1::user::dave", "label": "x"},
            )
            tid = r.json()["id"]

            d1 = await cli.delete(f"/v1/admin/api-tokens/{tid}", headers=h)
            assert d1.status_code == 204

            d2 = await cli.delete(f"/v1/admin/api-tokens/{tid}", headers=h)
            # idempotent: still 204, audit row tags effective=False
            assert d2.status_code == 204


async def test_revoke_unknown_returns_404(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-revoke-2")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            d = await cli.delete("/v1/admin/api-tokens/nonexistent-id", headers=h)
            assert d.status_code == 404


# ── audit ────────────────────────────────────────────────────────────


async def test_mint_writes_audit_row(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "tok-audit-1")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={"principal_id": "tok-audit-1::user::erin", "label": "audited"},
            )

        # Read audit log directly (lifespan exit dispose_db'd; reopen)
        from mcp_proxy.db import get_db, init_db, dispose_db
        from sqlalchemy import text
        await init_db(
            f"sqlite+aiosqlite:///{tmp_path / 'proxy.sqlite'}",
        )
        try:
            async with get_db() as conn:
                result = await conn.execute(
                    text(
                        "SELECT action, status, agent_id "
                        "FROM audit_log WHERE action = 'api_token.mint'"
                    ),
                )
                rows = result.mappings().all()
        finally:
            await dispose_db()
        assert len(rows) == 1
        assert rows[0]["action"] == "api_token.mint"
        assert rows[0]["status"] == "success"


# ── end-to-end with PR 2 resolver ────────────────────────────────────


async def test_mint_via_rest_then_auth_v1_models(tmp_path, monkeypatch):
    """Closes the loop: a token minted via the admin REST API is
    immediately usable as Bearer for ``/v1/models`` (the PR 2 resolver
    finds it). This is the demo flow customers will run."""
    monkeypatch.setenv("MCP_PROXY_ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("MCP_PROXY_AI_GATEWAY_BACKEND", "litellm_embedded")
    monkeypatch.setenv("MCP_PROXY_AI_GATEWAY_PROVIDER", "anthropic")

    app = await _spin_proxy(tmp_path, monkeypatch, "tok-e2e-1")

    # Patch list_available_models inside the live module to avoid
    # upstream catalogue traffic.
    from mcp_proxy.egress import llm_chat_router as router_module
    async def fake_list_available_models(enabled):
        return [{"id": "claude-haiku-4-5", "object": "model", "owned_by": "anthropic"}]
    monkeypatch.setattr(
        router_module, "list_available_models", fake_list_available_models,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_common_users()
            h = await _headers()
            r = await cli.post(
                "/v1/admin/api-tokens",
                headers=h,
                json={"principal_id": "tok-e2e-1::user::ferris", "label": "e2e"},
            )
            assert r.status_code == 201
            token = r.json()["token"]

            r2 = await cli.get(
                "/v1/models",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert r2.status_code == 200, r2.text
            assert r2.json()["data"][0]["id"] == "claude-haiku-4-5"
