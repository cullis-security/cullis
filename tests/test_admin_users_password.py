"""AD-style password layer for user principals — admin endpoints.

Covers the password fields added in migration 0026:
  - create_user: with password sets bcrypt hash + must_change_password
  - create_user: idempotent top-up when existing row has no password
  - create_user: 409 when caller tries to re-set an already-set password
  - reset_password: rotates hash + re-arms must_change_password
  - deactivate / reactivate: flip the disabled flag
  - delete_user: 204 (idempotent on missing row)

The password verification + JWT minting paths live in
``test_password_login.py``. This file pins the admin-facing surface
the dashboard wires its forms to.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

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


# ── create with password ───────────────────────────────────────────────


async def test_create_with_password_sets_hash_and_flag(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-create")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/users",
                headers=h,
                json={
                    "user_name": "alice",
                    "display_name": "Alice Rossi",
                    "reach": "intra",
                    "password": "InitialPwd!2026",
                },
            )
            assert r.status_code == 201, r.text
            data = r.json()
            assert data["has_password"] is True
            assert data["must_change_password"] is True
            assert data["disabled"] is False
            assert "password" not in data  # never echo plaintext
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_without_password_leaves_sso_only(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-noopt")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/users",
                headers=h,
                json={"user_name": "bob"},
            )
            assert r.status_code == 201
            data = r.json()
            assert data["has_password"] is False
            assert data["must_change_password"] is False
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_top_up_password_on_existing_sso_row(
    tmp_path, monkeypatch,
):
    """Admin pre-created the row via SSO upsert (no password); now wants
    to attach a local credential. Endpoint must accept it and flip the
    flag without overwriting other metadata."""
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-topup")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "carol", "display_name": "Carol"},
            )
            r = await cli.post(
                "/v1/admin/users", headers=h,
                json={
                    "user_name": "carol",
                    "display_name": "ignored",  # idempotency: kept old
                    "password": "SecondShot!2026",
                },
            )
            assert r.status_code == 201
            data = r.json()
            assert data["display_name"] == "Carol"  # original preserved
            assert data["has_password"] is True
            assert data["must_change_password"] is True
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_rejects_password_replacement(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-noreuse")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "dave", "password": "FirstPwd!2026"},
            )
            r = await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "dave", "password": "SecondPwd!2026"},
            )
            assert r.status_code == 409
            assert "reset-password" in r.json()["detail"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_create_rejects_too_short_password(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-short")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "eve", "password": "short"},
            )
            assert r.status_code == 422
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── reset password ─────────────────────────────────────────────────────


async def test_reset_password_rotates_hash_and_rearms_flag(
    tmp_path, monkeypatch,
):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-reset")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "frank", "password": "InitialPwd!2026"},
            )
            # Verify the change-flag clears via change-password (simulated
            # by direct DB poke) so reset truly re-arms.
            from mcp_proxy.db import get_db
            async with get_db() as conn:
                await conn.execute(
                    text(
                        "UPDATE local_user_principals "
                        "   SET must_change_password = :mcp "
                        " WHERE user_name = 'frank'"
                    ),
                    {"mcp": False},
                )

            r = await cli.post(
                "/v1/admin/users/pw-reset::user::frank/reset-password",
                headers=h,
                json={"new_password": "RotatedPwd!2026"},
            )
            assert r.status_code == 200, r.text
            data = r.json()
            assert data["has_password"] is True
            assert data["must_change_password"] is True
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_reset_password_404_for_missing_principal(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-reset-404")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/users/pw-reset-404::user::ghost/reset-password",
                headers=h,
                json={"new_password": "AnyPwd!2026"},
            )
            assert r.status_code == 404
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── deactivate / reactivate ────────────────────────────────────────────


async def test_deactivate_then_reactivate_flips_flag(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-flip")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "gail"},
            )
            pid = "pw-flip::user::gail"

            r = await cli.post(
                f"/v1/admin/users/{pid}/deactivate", headers=h,
            )
            assert r.status_code == 200
            assert r.json()["disabled"] is True

            r = await cli.post(
                f"/v1/admin/users/{pid}/reactivate", headers=h,
            )
            assert r.status_code == 200
            assert r.json()["disabled"] is False
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_deactivate_404_for_missing(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-deact-404")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/users/pw-deact-404::user::ghost/deactivate",
                headers=h,
            )
            assert r.status_code == 404
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── delete ─────────────────────────────────────────────────────────────


async def test_delete_user_purges_row(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-del")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            await cli.post(
                "/v1/admin/users", headers=h,
                json={"user_name": "harry"},
            )
            r = await cli.delete(
                "/v1/admin/users/pw-del::user::harry", headers=h,
            )
            assert r.status_code == 204

            r = await cli.get("/v1/admin/users", headers=h)
            assert r.json()["total"] == 0
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_delete_user_idempotent_on_missing(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "pw-del-noop")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.delete(
                "/v1/admin/users/pw-del-noop::user::ghost", headers=h,
            )
            assert r.status_code == 204
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
