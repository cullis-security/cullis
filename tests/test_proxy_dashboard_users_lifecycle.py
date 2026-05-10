"""Mastio dashboard — Users tab lifecycle (PR2 follow-up to PR #575).

Exercises the new dashboard endpoints layered on top of the AD-style
password backend already covered by ``test_admin_users_password.py``
and ``test_password_login.py``:

  POST /proxy/users/create                            (now password-aware)
  GET  /proxy/users/{principal_id}                    (detail page)
  POST /proxy/users/{principal_id}/deactivate
  POST /proxy/users/{principal_id}/reactivate
  POST /proxy/users/{principal_id}/delete
  POST /proxy/users/{principal_id}/reset-password

Mirrors the proxy_logged_in pattern from
``test_proxy_dashboard_mcp_resources.py`` so a future reader sees one
consistent integration-style fixture across every dashboard tab.
"""
from __future__ import annotations

import re
from urllib.parse import quote

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
    """Pull the CSRF token rendered on the Users page (any
    authenticated GET works — every dashboard page emits one)."""
    page = await client.get("/proxy/users")
    assert page.status_code == 200, page.text[:200]
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "csrf_token not found in /proxy/users body"
    return m.group(1)


async def _create(
    client, *, user_name: str, password: str | None = None,
    display_name: str = "", reach: str = "intra", surface: str = "",
):
    csrf = await _csrf(client)
    data = {
        "csrf_token": csrf,
        "user_name": user_name,
        "display_name": display_name,
        "reach": reach,
        "surface": surface,
    }
    if password is not None:
        data["password"] = password
    return await client.post(
        "/proxy/users/create", data=data, follow_redirects=False,
    )


async def _row(principal_id: str) -> dict | None:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT * FROM local_user_principals "
                " WHERE principal_id = :pid"
            ),
            {"pid": principal_id},
        )).mappings().first()
    return dict(row) if row else None


# ── create with password ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_with_password_sets_hash_and_flag(proxy_logged_in):
    cli = proxy_logged_in
    resp = await _create(
        cli, user_name="alice", display_name="Alice Rossi",
        password="InitialPwd!2026",
    )
    assert resp.status_code == 303, resp.text[:200]
    assert "/proxy/users?new_user_name=alice" in resp.headers["location"]

    row = await _row("acme::user::alice")
    assert row is not None
    assert row["password_hash"] is not None
    assert bool(row["must_change_password"]) is True
    assert bool(row["disabled"]) is False
    assert row["password_updated_at"] is not None


@pytest.mark.asyncio
async def test_create_without_password_leaves_sso_only(proxy_logged_in):
    cli = proxy_logged_in
    resp = await _create(cli, user_name="bob")
    assert resp.status_code == 303
    row = await _row("acme::user::bob")
    assert row is not None
    assert row["password_hash"] is None
    assert bool(row["must_change_password"]) is False


@pytest.mark.asyncio
async def test_create_top_up_password_on_existing_sso_row(proxy_logged_in):
    cli = proxy_logged_in
    # First create without password (SSO-only row).
    await _create(cli, user_name="carol")
    # Then re-create with a password to attach a credential.
    await _create(cli, user_name="carol", password="LaterPwd!2026")
    row = await _row("acme::user::carol")
    assert row["password_hash"] is not None
    assert bool(row["must_change_password"]) is True


@pytest.mark.asyncio
async def test_create_rejects_password_replacement(proxy_logged_in):
    cli = proxy_logged_in
    await _create(cli, user_name="dave", password="FirstPwd!2026")
    resp = await _create(cli, user_name="dave", password="SecondPwd!2026")
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]
    assert "Reset%20Password" in resp.headers["location"]


@pytest.mark.asyncio
async def test_create_rejects_short_password(proxy_logged_in):
    cli = proxy_logged_in
    resp = await _create(cli, user_name="eve", password="short")
    assert resp.status_code == 303
    assert "error=password" in resp.headers["location"]


# ── detail page ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detail_page_renders_user(proxy_logged_in):
    cli = proxy_logged_in
    await _create(
        cli, user_name="frank", display_name="Frank Conti",
        password="GoodPwd!2026",
    )
    resp = await cli.get(
        f"/proxy/users/{quote('acme::user::frank', safe='')}",
    )
    assert resp.status_code == 200, resp.text[:200]
    body = resp.text
    assert "Frank Conti" in body
    assert "acme::user::frank" in body
    # Status header on the right reflects pending password change.
    assert "Pending password change" in body
    # Danger Zone section is present with the three actions.
    assert "Danger Zone" in body
    assert "Reset Password" in body
    assert "Deactivate" in body
    assert "Delete User" in body


@pytest.mark.asyncio
async def test_detail_page_404_for_missing(proxy_logged_in):
    cli = proxy_logged_in
    resp = await cli.get(
        f"/proxy/users/{quote('acme::user::ghost', safe='')}",
    )
    assert resp.status_code == 404


# ── deactivate / reactivate ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_deactivate_then_reactivate_flips_disabled(proxy_logged_in):
    cli = proxy_logged_in
    await _create(cli, user_name="gail")
    pid = "acme::user::gail"
    csrf = await _csrf(cli)

    resp = await cli.post(
        f"/proxy/users/{quote(pid, safe='')}/deactivate",
        data={"csrf_token": csrf}, follow_redirects=False,
    )
    assert resp.status_code == 303
    row = await _row(pid)
    assert bool(row["disabled"]) is True

    resp = await cli.post(
        f"/proxy/users/{quote(pid, safe='')}/reactivate",
        data={"csrf_token": csrf}, follow_redirects=False,
    )
    assert resp.status_code == 303
    row = await _row(pid)
    assert bool(row["disabled"]) is False


@pytest.mark.asyncio
async def test_deactivate_404_for_missing(proxy_logged_in):
    cli = proxy_logged_in
    csrf = await _csrf(cli)
    resp = await cli.post(
        f"/proxy/users/{quote('acme::user::ghost', safe='')}/deactivate",
        data={"csrf_token": csrf}, follow_redirects=False,
    )
    assert resp.status_code == 404


# ── reset password ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reset_password_rotates_hash_and_rearms_flag(proxy_logged_in):
    cli = proxy_logged_in
    await _create(cli, user_name="harry", password="OldPwd!2026")
    pid = "acme::user::harry"
    # Manually clear the change-flag so the test proves reset re-arms it.
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text(
                "UPDATE local_user_principals SET must_change_password = :mcp "
                " WHERE principal_id = :pid"
            ),
            {"pid": pid, "mcp": False},
        )
    pre_hash = (await _row(pid))["password_hash"]

    csrf = await _csrf(cli)
    resp = await cli.post(
        f"/proxy/users/{quote(pid, safe='')}/reset-password",
        data={"csrf_token": csrf, "new_password": "BrandNew!2026"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    row = await _row(pid)
    assert row["password_hash"] != pre_hash  # rotated
    assert bool(row["must_change_password"]) is True


@pytest.mark.asyncio
async def test_reset_password_rejects_short(proxy_logged_in):
    cli = proxy_logged_in
    await _create(cli, user_name="ivy", password="OldPwd!2026")
    pid = "acme::user::ivy"
    csrf = await _csrf(cli)
    resp = await cli.post(
        f"/proxy/users/{quote(pid, safe='')}/reset-password",
        data={"csrf_token": csrf, "new_password": "tiny"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=" in resp.headers["location"]


# ── delete ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_purges_row_and_redirects_to_index(proxy_logged_in):
    cli = proxy_logged_in
    await _create(cli, user_name="jane")
    pid = "acme::user::jane"
    csrf = await _csrf(cli)
    resp = await cli.post(
        f"/proxy/users/{quote(pid, safe='')}/delete",
        data={"csrf_token": csrf}, follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/proxy/users?error=" in resp.headers["location"]
    assert await _row(pid) is None


# ── csrf guard ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lifecycle_endpoints_reject_missing_csrf(proxy_logged_in):
    cli = proxy_logged_in
    await _create(cli, user_name="ken")
    pid = "acme::user::ken"
    for action in ("deactivate", "reactivate", "delete", "reset-password"):
        resp = await cli.post(
            f"/proxy/users/{quote(pid, safe='')}/{action}",
            data={"new_password": "AnyPwd!2026"} if action == "reset-password" else {},
            follow_redirects=False,
        )
        assert resp.status_code == 403, f"{action} should reject missing csrf"


# ── auth guard ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detail_page_requires_login(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "test.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                f"/proxy/users/{quote('acme::user::someone', safe='')}",
                follow_redirects=False,
            )
            assert resp.status_code in (303, 307)
            assert "/proxy/login" in resp.headers.get("location", "") \
                or "/proxy/register" in resp.headers.get("location", "")
    get_settings.cache_clear()
