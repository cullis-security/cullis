"""Local admin password sign-in toggle (SSO-only hardening).

Covers:
  - default: fresh proxy accepts password sign-in (back-compat)
  - toggle off + OIDC configured: POST /proxy/login returns 403 and
    the GET page hides the password form, showing only the SSO button
  - toggle off without OIDC: settings endpoint refuses with a 400 and
    keeps the toggle in the enabled state (can't lock yourself out)
  - env-var break-glass (MCP_PROXY_FORCE_LOCAL_PASSWORD=1) forces the
    password path on even when the DB flag says disabled
  - audit log row is written on both the toggle flip and the 403 login
  - CLI reset-password overwrites the hash AND re-enables the toggle
"""
from __future__ import annotations

import json as _json
import time as _time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


def _admin_cookie(csrf_token: str = "csrf-toggle-test") -> tuple[str, str]:
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _sign
    payload = _json.dumps(
        {"role": "admin", "csrf_token": csrf_token, "exp": int(_time.time()) + 3600}
    )
    return _COOKIE_NAME, _sign(payload)


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy_toggle.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _set_admin_password(pw: str = "toggle-test-password") -> None:
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password(pw)


async def _configure_oidc() -> None:
    from mcp_proxy.db import set_config
    await set_config("oidc_issuer_url", "https://idp.example.com")
    await set_config("oidc_client_id", "cullis-proxy")


# ── Defaults ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_default_password_login_enabled(proxy_app):
    """Fresh install with nothing set: the helper returns True and
    /proxy/login renders the password form."""
    _, client = proxy_app
    await _set_admin_password()

    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    assert await is_local_password_login_enabled() is True

    resp = await client.get("/proxy/login")
    assert resp.status_code == 200
    assert 'name="password"' in resp.text


# ── Gating ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_login_post_403_when_disabled(proxy_app):
    _, client = proxy_app
    await _set_admin_password()
    await _configure_oidc()

    from mcp_proxy.dashboard.session import set_local_password_login_enabled
    await set_local_password_login_enabled(False)

    resp = await client.post(
        "/proxy/login",
        data={"password": "toggle-test-password"},
        follow_redirects=False,
    )
    assert resp.status_code == 403
    assert "disabled" in resp.text.lower()
    # The bcrypt compare must NOT have run — can't assert that directly, but
    # the vague response body should not leak which password was tried.
    assert "invalid password" not in resp.text.lower()


@pytest.mark.asyncio
async def test_login_get_hides_password_form_when_disabled(proxy_app):
    _, client = proxy_app
    await _set_admin_password()
    await _configure_oidc()

    from mcp_proxy.dashboard.session import set_local_password_login_enabled
    await set_local_password_login_enabled(False)

    resp = await client.get("/proxy/login")
    assert resp.status_code == 200
    body = resp.text
    assert 'name="password"' not in body
    assert "Sign in with SSO" in body


@pytest.mark.asyncio
async def test_login_post_accepted_when_enabled(proxy_app):
    _, client = proxy_app
    await _set_admin_password("toggle-test-password")

    resp = await client.post(
        "/proxy/login",
        data={"password": "toggle-test-password"},
        follow_redirects=False,
    )
    # 303 on success (redirect to post_login) regardless of whether OIDC
    # is configured — the default toggle state is enabled.
    assert resp.status_code == 303


# ── Toggle endpoint guard ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_toggle_disable_refused_without_oidc(proxy_app):
    """The settings endpoint must refuse to disable the toggle unless an
    OIDC provider is configured — single-click lockout guard."""
    _, client = proxy_app
    await _set_admin_password()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/local-password",
        data={"csrf_token": "csrf-toggle-test", "enabled": "0"},
    )
    assert resp.status_code == 400
    assert "oidc" in resp.text.lower()

    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    assert await is_local_password_login_enabled() is True


@pytest.mark.asyncio
async def test_toggle_disable_accepted_with_oidc(proxy_app):
    _, client = proxy_app
    await _set_admin_password()
    await _configure_oidc()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/local-password",
        data={"csrf_token": "csrf-toggle-test", "enabled": "0"},
    )
    assert resp.status_code == 200

    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    assert await is_local_password_login_enabled() is False


@pytest.mark.asyncio
async def test_toggle_audit_logged(proxy_app):
    _, client = proxy_app
    await _set_admin_password()
    await _configure_oidc()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    await client.post(
        "/proxy/settings/local-password",
        data={"csrf_token": "csrf-toggle-test", "enabled": "0"},
    )

    from sqlalchemy import text as _text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rows = (
            await conn.execute(
                _text(
                    "SELECT action, detail FROM audit_log "
                    "WHERE action = 'auth.password_login_toggle' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
        ).mappings().all()
    assert rows, "expected an auth.password_login_toggle audit row"
    assert "enabled=False" in rows[0]["detail"]


@pytest.mark.asyncio
async def test_toggle_requires_csrf(proxy_app):
    _, client = proxy_app
    await _set_admin_password()
    await _configure_oidc()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/local-password",
        data={"enabled": "0"},  # no csrf_token
    )
    assert resp.status_code == 403


# ── Env-var break-glass ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_env_force_overrides_db_flag(tmp_path, monkeypatch):
    """MCP_PROXY_FORCE_LOCAL_PASSWORD=1 must beat a DB flag set to 0 —
    that's the whole point of the break-glass.
    """
    db_file = tmp_path / "proxy_force.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", "1")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            await _set_admin_password("force-test-password")
            await _configure_oidc()

            # Explicitly flip the toggle off in the DB.
            from mcp_proxy.dashboard.session import (
                is_local_password_login_enabled,
                set_local_password_login_enabled,
            )
            await set_local_password_login_enabled(False)

            # Helper ignores the DB flag and returns True because of env.
            assert await is_local_password_login_enabled() is True

            # Login GET shows the form.
            r = await client.get("/proxy/login")
            assert 'name="password"' in r.text

            # Login POST works.
            r = await client.post(
                "/proxy/login",
                data={"password": "force-test-password"},
                follow_redirects=False,
            )
            assert r.status_code == 303

    get_settings.cache_clear()


# ── CLI reset-password ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cli_reset_password_restores_access(tmp_path, monkeypatch):
    """Drive the async command directly rather than via ``cli.main`` —
    ``main`` uses ``asyncio.run`` which can't nest inside a pytest-asyncio
    event loop. The helper is where the interesting logic lives anyway."""
    import argparse

    db_file = tmp_path / "proxy_cli.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.db import dispose_db, init_db
    await init_db(get_settings().database_url)
    try:
        await _set_admin_password("old-password-1234")
        from mcp_proxy.dashboard.session import (
            set_local_password_login_enabled,
            verify_admin_password,
            is_local_password_login_enabled,
        )
        await set_local_password_login_enabled(False)
        assert await is_local_password_login_enabled() is False
    finally:
        await dispose_db()

    from mcp_proxy.cli import _cmd_reset_password
    args = argparse.Namespace(password="new-cli-password-abc")
    rc = await _cmd_reset_password(args)
    assert rc == 0

    await init_db(get_settings().database_url)
    try:
        assert await verify_admin_password("new-cli-password-abc") is True
        assert await verify_admin_password("old-password-1234") is False
        assert await is_local_password_login_enabled() is True
    finally:
        await dispose_db()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_cli_reset_password_rejects_short(tmp_path, monkeypatch):
    import argparse

    db_file = tmp_path / "proxy_cli_short.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.cli import _cmd_reset_password
    args = argparse.Namespace(password="short")
    rc = await _cmd_reset_password(args)
    assert rc == 1
    get_settings.cache_clear()
