"""Audit F-B-9 — Mastio (``mcp_proxy``) logout must enforce CSRF.

Before the fix ``mcp_proxy/dashboard/router.py:281-288`` invoked
``verify_csrf`` but discarded the return value, so a cross-site POST
without the form token still logged the victim out. Force-logout was
possible against any admin holding a valid Mastio session.

After the fix the handler raises ``HTTPException(403)`` when
``session.csrf_token`` is set (valid cookie) and ``verify_csrf`` fails.
The bare-no-cookie case stays a friendly 303 so expired-session
browsers do not land on a 403 error page.
"""
from __future__ import annotations

import re

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


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


async def _csrf(client: AsyncClient) -> str:
    """Pull the CSRF token from the dashboard landing page — the form
    on every mutating page carries it in a hidden input."""
    page = await client.get("/proxy/backends")
    assert page.status_code == 200, page.text
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match, "csrf_token not found in /proxy/backends page"
    return match.group(1)


# ── F-B-9 regressions on /proxy/logout ──────────────────────────────

async def test_proxy_logout_without_csrf_rejected(proxy_logged_in: AsyncClient):
    """Before F-B-9 this was a 303 with cookie cleared — force-logout
    by cross-site POST. Now it is a 403."""
    client = proxy_logged_in
    resp = await client.post(
        "/proxy/logout",
        data={},  # no csrf_token
        follow_redirects=False,
    )
    assert resp.status_code == 403
    # Session cookie must NOT be cleared on a rejected logout: the
    # cookie on the response headers should not be a clear-directive.
    # ``httpx`` surfaces clears as set-cookie with empty value +
    # expires in the past; assert nothing like that was sent.
    set_cookie = resp.headers.get("set-cookie", "")
    assert "expires=thu, 01 jan 1970" not in set_cookie.lower()


async def test_proxy_logout_with_valid_csrf_succeeds(proxy_logged_in: AsyncClient):
    """Happy path: valid session + valid CSRF → 303 + cleared session."""
    client = proxy_logged_in
    csrf = await _csrf(client)
    resp = await client.post(
        "/proxy/logout",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/proxy/login" in resp.headers.get("location", "")


async def test_proxy_logout_with_wrong_csrf_rejected(proxy_logged_in: AsyncClient):
    """Valid session + bogus CSRF value still fails closed."""
    client = proxy_logged_in
    resp = await client.post(
        "/proxy/logout",
        data={"csrf_token": "definitely-not-the-real-token"},
        follow_redirects=False,
    )
    assert resp.status_code == 403


async def test_proxy_logout_without_cookie_is_idempotent(tmp_path, monkeypatch):
    """No session cookie present → 303 (idempotent). Browsers whose
    cookie expired mid-session should still land on /proxy/login
    cleanly without a 403 error page."""
    db_file = tmp_path / "proxy_nocookie.sqlite"
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
    try:
        async with app.router.lifespan_context(app):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/proxy/logout",
                    data={},
                    follow_redirects=False,
                )
                assert resp.status_code == 303
                assert "/proxy/login" in resp.headers.get("location", "")
    finally:
        get_settings.cache_clear()
