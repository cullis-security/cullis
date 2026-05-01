"""
M-dash regression: dashboard hardening for the SSO-only hardening
toggle and the session cookie ``Secure`` flag.

1. The ``MCP_PROXY_FORCE_LOCAL_PASSWORD`` env break-glass used to
   silently override the DB-stored "local password disabled" flag.
   No audit trail. Now the override emits a one-shot
   ``auth.local_password.break_glass`` audit row when it's actually
   reversing a DB-disabled state, so a post-incident reviewer can
   see when SSO-only was bypassed.

2. The session cookie ``Secure`` flag was decided from a heuristic
   on ``proxy_public_url.startswith("https")``. If the operator left
   the env var unset (or pointed it at an internal HTTP URL while
   nginx terminates HTTPS), the cookie shipped without ``Secure``
   and could leak over HTTP. Now production forces ``Secure=True``.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "m_dash.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    # Reset the per-process flag so each test starts from a clean
    # "not yet audited" state.
    import mcp_proxy.dashboard.session as _ses
    _ses._force_local_password_audited = False

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()
    _ses._force_local_password_audited = False


# ── Break-glass audit ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_break_glass_audited_when_db_says_disabled(
    proxy_app, monkeypatch,
) -> None:
    monkeypatch.setenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", "1")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import set_config
    await set_config("local_password_enabled", "0")

    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    assert await is_local_password_login_enabled() is True

    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT status, detail FROM audit_log "
                "WHERE action = 'auth.local_password.break_glass'",
            ),
        )).all()
    assert len(rows) == 1, "break-glass override must emit exactly one audit row"
    status, detail = rows[0]
    assert status == "active"
    assert detail is not None and "MCP_PROXY_FORCE_LOCAL_PASSWORD" in detail


@pytest.mark.asyncio
async def test_break_glass_silent_when_db_already_enabled(
    proxy_app, monkeypatch,
) -> None:
    """Env override + DB toggle both 'enabled' = no override happening,
    no audit noise. Triaging post-incident wants to spot REAL break-glass
    events, not see one for every prod boot where the env is set
    redundantly."""
    monkeypatch.setenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", "1")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    # DB unset (default = enabled) — env doesn't change anything.

    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    assert await is_local_password_login_enabled() is True

    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT 1 FROM audit_log "
                "WHERE action = 'auth.local_password.break_glass'",
            ),
        )).all()
    assert rows == [], "redundant env override must not pollute the audit log"


@pytest.mark.asyncio
async def test_break_glass_audit_is_one_shot(proxy_app, monkeypatch) -> None:
    """Multiple consults inside one process emit at most one audit row."""
    monkeypatch.setenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", "1")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.db import set_config
    await set_config("local_password_enabled", "0")

    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    for _ in range(5):
        await is_local_password_login_enabled()

    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT 1 FROM audit_log "
                "WHERE action = 'auth.local_password.break_glass'",
            ),
        )).all()
    assert len(rows) == 1


# ── Cookie Secure flag ───────────────────────────────────────────────


def test_cookie_secure_forced_in_production(monkeypatch) -> None:
    """``Secure`` must be ``True`` in production regardless of
    ``proxy_public_url``. Operators forgetting to set the URL hint
    while nginx terminates HTTPS in front used to ship cookies
    without ``Secure``.
    """
    monkeypatch.setenv("MCP_PROXY_PROXY_PUBLIC_URL", "")
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.dashboard.session import _should_set_secure_cookie
    assert _should_set_secure_cookie() is True
    get_settings.cache_clear()


def test_cookie_secure_follows_url_in_dev(monkeypatch) -> None:
    """In development the URL heuristic still applies — local HTTP
    loopback is the norm and forcing Secure would break dev login."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    from mcp_proxy.config import get_settings

    monkeypatch.setenv("MCP_PROXY_PROXY_PUBLIC_URL", "http://localhost:7777")
    get_settings.cache_clear()
    from mcp_proxy.dashboard.session import _should_set_secure_cookie
    assert _should_set_secure_cookie() is False

    monkeypatch.setenv("MCP_PROXY_PROXY_PUBLIC_URL", "https://mastio.example")
    get_settings.cache_clear()
    assert _should_set_secure_cookie() is True
    get_settings.cache_clear()
