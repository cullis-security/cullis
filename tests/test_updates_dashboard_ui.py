"""Rendering tests for the federation-update dashboard UI.

Exercises:
- ``GET /proxy/updates`` HTML page (login-gated, context-aware action
  buttons, critical banner, empty state).
- ``GET /proxy/badge/updates`` HTMX fragment (empty / amber / red).
- Nav entry in ``base.html``.

Assertions look for specific stable strings in the rendered HTML —
regex / in-string checks rather than DOM parsing — so a minor style
tweak doesn't break the test but a functional regression does.
"""
from __future__ import annotations

import re
import sys
import types

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from mcp_proxy.updates import registry as registry_mod
from mcp_proxy.updates.base import Migration


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_logged_in(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "test.local")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    monkeypatch.setenv("CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS", "0")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test",
        ) as client:
            from mcp_proxy.dashboard.session import set_admin_password
            await set_admin_password("test-password-1234")
            resp = await client.post(
                "/proxy/login",
                data={"password": "test-password-1234"},
                follow_redirects=False,
            )
            assert resp.status_code in (302, 303), resp.text
            yield app, client
    get_settings.cache_clear()


@pytest.fixture
def fake_pkg(monkeypatch):
    pkg_name = (
        "mcp_proxy.updates.migrations"
        f"._ui_testfixtures_{id(monkeypatch)}"
    )
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = []  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, pkg_name, pkg)
    monkeypatch.setattr(registry_mod, "_migrations_pkg", pkg)
    return pkg


def _make_migration(
    fake_pkg_mod: types.ModuleType,
    name: str,
    migration_id: str,
    *,
    criticality: str = "info",
    affects: tuple[str, ...] = (),
    description: str = "test fixture migration",
) -> type[Migration]:
    async def _check(self) -> bool:
        return True

    async def _up(self) -> None:
        return None

    async def _rollback(self) -> None:
        return None

    cls = type(
        name,
        (Migration,),
        {
            "migration_id": migration_id,
            "migration_type": "cert-schema",
            "criticality": criticality,
            "description": description,
            "preserves_enrollments": True,
            "affects_enrollments": affects,
            "check": _check,
            "up": _up,
            "rollback": _rollback,
        },
    )
    cls.__module__ = fake_pkg_mod.__name__
    setattr(fake_pkg_mod, name, cls)
    return cls


# ── Page renders ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_page_requires_login_redirects(tmp_path, monkeypatch):
    """Unauthenticated GET /proxy/updates → 303 to /proxy/login."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}",
    )
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport, base_url="http://test",
        ) as client:
            resp = await client.get("/proxy/updates", follow_redirects=False)
            assert resp.status_code in (302, 303)
            assert "/proxy/login" in resp.headers.get("location", "")
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_page_renders_empty_state_when_no_migrations(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    resp = await client.get("/proxy/updates")
    assert resp.status_code == 200
    html = resp.text
    assert "No migrations registered" in html
    # Critical banner must NOT render on empty registry.
    assert "Critical updates pending" not in html


@pytest.mark.asyncio
async def test_page_renders_pending_migration_with_apply_button(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(
        fake_pkg, "MigPending", "2099-ui-01-pending",
        criticality="info", affects=("connector",),
    )
    from mcp_proxy.db import insert_pending_update
    await insert_pending_update(
        migration_id="2099-ui-01-pending",
        detected_at="2099-01-01T00:00:00+00:00",
    )

    resp = await client.get("/proxy/updates")
    html = resp.text
    assert resp.status_code == 200
    assert "2099-ui-01-pending" in html
    # Apply button wired with the id.
    assert 'data-update-action="apply"' in html
    assert 'data-migration-id="2099-ui-01-pending"' in html
    # Pending status badge rendered.
    assert "Pending" in html


@pytest.mark.asyncio
async def test_page_renders_applied_migration_with_rollback_button(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "MigApplied", "2099-ui-02-applied")
    from mcp_proxy.db import (
        insert_pending_update, update_pending_update_status,
    )
    await insert_pending_update(
        migration_id="2099-ui-02-applied",
        detected_at="2099-02-01T00:00:00+00:00",
    )
    await update_pending_update_status(
        migration_id="2099-ui-02-applied",
        status="applied",
        applied_at="2099-02-01T01:00:00+00:00",
    )

    resp = await client.get("/proxy/updates")
    html = resp.text
    assert "2099-ui-02-applied" in html
    # Rollback button, NOT apply.
    assert (
        'data-update-action="rollback"' in html
        and 'data-migration-id="2099-ui-02-applied"' in html
    )
    # Applied badge.
    assert "Applied" in html


@pytest.mark.asyncio
async def test_page_renders_failed_migration_with_retry_and_rollback(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "MigFailed", "2099-ui-03-failed")
    from mcp_proxy.db import (
        insert_pending_update, update_pending_update_status,
    )
    await insert_pending_update(
        migration_id="2099-ui-03-failed",
        detected_at="2099-03-01T00:00:00+00:00",
    )
    await update_pending_update_status(
        migration_id="2099-ui-03-failed",
        status="failed",
        error="synthetic: disk full",
    )

    resp = await client.get("/proxy/updates")
    html = resp.text
    # Both action buttons rendered for failed status.
    assert "Retry apply" in html
    assert "Rollback" in html
    # Error expander surfaces the message.
    assert "synthetic: disk full" in html


@pytest.mark.asyncio
async def test_page_renders_critical_banner_when_critical_pending(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(
        fake_pkg, "MigCrit", "2099-ui-04-crit",
        criticality="critical", affects=("connector",),
    )
    from mcp_proxy.db import insert_pending_update
    await insert_pending_update(
        migration_id="2099-ui-04-crit",
        detected_at="2099-04-01T00:00:00+00:00",
    )

    resp = await client.get("/proxy/updates")
    html = resp.text
    assert "Critical updates pending" in html
    # Anchor into the first critical row is wired.
    assert 'id="first-critical"' in html


@pytest.mark.asyncio
async def test_page_no_banner_when_only_non_critical_pending(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(
        fake_pkg, "MigWarn", "2099-ui-05-warn",
        criticality="warning", affects=("connector",),
    )
    from mcp_proxy.db import insert_pending_update
    await insert_pending_update(
        migration_id="2099-ui-05-warn",
        detected_at="2099-05-01T00:00:00+00:00",
    )

    resp = await client.get("/proxy/updates")
    html = resp.text
    assert "Critical updates pending" not in html
    assert "2099-ui-05-warn" in html


@pytest.mark.asyncio
async def test_page_csrf_token_embedded_in_forms(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "MigCsrf", "2099-ui-06-csrf")
    from mcp_proxy.db import insert_pending_update
    await insert_pending_update(
        migration_id="2099-ui-06-csrf",
        detected_at="2099-06-01T00:00:00+00:00",
    )

    resp = await client.get("/proxy/updates")
    html = resp.text
    # At least two csrf_token hidden fields — one per modal form.
    # base.html may embed additional copies (logout etc.); what matters
    # is that both modals on this page inherit the same session token.
    tokens = re.findall(r'name="csrf_token" value="([^"]+)"', html)
    assert len(tokens) >= 2
    assert tokens[0]  # non-empty
    assert all(t == tokens[0] for t in tokens)


@pytest.mark.asyncio
async def test_nav_link_present_and_active(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    resp = await client.get("/proxy/updates")
    html = resp.text
    # Nav anchor for Updates page.
    assert 'href="/proxy/updates"' in html
    # Active marker on the nav entry when we're on this page.
    active = re.search(
        r'href="/proxy/updates"[^>]*class="[^"]*nav-active',
        html,
    )
    assert active, "Updates nav entry is not marked active"


# ── Badge endpoint ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_badge_empty_when_no_pending(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    resp = await client.get("/proxy/badge/updates")
    assert resp.status_code == 200
    assert resp.text == ""


@pytest.mark.asyncio
async def test_badge_amber_when_only_non_critical_pending(
    proxy_logged_in, fake_pkg,
):
    _, client = proxy_logged_in
    _make_migration(
        fake_pkg, "MigBadgeWarn", "2099-badge-01-warn",
        criticality="warning",
    )
    from mcp_proxy.db import insert_pending_update
    await insert_pending_update(
        migration_id="2099-badge-01-warn",
        detected_at="2099-07-01T00:00:00+00:00",
    )

    resp = await client.get("/proxy/badge/updates")
    assert resp.status_code == 200
    # Amber tint classes present.
    assert "amber" in resp.text
    # Count of 1.
    assert ">1<" in resp.text


@pytest.mark.asyncio
async def test_badge_red_when_critical_pending(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    _make_migration(
        fake_pkg, "MigBadgeCrit", "2099-badge-02-crit",
        criticality="critical",
    )
    _make_migration(
        fake_pkg, "MigBadgeInfo", "2099-badge-02-info",
        criticality="info",
    )
    from mcp_proxy.db import insert_pending_update
    await insert_pending_update(
        migration_id="2099-badge-02-crit",
        detected_at="2099-08-01T00:00:00+00:00",
    )
    await insert_pending_update(
        migration_id="2099-badge-02-info",
        detected_at="2099-08-02T00:00:00+00:00",
    )

    resp = await client.get("/proxy/badge/updates")
    assert resp.status_code == 200
    # Red tint because at least one critical is pending.
    assert "red" in resp.text
    # Total count is 2.
    assert ">2<" in resp.text


@pytest.mark.asyncio
async def test_badge_ignores_non_pending_rows(proxy_logged_in, fake_pkg):
    _, client = proxy_logged_in
    _make_migration(fake_pkg, "MigBadgeDone", "2099-badge-03-done")
    from mcp_proxy.db import (
        insert_pending_update, update_pending_update_status,
    )
    await insert_pending_update(
        migration_id="2099-badge-03-done",
        detected_at="2099-09-01T00:00:00+00:00",
    )
    await update_pending_update_status(
        migration_id="2099-badge-03-done",
        status="applied",
        applied_at="2099-09-01T01:00:00+00:00",
    )
    resp = await client.get("/proxy/badge/updates")
    assert resp.status_code == 200
    assert resp.text == ""
