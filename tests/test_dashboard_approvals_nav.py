"""P1.1 companion (open-core) — conditional Approvals nav link + badge.

The actual approval UI lives in the enterprise ``rbac_multi_admin``
plugin. Open-core only owns two surface points:

1. A sidebar link in ``base.html`` shown only when
   ``has_feature('rbac_multi_admin')`` returns True, so community
   deploys don't see a dead link.
2. A ``/proxy/badge/approvals`` endpoint that renders an HTMX-targeted
   pending count badge. Same gate: empty in community mode, empty when
   the enterprise plugin is not installed alongside the proxy, count
   when both are present.

These tests live in open-core so the gate behavior travels with the
view layer that owns it. Counting / API tests for the plugin itself
live in the enterprise repo.
"""
from __future__ import annotations

import json as _json
import time as _time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


def _admin_cookie(csrf_token: str = "test-csrf-token") -> tuple[str, str]:
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _sign

    payload = _json.dumps(
        {"role": "admin", "csrf_token": csrf_token, "exp": int(_time.time()) + 3600},
    )
    return _COOKIE_NAME, _sign(payload)


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
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


# ── nav link visibility (conditional on has_feature) ────────────────


@pytest.mark.asyncio
async def test_nav_hides_approvals_when_feature_off(proxy_app, monkeypatch):
    """Community mode: ``has_feature`` returns False → no Approvals link."""
    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: False)

    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.get("/proxy/agents")
    assert resp.status_code == 200
    body = resp.text
    assert "/proxy/admin/approvals" not in body
    # Sanity: the sibling Enrollments link is always present.
    assert "/proxy/enrollments" in body


@pytest.mark.asyncio
async def test_nav_shows_approvals_when_feature_on(proxy_app, monkeypatch):
    """Enterprise mode: feature on → link present with HTMX badge."""
    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: True)

    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.get("/proxy/agents")
    assert resp.status_code == 200
    body = resp.text
    assert 'href="/proxy/admin/approvals"' in body
    # The link carries an HTMX-poll badge target.
    assert 'hx-get="/proxy/badge/approvals"' in body
    # Display text is plain so it survives screen readers.
    assert ">Approvals<" in body or "Approvals" in body


# ── /proxy/badge/approvals endpoint ─────────────────────────────────


@pytest.mark.asyncio
async def test_badge_approvals_empty_when_unauth(proxy_app):
    _, client = proxy_app
    resp = await client.get("/proxy/badge/approvals")
    assert resp.status_code == 200
    assert resp.text == ""


@pytest.mark.asyncio
async def test_badge_approvals_empty_when_feature_off(proxy_app, monkeypatch):
    """Logged-in admin in community mode → no badge (link is also hidden)."""
    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: False)

    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.get("/proxy/badge/approvals")
    assert resp.status_code == 200
    assert resp.text == ""


@pytest.mark.asyncio
async def test_badge_approvals_empty_when_plugin_unavailable(proxy_app, monkeypatch):
    """Feature flag is on but the enterprise package is not installed on
    this deploy — the late import inside the handler must degrade
    silently to an empty badge so the dashboard nav doesn't break.

    The open-core repo runs tests without the enterprise package on
    PYTHONPATH, so the ImportError path is exercised by simply turning
    the feature flag on and hitting the endpoint — no module-system
    monkey-business required.
    """
    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: True)

    import sys
    assert "cullis_enterprise" not in sys.modules, (
        "test precondition: enterprise package must not be on the open-core "
        "test path; if you installed it locally for cross-repo work, "
        "uninstall it before running this test"
    )

    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.get("/proxy/badge/approvals")
    assert resp.status_code == 200
    assert resp.text == ""


# ── has_feature global is callable from every dashboard sub-router ─


def test_has_feature_registered_on_every_dashboard_templates_instance():
    """Each dashboard sub-router builds its own ``Jinja2Templates``
    instance; ``base.html`` calls ``has_feature(...)`` and would 500
    against any instance that did not register the global.

    The fix is the shared ``build_templates`` factory in
    ``_template_env``. This guard catches regressions where someone
    constructs a fresh ``Jinja2Templates(directory=...)`` again instead
    of going through the factory.
    """
    from mcp_proxy.dashboard import (
        ai_providers,
        downloads,
        link_broker,
        mcp_resources,
        policies_local,
        router as _router,
        tool_rules,
        updates_router,
    )

    instances = {
        "router.py": _router.templates,
        "ai_providers.py": ai_providers.templates,
        "downloads.py": downloads.templates,
        "link_broker.py": link_broker.templates,
        "mcp_resources.py": mcp_resources.templates,
        "policies_local.py": policies_local.templates,
        "tool_rules.py": tool_rules.templates,
        "updates_router.py": updates_router._templates,
    }

    missing = [
        name for name, t in instances.items()
        if "has_feature" not in t.env.globals
        or not callable(t.env.globals["has_feature"])
    ]
    assert not missing, (
        "Jinja2Templates instances without has_feature global "
        "(use mcp_proxy.dashboard._template_env.build_templates): "
        + ", ".join(missing)
    )


@pytest.mark.asyncio
async def test_ai_providers_page_renders_with_feature_on(proxy_app, monkeypatch):
    """Smoke: a sub-router page extending base.html must render cleanly
    when has_feature is on. Catches the original GET /proxy/ai-providers
    500 regression where ai_providers.py built its own env without the
    global."""
    import mcp_proxy.license
    monkeypatch.setattr(mcp_proxy.license, "has_feature", lambda _f: True)

    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.get("/proxy/ai-providers")
    assert resp.status_code == 200, resp.text
    # Confirms the conditional rendered the link inside this page too,
    # not only on /proxy/agents.
    assert 'href="/proxy/admin/approvals"' in resp.text
