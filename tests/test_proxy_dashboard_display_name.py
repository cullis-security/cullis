"""Inline-edit Org display name on the Mastio dashboard overview card.

Covers the trio of endpoints behind the HTMX swap pattern:

  GET  /proxy/settings/org/display-name        - view-mode partial (cancel)
  GET  /proxy/settings/org/display-name/edit   - edit-mode partial (form)
  POST /proxy/settings/org/display-name        - persist + return view partial

The dogfood friction this closes: an admin who lands on the overview with
the deterministic hex Org ID (ADR-006 section 2.2) used to be sent to the
full broker-uplink wizard at /proxy/setup just to rename the org. The
wizard exposed the org_id input even though it is silently ignored in
standalone, so editing it looked like a no-op. The new flow swaps the
title block inline with a single field and persists via set_config.

Auditing is non-negotiable: every successful POST writes an
``org.display_name.update`` row to ``audit_log``. CSRF is enforced on the
mutating endpoint; missing-session paths redirect to /proxy/login.
"""
from __future__ import annotations

import json as _json
import re
import time as _time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


CSRF = "csrf-display-name-test"


def _admin_cookie(csrf_token: str = CSRF) -> tuple[str, str]:
    """Mint a signed admin session cookie carrying a fixed CSRF token."""
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _sign
    payload = _json.dumps(
        {"role": "admin", "csrf_token": csrf_token, "exp": int(_time.time()) + 3600}
    )
    return _COOKIE_NAME, _sign(payload)


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    """Spin a standalone Mastio app against a per-test sqlite DB."""
    db_file = tmp_path / "proxy_display_name.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme-hex-1234")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "test.local")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _seed_org_id(value: str = "acme-hex-1234") -> None:
    from mcp_proxy.db import set_config
    await set_config("org_id", value)


# ── GET view partial ────────────────────────────────────────────────────


async def test_get_view_partial_without_display_name_shows_set_cta(proxy_app):
    """When no display_name is set, the partial includes the amber 'Set a
    friendly display name' CTA + a 'Set name' button next to the hex."""
    _, client = proxy_app
    await _seed_org_id()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.get("/proxy/settings/org/display-name")
    assert resp.status_code == 200, resp.text
    assert 'id="org-title-block"' in resp.text
    assert "acme-hex-1234" in resp.text
    assert "Set a friendly display name" in resp.text
    assert "Set name" in resp.text
    # The edit endpoint is the swap target, not /proxy/setup.
    assert "/proxy/settings/org/display-name/edit" in resp.text
    assert 'href="/proxy/setup"' not in resp.text


async def test_get_view_partial_with_display_name_shows_rename(proxy_app):
    """Once a display_name is set, the partial shows it as the title with
    the hex as a subtitle and a 'Rename' button."""
    _, client = proxy_app
    await _seed_org_id()
    from mcp_proxy.db import set_config
    await set_config("display_name", "Acme Corporation")

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.get("/proxy/settings/org/display-name")
    assert resp.status_code == 200, resp.text
    assert "Acme Corporation" in resp.text
    assert "acme-hex-1234" in resp.text  # hex moved to subtitle
    assert "Rename" in resp.text
    # Amber CTA is gone once the friendly name is set.
    assert "Set a friendly display name" not in resp.text


# ── GET edit partial ────────────────────────────────────────────────────


async def test_get_edit_partial_renders_form(proxy_app):
    """Edit mode swaps the title block with an HTMX form (hx-post target)."""
    _, client = proxy_app
    await _seed_org_id()
    from mcp_proxy.db import set_config
    await set_config("display_name", "Existing Name")

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.get("/proxy/settings/org/display-name/edit")
    assert resp.status_code == 200, resp.text
    assert 'id="org-title-block"' in resp.text
    assert 'name="display_name"' in resp.text
    assert 'value="Existing Name"' in resp.text
    assert 'hx-post="/proxy/settings/org/display-name"' in resp.text
    # CSRF carried via hx-vals on the form element.
    assert CSRF in resp.text


# ── POST happy paths ────────────────────────────────────────────────────


async def test_post_valid_persists_and_returns_view_partial(proxy_app):
    _, client = proxy_app
    await _seed_org_id()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/org/display-name",
        data={"csrf_token": CSRF, "display_name": "  Acme Corporation  "},
    )
    assert resp.status_code == 200, resp.text
    # Trimmed before persist.
    from mcp_proxy.db import get_config
    assert await get_config("display_name") == "Acme Corporation"
    # Returned partial is view-mode with the new title.
    assert 'id="org-title-block"' in resp.text
    assert "Acme Corporation" in resp.text
    assert "Rename" in resp.text
    assert 'name="display_name"' not in resp.text  # no longer the form


async def test_post_empty_clears_display_name(proxy_app):
    _, client = proxy_app
    await _seed_org_id()
    from mcp_proxy.db import set_config, get_config
    await set_config("display_name", "Old Name")

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/org/display-name",
        data={"csrf_token": CSRF, "display_name": ""},
    )
    assert resp.status_code == 200, resp.text
    assert await get_config("display_name") == ""
    # View partial falls back to the hex title + the amber CTA.
    assert "acme-hex-1234" in resp.text
    assert "Set a friendly display name" in resp.text


async def test_post_audit_row_written(proxy_app):
    _, client = proxy_app
    await _seed_org_id()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/org/display-name",
        data={"csrf_token": CSRF, "display_name": "Acme Corporation"},
    )
    assert resp.status_code == 200, resp.text

    from sqlalchemy import text as _text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rows = (
            await conn.execute(
                _text(
                    "SELECT action, status, detail FROM audit_log "
                    "WHERE action = 'org.display_name.update' "
                    "ORDER BY id DESC LIMIT 1"
                )
            )
        ).mappings().all()
    assert rows, "expected an org.display_name.update audit row"
    row = rows[0]
    assert row["status"] == "success"
    assert "Acme Corporation" in row["detail"]


# ── POST failure modes ──────────────────────────────────────────────────


async def test_post_too_long_returns_400(proxy_app):
    _, client = proxy_app
    await _seed_org_id()
    from mcp_proxy.db import get_config

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/org/display-name",
        data={"csrf_token": CSRF, "display_name": "x" * 256},
    )
    assert resp.status_code == 400, resp.text
    # Persisted value is untouched.
    assert (await get_config("display_name")) in (None, "")


async def test_post_missing_csrf_returns_403(proxy_app):
    _, client = proxy_app
    await _seed_org_id()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/org/display-name",
        data={"display_name": "Acme Corporation"},  # no csrf_token
    )
    assert resp.status_code == 403


async def test_post_wrong_csrf_returns_403(proxy_app):
    _, client = proxy_app
    await _seed_org_id()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.post(
        "/proxy/settings/org/display-name",
        data={"csrf_token": "not-the-real-token", "display_name": "x"},
    )
    assert resp.status_code == 403


async def test_post_without_login_redirects(proxy_app):
    _, client = proxy_app
    await _seed_org_id()

    resp = await client.post(
        "/proxy/settings/org/display-name",
        data={"csrf_token": CSRF, "display_name": "x"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/proxy/login" in resp.headers.get("location", "")


async def test_get_edit_without_login_redirects(proxy_app):
    _, client = proxy_app

    resp = await client.get(
        "/proxy/settings/org/display-name/edit",
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "/proxy/login" in resp.headers.get("location", "")


# ── Customer-path smoke: overview card uses the new endpoint, not /setup


async def test_overview_card_hooks_to_inline_edit_not_setup_wizard(proxy_app):
    """Regression for the dogfood friction: clicking the rename affordance
    on the overview must trigger the inline HTMX swap, not bounce to
    /proxy/setup. We assert on the rendered overview HTML.
    """
    _, client = proxy_app
    await _seed_org_id()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.get("/proxy/overview")
    assert resp.status_code == 200, resp.text
    # The title block carries the HTMX hooks for the new endpoint.
    assert 'id="org-title-block"' in resp.text
    assert "/proxy/settings/org/display-name/edit" in resp.text
    # The "Set a friendly display name" amber CTA no longer points at the
    # broker-uplink wizard (#326-adjacent UX bug).
    amber_block = re.search(
        r"Hex above is the deterministic Org ID.*?</p>",
        resp.text, re.DOTALL,
    )
    assert amber_block, "amber CTA paragraph missing from overview"
    assert "/proxy/setup" not in amber_block.group(0)


async def test_full_round_trip_view_edit_save_view(proxy_app):
    """End-to-end: render view -> swap to edit -> POST save -> view shows
    the new name. Mirrors what HTMX does in the browser. Status asserted
    on every step (memory rule layered-test-breakage-keyerror-masking).
    """
    _, client = proxy_app
    await _seed_org_id()

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    r1 = await client.get("/proxy/settings/org/display-name")
    assert r1.status_code == 200, r1.text
    assert "Set name" in r1.text

    r2 = await client.get("/proxy/settings/org/display-name/edit")
    assert r2.status_code == 200, r2.text
    assert 'name="display_name"' in r2.text

    r3 = await client.post(
        "/proxy/settings/org/display-name",
        data={"csrf_token": CSRF, "display_name": "Round Trip Org"},
    )
    assert r3.status_code == 200, r3.text
    assert "Round Trip Org" in r3.text

    r4 = await client.get("/proxy/settings/org/display-name")
    assert r4.status_code == 200, r4.text
    assert "Round Trip Org" in r4.text
    assert "Rename" in r4.text


# ── Drive-by: derived org_id is readonly in the setup wizard ───────────


async def test_setup_wizard_org_id_readonly_when_derived(proxy_app, monkeypatch):
    """ADR-006 section 2.2 - in standalone the org_id is derived from the
    Org CA pubkey and silently ignored if posted back. Mark the input
    readonly so admins do not believe editing it does anything.
    """
    app, client = proxy_app
    await _seed_org_id()

    class _FakeAgentMgr:
        ca_loaded = True

        def derive_org_id_from_ca(self) -> str:
            return "derived-hex-deadbeef"

    monkeypatch.setattr(app.state, "agent_manager", _FakeAgentMgr(), raising=False)

    name, value = _admin_cookie()
    client.cookies.set(name, value)

    resp = await client.get("/proxy/setup")
    assert resp.status_code == 200, resp.text
    # Match the input element for ``org_id`` and confirm it carries the
    # readonly attribute + the ADR-006 hint.
    m = re.search(
        r'<input[^>]*name="org_id"[^>]*>',
        resp.text,
    )
    assert m, "org_id input missing from /proxy/setup"
    assert "readonly" in m.group(0)
    assert "ADR-006" in resp.text
