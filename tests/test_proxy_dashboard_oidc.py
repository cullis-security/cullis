"""Tests for the MCP Proxy dashboard: OIDC flow, overview, settings, and
the federated-agents accordion partial.

The OIDC tests stub out the HTTP calls to the IdP so we never hit the
network: ``build_authorization_url`` only needs the discovery doc, and
``exchange_code_for_identity`` is mocked at the module level for the
callback test.
"""
from __future__ import annotations

import json as _json
import time as _time
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


# ── Helpers ──────────────────────────────────────────────────────────


def _admin_cookie(csrf_token: str = "csrf-oidc-test") -> tuple[str, str]:
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _sign
    payload = _json.dumps(
        {"role": "admin", "csrf_token": csrf_token, "exp": int(_time.time()) + 3600}
    )
    return _COOKIE_NAME, _sign(payload)


def _oidc_state_cookie(state: str, nonce: str, code_verifier: str) -> tuple[str, str]:
    from mcp_proxy.dashboard.session import _OIDC_STATE_COOKIE, _sign
    payload = _json.dumps({
        "state": state, "nonce": nonce, "code_verifier": code_verifier,
        "exp": int(_time.time()) + 600,
    })
    return _OIDC_STATE_COOKIE, _sign(payload)


# ── Fixture: proxy app on an isolated SQLite DB ─────────────────────


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy_oidc.sqlite"
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


# ─────────────────────────────────────────────────────────────────────
# Settings page
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_settings_requires_login(proxy_app):
    _, client = proxy_app
    resp = await client.get("/proxy/settings", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/proxy/login"


@pytest.mark.asyncio
async def test_settings_renders_and_masks_secret(proxy_app):
    app, client = proxy_app
    from mcp_proxy.db import set_config
    await set_config("oidc_issuer_url", "https://idp.example.com")
    await set_config("oidc_client_id", "cullis-proxy")
    await set_config("oidc_client_secret", "super-secret-value")

    name, value = _admin_cookie()
    client.cookies.set(name, value)
    resp = await client.get("/proxy/settings")
    assert resp.status_code == 200
    body = resp.text
    assert "https://idp.example.com" in body
    assert "cullis-proxy" in body
    # The stored secret MUST NOT be rendered.
    assert "super-secret-value" not in body
    # But the UI should indicate one is set.
    assert "value stored" in body


@pytest.mark.asyncio
async def test_settings_post_persists_but_keeps_existing_secret(proxy_app):
    app, client = proxy_app
    from mcp_proxy.db import get_config, set_config
    await set_config("oidc_client_secret", "OLD-SECRET")

    csrf = "settings-csrf"
    name, value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(name, value)

    resp = await client.post("/proxy/settings", data={
        "csrf_token": csrf,
        "oidc_issuer_url": "https://new-idp.example.com",
        "oidc_client_id": "new-client",
        "oidc_client_secret": "",  # empty => keep existing
    })
    assert resp.status_code == 200

    assert await get_config("oidc_issuer_url") == "https://new-idp.example.com"
    assert await get_config("oidc_client_id") == "new-client"
    assert await get_config("oidc_client_secret") == "OLD-SECRET"


@pytest.mark.asyncio
async def test_settings_post_requires_csrf(proxy_app):
    _, client = proxy_app
    name, value = _admin_cookie()  # csrf is "csrf-oidc-test"
    client.cookies.set(name, value)
    resp = await client.post("/proxy/settings", data={
        "csrf_token": "wrong",
        "oidc_issuer_url": "https://e.test",
        "oidc_client_id": "c",
    })
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_settings_rejects_invalid_issuer(proxy_app):
    _, client = proxy_app
    csrf = "csrf-bad-issuer"
    name, value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(name, value)
    resp = await client.post("/proxy/settings", data={
        "csrf_token": csrf,
        "oidc_issuer_url": "not-a-url",
        "oidc_client_id": "c",
    })
    assert resp.status_code == 400


# ─────────────────────────────────────────────────────────────────────
# OIDC start
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oidc_start_errors_when_not_configured(proxy_app):
    _, client = proxy_app
    resp = await client.get("/proxy/oidc/start", follow_redirects=False)
    assert resp.status_code == 400
    assert "not configured" in resp.text.lower()


@pytest.mark.asyncio
async def test_oidc_start_redirects_to_idp_with_pkce(proxy_app):
    _, client = proxy_app
    from mcp_proxy.db import set_config
    await set_config("oidc_issuer_url", "https://idp.example.com")
    await set_config("oidc_client_id", "cullis-proxy")

    with patch(
        "mcp_proxy.dashboard.oidc._fetch_discovery",
        new=AsyncMock(return_value={
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/jwks",
        }),
    ):
        resp = await client.get("/proxy/oidc/start", follow_redirects=False)

    assert resp.status_code == 303
    loc = resp.headers["location"]
    assert loc.startswith("https://idp.example.com/authorize")
    assert "code_challenge=" in loc
    assert "code_challenge_method=S256" in loc
    assert "scope=openid" in loc
    assert "client_id=cullis-proxy" in loc

    # State cookie must be set so the callback can verify.
    from mcp_proxy.dashboard.session import _OIDC_STATE_COOKIE
    assert _OIDC_STATE_COOKIE in resp.cookies


# ─────────────────────────────────────────────────────────────────────
# OIDC callback
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oidc_callback_missing_state_returns_error(proxy_app):
    _, client = proxy_app
    from mcp_proxy.db import set_config
    await set_config("oidc_issuer_url", "https://idp.example.com")
    await set_config("oidc_client_id", "cullis-proxy")

    resp = await client.get(
        "/proxy/oidc/callback?code=abc&state=xyz",
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "expired" in resp.text.lower() or "invalid" in resp.text.lower()


@pytest.mark.asyncio
async def test_oidc_callback_state_mismatch_returns_403(proxy_app):
    _, client = proxy_app
    from mcp_proxy.db import set_config
    await set_config("oidc_issuer_url", "https://idp.example.com")
    await set_config("oidc_client_id", "cullis-proxy")

    name, value = _oidc_state_cookie("the-real-state", "n", "v")
    client.cookies.set(name, value)

    resp = await client.get(
        "/proxy/oidc/callback?code=abc&state=evil-state",
        follow_redirects=False,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_oidc_callback_success_sets_session(proxy_app):
    _, client = proxy_app
    from mcp_proxy.db import set_config
    await set_config("oidc_issuer_url", "https://idp.example.com")
    await set_config("oidc_client_id", "cullis-proxy")
    await set_config("org_id", "acme")  # so we redirect to /overview

    flow_state = ("fixed-state-hex", "fixed-nonce-hex", "fixed-verifier")
    name, value = _oidc_state_cookie(*flow_state)
    client.cookies.set(name, value)

    from mcp_proxy.dashboard.oidc import OidcIdentity
    fake_identity = OidcIdentity(
        sub="user-42", email="admin@acme.com", name="Acme Admin",
        issuer="https://idp.example.com", claims={},
    )

    with patch(
        "mcp_proxy.dashboard.oidc.exchange_code_for_identity",
        new=AsyncMock(return_value=fake_identity),
    ):
        resp = await client.get(
            f"/proxy/oidc/callback?code=auth-code&state={flow_state[0]}",
            follow_redirects=False,
        )

    assert resp.status_code == 303
    # Session cookie set
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _OIDC_STATE_COOKIE
    assert _COOKIE_NAME in resp.cookies
    # OIDC state cookie cleared
    # (it appears in Set-Cookie with empty value + Max-Age=0)
    set_cookie = resp.headers.get("set-cookie", "") + "".join(
        resp.headers.get_list("set-cookie")
        if hasattr(resp.headers, "get_list") else [],
    )
    assert _OIDC_STATE_COOKIE in set_cookie


# ─────────────────────────────────────────────────────────────────────
# Overview
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_overview_requires_login(proxy_app):
    _, client = proxy_app
    resp = await client.get("/proxy/overview", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/proxy/login"


@pytest.mark.asyncio
async def test_overview_renders_with_org(proxy_app):
    _, client = proxy_app
    from mcp_proxy.db import set_config
    await set_config("org_id", "acme")
    await set_config("display_name", "Acme Corp")
    await set_config("broker_url", "https://broker.example.com")

    name, value = _admin_cookie()
    client.cookies.set(name, value)
    resp = await client.get("/proxy/overview")
    assert resp.status_code == 200
    body = resp.text
    assert "Acme Corp" in body
    assert "https://broker.example.com" in body


# ─────────────────────────────────────────────────────────────────────
# Login page reflects OIDC availability
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_login_page_shows_sso_button_when_configured(proxy_app):
    _, client = proxy_app

    # Admin password must exist or /proxy/login redirects to /proxy/register.
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password("test-password-1234")

    from mcp_proxy.db import set_config
    await set_config("oidc_issuer_url", "https://idp.example.com")
    await set_config("oidc_client_id", "cullis-proxy")
    await set_config("display_name", "Acme Corp")

    resp = await client.get("/proxy/login")
    assert resp.status_code == 200
    body = resp.text
    assert "Sign in with SSO" in body
    assert "/proxy/oidc/start" in body
    assert "Acme Corp" in body


@pytest.mark.asyncio
async def test_login_page_hides_sso_button_when_unconfigured(proxy_app):
    _, client = proxy_app
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password("test-password-1234")

    resp = await client.get("/proxy/login")
    assert resp.status_code == 200
    assert "Sign in with SSO" not in resp.text


# ─────────────────────────────────────────────────────────────────────
# Federated agents accordion + partial
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_federated_partial_requires_login(proxy_app):
    _, client = proxy_app
    resp = await client.get("/proxy/federated/peer-org")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_federated_partial_lists_cached_agents(proxy_app):
    _, client = proxy_app
    # Seed the federation cache directly (as the subscriber would)
    from sqlalchemy import text

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        for i, cap in enumerate(["cap.a", "cap.b"]):
            await conn.execute(
                text(
                    "INSERT INTO cached_federated_agents "
                    "(agent_id, org_id, display_name, capabilities, revoked, updated_at) "
                    "VALUES (:aid, 'peer', :name, :caps, 0, '2026-04-14T00:00:00Z')"
                ),
                {
                    "aid": f"peer::agent-{i}",
                    "name": f"Peer Agent {i}",
                    "caps": _json.dumps([cap]),
                },
            )

    name, value = _admin_cookie()
    client.cookies.set(name, value)
    resp = await client.get("/proxy/federated/peer")
    assert resp.status_code == 200
    body = resp.text
    assert "peer::agent-0" in body
    assert "peer::agent-1" in body


# NOTE: the former ``test_agents_page_shows_federated_section`` has been
# retired. That test exercised the Peer Agents accordion that used to
# live on ``/proxy/agents``; the accordion has since been removed —
# peer-org discovery moved to ``/proxy/network``, and ``/proxy/agents``
# is now scoped to "my agents" only (split into Federated / Local by
# ``reach``). The ``/proxy/federated/{org}`` partial endpoint itself
# is kept (see ``test_federated_partial_*`` above), but it is no
# longer rendered from the Agents page.
