"""Dashboard mutations for user API tokens (ADR-027 Phase 1, PR 4).

Pins on the cookie-auth + CSRF flow that mirrors users_reset_password:

  * Anonymous POST is bounced to /proxy/login
  * Form mint redirects 303 with ``?new_token=`` + ``?new_token_label=``
    so the template can render the one-time banner
  * Empty label rejected with ``?token_error=`` redirect
  * Revoke happy path → 303 with ``?ok=token+revoked``
  * Revoke unknown id → 303 with ``?token_error=``
  * Revoke a token belonging to another user → 303 with ``?token_error=``
    (prevents cross-user revoke from a stale form)
  * After mint, GET /proxy/users/{pid} shows the token in the table
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit, parse_qs

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


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


async def _csrf(client: AsyncClient, principal_id: str) -> str:
    """Pull the CSRF token from a user_detail render so we can POST."""
    from urllib.parse import quote
    page = await client.get(
        f"/proxy/users/{quote(principal_id, safe='')}",
        follow_redirects=False,
    )
    # If the user row does not exist locally yet, user_detail redirects
    # to /proxy/users with an error. Seed a row directly in the DB so
    # we have something to render against.
    if page.status_code == 303:
        # Seed local_user_principals row, then re-fetch.
        from datetime import datetime, timezone
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            await conn.execute(
                text(
                    "INSERT INTO local_user_principals "
                    "(principal_id, user_name, display_name, reach, "
                    "surface, cert_thumbprint, created_at, last_active_at) "
                    "VALUES (:pid, :name, :dn, 'intra', 'frontdesk', "
                    "NULL, :ts, NULL)"
                ),
                {
                    "pid": principal_id,
                    "name": principal_id.split("::")[-1],
                    "dn": principal_id.split("::")[-1],
                    "ts": datetime.now(timezone.utc).isoformat(),
                },
            )
        page = await client.get(
            f"/proxy/users/{quote(principal_id, safe='')}",
            follow_redirects=False,
        )
    assert page.status_code == 200, page.text[:300]
    m = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert m, "csrf_token not found"
    return m.group(1)


# ── helpers for redirect parsing ─────────────────────────────────────


def _redirect_query(resp) -> dict[str, list[str]]:
    loc = resp.headers.get("location", "")
    qs = urlsplit(loc).query
    return parse_qs(qs)


# ── auth ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_anonymous_post_redirects_to_login(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            r = await cli.post(
                "/proxy/users/acme::user::alice/api-tokens/create",
                data={"label": "x"},
                follow_redirects=False,
            )
    assert r.status_code in (303, 401, 403), r.text
    if r.status_code == 303:
        assert "login" in r.headers.get("location", ""), r.headers


# ── mint ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mint_redirects_with_cleartext_in_query(proxy_logged_in):
    pid = "acme::user::alice"
    csrf = await _csrf(proxy_logged_in, pid)
    from urllib.parse import quote
    r = await proxy_logged_in.post(
        f"/proxy/users/{quote(pid, safe='')}/api-tokens/create",
        data={"csrf_token": csrf, "label": "Cursor laptop"},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    qs = _redirect_query(r)
    assert "new_token" in qs, qs
    token = unquote(qs["new_token"][0])
    assert token.startswith("culk_")
    assert len(token) == 57
    assert qs["new_token_label"][0] == "Cursor+laptop" or unquote(qs["new_token_label"][0]) == "Cursor laptop"


@pytest.mark.asyncio
async def test_mint_empty_label_redirects_with_error(proxy_logged_in):
    pid = "acme::user::bob"
    csrf = await _csrf(proxy_logged_in, pid)
    from urllib.parse import quote
    r = await proxy_logged_in.post(
        f"/proxy/users/{quote(pid, safe='')}/api-tokens/create",
        data={"csrf_token": csrf, "label": "   "},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    qs = _redirect_query(r)
    assert "token_error" in qs, qs


@pytest.mark.asyncio
async def test_mint_persists_scope_and_expires(proxy_logged_in):
    pid = "acme::user::carol"
    csrf = await _csrf(proxy_logged_in, pid)
    from urllib.parse import quote
    r = await proxy_logged_in.post(
        f"/proxy/users/{quote(pid, safe='')}/api-tokens/create",
        data={
            "csrf_token": csrf,
            "label": "LibreChat anthro-only",
            "expires_at": "2027-12-31",
            # Multi-value: httpx serialises a list as repeated form fields.
            "scope_providers": ["anthropic", "openai"],
        },
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text

    # Verify the row in DB
    from mcp_proxy.db import list_user_api_tokens
    rows = await list_user_api_tokens(pid)
    assert len(rows) == 1
    row = rows[0]
    assert row["label"] == "LibreChat anthro-only"
    assert sorted(row["scope_providers"]) == ["anthropic", "openai"]
    # YYYY-MM-DD promoted to a full ISO timestamp by the route
    assert row["expires_at"] is not None
    assert row["expires_at"].startswith("2027-12-31")


# ── revoke ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_revoke_happy_path(proxy_logged_in):
    pid = "acme::user::dave"
    csrf = await _csrf(proxy_logged_in, pid)
    from urllib.parse import quote
    mint_r = await proxy_logged_in.post(
        f"/proxy/users/{quote(pid, safe='')}/api-tokens/create",
        data={"csrf_token": csrf, "label": "to-revoke"},
        follow_redirects=False,
    )
    assert mint_r.status_code == 303

    from mcp_proxy.db import list_user_api_tokens
    rows = await list_user_api_tokens(pid)
    token_id = rows[0]["id"]

    csrf2 = await _csrf(proxy_logged_in, pid)
    revoke_r = await proxy_logged_in.post(
        f"/proxy/users/{quote(pid, safe='')}/api-tokens/{token_id}/revoke",
        data={"csrf_token": csrf2},
        follow_redirects=False,
    )
    assert revoke_r.status_code == 303
    qs = _redirect_query(revoke_r)
    assert "ok" in qs, qs

    # Default list filters revoked rows out
    after = await list_user_api_tokens(pid)
    assert after == []
    after_full = await list_user_api_tokens(pid, include_revoked=True)
    assert len(after_full) == 1
    assert after_full[0]["revoked_at"] is not None


@pytest.mark.asyncio
async def test_revoke_unknown_id_returns_error(proxy_logged_in):
    pid = "acme::user::erin"
    csrf = await _csrf(proxy_logged_in, pid)
    from urllib.parse import quote
    r = await proxy_logged_in.post(
        f"/proxy/users/{quote(pid, safe='')}/api-tokens/nonexistent-id/revoke",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    qs = _redirect_query(r)
    assert "token_error" in qs, qs


@pytest.mark.asyncio
async def test_revoke_token_of_different_user_rejected(proxy_logged_in):
    """A stale revoke form from one user's page must not be able to
    nuke another user's token by guessing the id."""
    from urllib.parse import quote
    pid_a = "acme::user::frank"
    pid_b = "acme::user::grace"
    csrf_a = await _csrf(proxy_logged_in, pid_a)
    await proxy_logged_in.post(
        f"/proxy/users/{quote(pid_a, safe='')}/api-tokens/create",
        data={"csrf_token": csrf_a, "label": "frank-only"},
        follow_redirects=False,
    )
    from mcp_proxy.db import list_user_api_tokens
    rows = await list_user_api_tokens(pid_a)
    tid = rows[0]["id"]

    csrf_b = await _csrf(proxy_logged_in, pid_b)
    r = await proxy_logged_in.post(
        f"/proxy/users/{quote(pid_b, safe='')}/api-tokens/{tid}/revoke",
        data={"csrf_token": csrf_b},
        follow_redirects=False,
    )
    assert r.status_code == 303
    qs = _redirect_query(r)
    assert "token_error" in qs, qs
    # The original token is still active.
    still = await list_user_api_tokens(pid_a)
    assert len(still) == 1
    assert still[0]["revoked_at"] is None


# ── render integration ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_user_detail_renders_token_table(proxy_logged_in):
    pid = "acme::user::heidi"
    csrf = await _csrf(proxy_logged_in, pid)
    from urllib.parse import quote
    await proxy_logged_in.post(
        f"/proxy/users/{quote(pid, safe='')}/api-tokens/create",
        data={"csrf_token": csrf, "label": "render-test"},
        follow_redirects=False,
    )
    page = await proxy_logged_in.get(
        f"/proxy/users/{quote(pid, safe='')}",
    )
    assert page.status_code == 200
    body = page.text
    # The API Tokens tab button must be present
    assert "API Tokens" in body
    # The token label rendered in the active-tokens table
    assert "render-test" in body


@pytest.mark.asyncio
async def test_user_detail_shows_one_time_banner_when_new_token_query_present(proxy_logged_in):
    pid = "acme::user::ivan"
    # Just render the page with the query param; we don't need to
    # actually mint here — the template branch is gated on the param.
    from urllib.parse import quote
    # Seeds the local_user_principals row (return value intentionally
    # discarded — we don't POST anything in this test, just GET).
    await _csrf(proxy_logged_in, pid)
    fake_token = "culk_" + "x" * 52
    page = await proxy_logged_in.get(
        f"/proxy/users/{quote(pid, safe='')}?new_token={quote(fake_token)}&new_token_label=demo",
    )
    assert page.status_code == 200
    body = page.text
    assert fake_token in body
    assert "save it now" in body  # one-time banner copy
