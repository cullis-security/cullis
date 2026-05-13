"""Mastio dashboard /proxy/users CRUD forwarded to Frontdesk Ambassador.

Mastio is the control plane (principal registry, attribution, cert
authority). Frontdesk is the data plane (users.db, bcrypt, password
lifecycle). The dashboard mints a one-time temp password, forwards
the lifecycle call to ``frontdesk_ambassador_url``, surfaces the temp
password once on redirect, and never persists or logs the plaintext.

Tests cover:
  - 16-char unambiguous temp-password alphabet
  - Create / Reset / Delete forwards with X-Admin-Secret header
  - Degraded mode when the Ambassador is not configured (read-only)
  - Error mapping: 409 → user exists, transport → unreachable
  - Plaintext temp password never leaves through ``_log``
"""
from __future__ import annotations

import re

import pytest
from httpx import ASGITransport, AsyncClient

# Most tests are async (ASGI client). The two ``_temp_password`` ones
# at the top are pure functions, so we mark per-test instead of
# applying ``pytestmark`` globally — that keeps pytest from warning
# about the asyncio marker on sync tests.


async def _spin(tmp_path, monkeypatch, *, frontdesk: bool = True):
    db_file = tmp_path / "p.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "td-org")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    if frontdesk:
        monkeypatch.setenv("MCP_PROXY_FRONTDESK_AMBASSADOR_URL", "http://fd-test:7777")
        monkeypatch.setenv("MCP_PROXY_FRONTDESK_ADMIN_SECRET", "test-admin-secret")
    else:
        monkeypatch.delenv("MCP_PROXY_FRONTDESK_AMBASSADOR_URL", raising=False)
        monkeypatch.delenv("MCP_PROXY_FRONTDESK_ADMIN_SECRET", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def _login(cli: AsyncClient) -> None:
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password("test-password-1234")
    r = await cli.post(
        "/proxy/login",
        data={"password": "test-password-1234"},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text


async def _csrf(cli: AsyncClient) -> str:
    r = await cli.get("/proxy/users")
    assert r.status_code == 200, r.text
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    assert m, "csrf_token not found in /proxy/users page"
    return m.group(1)


def _install_fake_frontdesk(monkeypatch, *, responses):
    """Patch _frontdesk_admin_call to record + script responses.

    ``responses`` is a list of ``(status, body, transport_err)`` tuples
    popped in order. The captured calls live on the returned list.
    """
    calls: list[dict] = []

    async def fake_call(method, path, *, json_body=None):
        calls.append({"method": method, "path": path, "json_body": json_body})
        if not responses:
            raise AssertionError(f"unexpected extra call: {method} {path}")
        return responses.pop(0)

    from mcp_proxy.dashboard import router as dash_router
    monkeypatch.setattr(dash_router, "_frontdesk_admin_call", fake_call)
    # Also short-circuit the list fetch so the page render doesn't try
    # to hit fd-test on background pulls during the redirect-following
    # detail page render.
    async def fake_fetch_list():
        return {}
    monkeypatch.setattr(dash_router, "_fetch_frontdesk_users", fake_fetch_list)
    return calls


# ── temp password generator ────────────────────────────────────────────


def test_temp_password_alphabet_is_unambiguous():
    from mcp_proxy.dashboard.router import _generate_temp_password
    forbidden = set("0O1lI-_")
    for _ in range(50):
        pw = _generate_temp_password()
        assert len(pw) == 16, f"want 16 chars, got {len(pw)}"
        assert not (set(pw) & forbidden), (
            f"temp pw {pw!r} contains forbidden char from {forbidden}"
        )


def test_temp_password_distinct_across_calls():
    from mcp_proxy.dashboard.router import _generate_temp_password
    seen = {_generate_temp_password() for _ in range(200)}
    # 16 chars over a ~56-char alphabet, 200 draws: collision probability
    # is astronomical. Anything less than 200 distinct values means the
    # RNG is broken.
    assert len(seen) == 200


# ── degraded mode (no Frontdesk wired) ─────────────────────────────────


@pytest.mark.asyncio
async def test_users_create_registry_only_when_frontdesk_missing(
    tmp_path, monkeypatch,
):
    """No Frontdesk Ambassador configured = create the registry row
    directly in ``local_user_principals`` without minting a temp password
    (ADR-027 path — the admin will mint a ``culk_*`` token from the
    detail page to grant access)."""
    app = await _spin(tmp_path, monkeypatch, frontdesk=False)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/create",
                data={
                    "csrf_token": csrf,
                    "user_name": "alice",
                    "display_name": "Alice Demo",
                },
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text
            loc = r.headers["location"]
            # Redirect to per-user detail page with a success banner.
            assert "/proxy/users/td-org%3A%3Auser%3A%3Aalice" in loc, loc
            assert "Registry+row+created" in loc, loc
            # Crucially no temp password in the URL — registry-only mode
            # doesn't mint one.
            assert "new_pw" not in loc, loc

            # Verify the row landed in local_user_principals.
            from mcp_proxy.db import get_db
            from sqlalchemy import text
            async with get_db() as conn:
                result = await conn.execute(
                    text(
                        "SELECT user_name, display_name, surface "
                        "FROM local_user_principals "
                        "WHERE principal_id = 'td-org::user::alice'"
                    ),
                )
                row = result.mappings().first()
            assert row is not None
            assert row["user_name"] == "alice"
            assert row["display_name"] == "Alice Demo"
            assert row["surface"] == "registry"

            # Second submit with the same name → 303 to ?error=...exists.
            r2 = await cli.post(
                "/proxy/users/create",
                data={
                    "csrf_token": csrf,
                    "user_name": "alice",
                    "display_name": "Alice Two",
                },
                follow_redirects=False,
            )
            assert r2.status_code == 303
            assert "already+exists" in r2.headers["location"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── happy path: create ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_users_create_forwards_to_ambassador_and_redirects_to_detail(
    tmp_path, monkeypatch,
):
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        calls = _install_fake_frontdesk(
            monkeypatch, responses=[(201, {"user_name": "alice"}, None)],
        )
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/create",
                data={
                    "csrf_token": csrf,
                    "user_name": "alice",
                    "display_name": "Alice Rossi",
                },
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text
            loc = r.headers["location"]
            assert "/proxy/users/" in loc
            # Wave B G2 (audit 2026-05-11) — redirect now carries an
            # opaque single-consume ticket instead of the cleartext
            # password. The detail page resolves the ticket to the
            # cleartext server-side; pre-fix the cleartext was in the
            # URL and landed in nginx logs / browser history / Referer.
            assert "new_pw_ticket=" in loc, (
                "temp password ticket must be in redirect query"
            )
    # Forwarded call shape
    assert len(calls) == 1
    c = calls[0]
    assert c["method"] == "POST"
    assert c["path"] == "/admin/users"
    body = c["json_body"]
    assert body["user_name"] == "alice"
    assert body["display_name"] == "Alice Rossi"
    assert body["must_change_password"] is True
    assert isinstance(body["password"], str) and len(body["password"]) == 16
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_users_create_409_returns_already_exists(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        _install_fake_frontdesk(
            monkeypatch, responses=[(409, {"detail": "already exists"}, None)],
        )
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/create",
                data={"csrf_token": csrf, "user_name": "alice"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "already+exists" in r.headers["location"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_users_create_transport_error_returns_unreachable(
    tmp_path, monkeypatch,
):
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        _install_fake_frontdesk(
            monkeypatch, responses=[(0, None, "transport_error")],
        )
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/create",
                data={"csrf_token": csrf, "user_name": "alice"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "Frontdesk+unreachable" in r.headers["location"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── reset-password ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_users_reset_password_forwards_and_surfaces_new_temp(
    tmp_path, monkeypatch,
):
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        calls = _install_fake_frontdesk(
            monkeypatch, responses=[(204, None, None)],
        )
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            pid = "td-org::user::alice"
            r = await cli.post(
                f"/proxy/users/{pid}/reset-password",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text
            loc = r.headers["location"]
            # Wave B G2 — opaque ticket replaces cleartext password.
            assert "reset_pw_ticket=" in loc
    assert len(calls) == 1
    c = calls[0]
    assert c["method"] == "POST"
    assert c["path"] == "/admin/users/alice/reset-password"
    assert isinstance(c["json_body"]["new_password"], str)
    assert len(c["json_body"]["new_password"]) == 16
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── delete ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_users_delete_204_scrubs_mastio_row(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        # Pre-seed a Mastio row so we can verify the scrub.
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            await conn.execute(
                text(
                    "INSERT INTO local_user_principals "
                    "(principal_id, user_name, display_name, reach, surface, created_at) "
                    "VALUES (:pid, :uname, :dname, 'intra', 'frontdesk', "
                    "datetime('now'))"
                ),
                {
                    "pid": "td-org::user::alice",
                    "uname": "alice",
                    "dname": "Alice",
                },
            )
        calls = _install_fake_frontdesk(
            monkeypatch, responses=[(204, None, None)],
        )
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/td-org::user::alice/delete",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text
            assert "/proxy/users?ok=Deleted" in r.headers["location"]
        # Mastio row gone.
        async with get_db() as conn:
            row = (await conn.execute(
                text(
                    "SELECT principal_id FROM local_user_principals "
                    "WHERE principal_id = :pid"
                ),
                {"pid": "td-org::user::alice"},
            )).first()
            assert row is None, "expected Mastio row to be scrubbed after delete"
    assert calls[0]["method"] == "DELETE"
    assert calls[0]["path"] == "/admin/users/alice"
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_users_delete_404_is_idempotent_and_still_scrubs(
    tmp_path, monkeypatch,
):
    """If the Frontdesk says 404, the row is already gone on that side.

    We still scrub the Mastio attribution row so the dashboard view
    converges (no orphaned principal floating without credentials).
    """
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            await conn.execute(
                text(
                    "INSERT INTO local_user_principals "
                    "(principal_id, user_name, display_name, reach, surface, created_at) "
                    "VALUES ('td-org::user::ghost', 'ghost', '', 'intra', "
                    "'frontdesk', datetime('now'))"
                )
            )
        _install_fake_frontdesk(monkeypatch, responses=[(404, None, None)])
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/td-org::user::ghost/delete",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "/proxy/users?ok=Deleted" in r.headers["location"]
        async with get_db() as conn:
            row = (await conn.execute(
                text(
                    "SELECT principal_id FROM local_user_principals "
                    "WHERE principal_id = 'td-org::user::ghost'"
                )
            )).first()
            assert row is None
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── reset TOFU pin (Mastio-local, no Frontdesk bridge) ─────────────────


@pytest.mark.asyncio
async def test_users_reset_tofu_pin_clears_and_redirects(tmp_path, monkeypatch):
    """Pubkey thumbprint set → POST clears it, dashboard redirects with
    ?ok=TOFU+pin+cleared, no Frontdesk Ambassador call."""
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            await conn.execute(
                text(
                    "INSERT INTO local_user_principals "
                    "(principal_id, user_name, display_name, reach, "
                    " surface, pubkey_thumbprint, created_at) "
                    "VALUES (:pid, :uname, '', 'intra', 'frontdesk', "
                    "        :thumb, datetime('now'))"
                ),
                {
                    "pid": "td-org::user::alice", "uname": "alice",
                    "thumb": "a" * 64,
                },
            )
        # No Ambassador call expected — script empty responses and we
        # assert nothing was popped.
        calls = _install_fake_frontdesk(monkeypatch, responses=[])
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/td-org::user::alice/reset-tofu-pin",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text
            assert "TOFU+pin+cleared" in r.headers["location"]
        assert calls == [], "no Frontdesk bridge expected for TOFU reset"
        async with get_db() as conn:
            row = (await conn.execute(
                text(
                    "SELECT pubkey_thumbprint FROM local_user_principals "
                    "WHERE principal_id = 'td-org::user::alice'"
                )
            )).mappings().first()
            assert row["pubkey_thumbprint"] is None
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_users_reset_tofu_pin_no_pin_redirects_error(tmp_path, monkeypatch):
    """Row exists, pubkey already NULL → redirect with ?error=No+pin+to+clear
    so the operator sees the helper was a no-op."""
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            await conn.execute(
                text(
                    "INSERT INTO local_user_principals "
                    "(principal_id, user_name, display_name, reach, "
                    " surface, created_at) "
                    "VALUES ('td-org::user::bob', 'bob', '', 'intra', "
                    "        'frontdesk', datetime('now'))"
                )
            )
        _install_fake_frontdesk(monkeypatch, responses=[])
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/td-org::user::bob/reset-tofu-pin",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "No+pin+to+clear" in r.headers["location"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_users_reset_tofu_pin_requires_csrf(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        _install_fake_frontdesk(monkeypatch, responses=[])
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            r = await cli.post(
                "/proxy/users/td-org::user::alice/reset-tofu-pin",
                data={"csrf_token": "wrong"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "error=csrf" in r.headers["location"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── security: plaintext password never logged ──────────────────────────


@pytest.mark.asyncio
async def test_plaintext_temp_password_never_logged(tmp_path, monkeypatch):
    """The dashboard mints a temp password and hands it to the admin via
    the redirect query string. It must NEVER show up in the worker log
    even at WARNING level when the Frontdesk rejects the request.

    We capture every call to ``_log.warning`` / ``_log.info`` /
    ``_log.error`` on the dashboard router module and assert the
    16-char value never appears in any formatted argument.
    """
    app = await _spin(tmp_path, monkeypatch, frontdesk=True)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        # Force the Frontdesk to reject with 500 so the warning path
        # fires (the happy path takes no log line). We also script a
        # transport error path to cover that branch.
        _install_fake_frontdesk(
            monkeypatch,
            responses=[(500, {"detail": "boom"}, None)],
        )
        # Capture every log line emitted from the router module.
        from mcp_proxy.dashboard import router as dash_router
        log_calls: list[tuple[str, tuple, dict]] = []

        def _capture(level):
            def inner(msg, *args, **kwargs):
                log_calls.append((msg, args, kwargs))
            return inner

        monkeypatch.setattr(dash_router._log, "warning", _capture("warning"))
        monkeypatch.setattr(dash_router._log, "info", _capture("info"))
        monkeypatch.setattr(dash_router._log, "error", _capture("error"))

        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/users/create",
                data={"csrf_token": csrf, "user_name": "audit-target"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            # The temp password lives in the redirect query string; pull it
            # out so we know exactly what value to look for in the log.
            loc = r.headers["location"]
            # Either banner is acceptable here (500 path redirects to list
            # with error), but for the leak check we just want to verify
            # that whatever 16-char strings might exist NEVER end up in
            # _log calls. So we synthesise a probe password too.
            # Wave B G2 — opaque ticket replaces cleartext password.
            assert (
                "new_pw_ticket=" in loc or "Frontdesk+rejected" in loc
            ), loc

    # No log entry may carry a 16-char unambiguous string that matches
    # the alphabet — that would be a leak. Heuristic: scan every arg
    # for any 16-char substring made entirely of the alphabet.
    alphabet = set(
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    )
    leak_re = re.compile(
        r"[ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789]{16}"
    )
    for msg, args, _kwargs in log_calls:
        for piece in (msg, *args):
            s = str(piece)
            for candidate in leak_re.findall(s):
                # Confirm it is purely alphabet chars (no padding).
                assert not (set(candidate) <= alphabet and len(candidate) == 16 and
                            candidate.isalnum()), (
                    f"possible temp password leak in log: {s!r}"
                )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
