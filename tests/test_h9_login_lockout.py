"""
H9 regression: per-IP rate-limit + lockout on the Mastio dashboard
``/proxy/login`` form.

The handler used to bcrypt-compare every request with no per-IP
gating, no failure counter, and no back-off. Audit H9 flagged the
obvious brute-force surface — bcrypt buys time per guess, not per
million guesses. This file locks in the new safeguards:

- 10 attempts/min/IP rate cap before bcrypt fires
- 5 consecutive failures within 15 min lock the IP for 15 min
- Successful login resets the counter
- Audit row on lock, on rate-limit, on each failure (with counter), on success
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "h9_lockout.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_FORCE_LOCAL_PASSWORD", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    # Reset the lockout + rate limiter singletons so each test runs clean.
    from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter
    from mcp_proxy.dashboard.login_lockout import reset_login_lockout_for_tests
    reset_agent_rate_limiter()
    reset_login_lockout_for_tests()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()
    reset_agent_rate_limiter()
    reset_login_lockout_for_tests()


async def _set_admin_password(pw: str = "correct-horse-battery-staple") -> None:
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password(pw)


# ── Lockout after 5 consecutive failures ─────────────────────────────


@pytest.mark.asyncio
async def test_lockout_after_threshold_failures(proxy_app):
    _, client = proxy_app
    await _set_admin_password()

    # 5 wrong guesses each return 401 — at the 5th the lockout is armed.
    for _ in range(5):
        resp = await client.post(
            "/proxy/login",
            data={"password": "wrong-guess"},
            follow_redirects=False,
        )
        assert resp.status_code == 401, resp.text

    # 6th attempt — even with the right password — must be blocked.
    resp = await client.post(
        "/proxy/login",
        data={"password": "correct-horse-battery-staple"},
        follow_redirects=False,
    )
    assert resp.status_code == 429, resp.text
    assert "too many failed attempts" in resp.text.lower()


# ── Successful login resets the counter ───────────────────────────────


@pytest.mark.asyncio
async def test_success_resets_failure_counter(proxy_app):
    _, client = proxy_app
    await _set_admin_password()

    # 4 failures — under the threshold.
    for _ in range(4):
        resp = await client.post(
            "/proxy/login",
            data={"password": "wrong"},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    # Right password — success.
    resp = await client.post(
        "/proxy/login",
        data={"password": "correct-horse-battery-staple"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    # 4 more failures — still under the threshold (counter was reset).
    for _ in range(4):
        resp = await client.post(
            "/proxy/login",
            data={"password": "wrong"},
            follow_redirects=False,
        )
        assert resp.status_code == 401, "success did not reset failure counter"


# ── Rate limit before bcrypt ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_limit_caps_attempts_per_minute(proxy_app, monkeypatch):
    _, client = proxy_app
    await _set_admin_password()

    # Drop the rate-limit ceiling far enough below the lockout
    # threshold that this test exercises the rate-limit path.
    from mcp_proxy.dashboard import login_lockout, router as dashboard_router
    monkeypatch.setattr(login_lockout, "LOGIN_RATE_PER_MINUTE", 2)
    monkeypatch.setattr(dashboard_router, "LOGIN_RATE_PER_MINUTE", 2, raising=False)
    # ``router`` imports the constant lazily inside the handler, so the
    # monkeypatch on ``login_lockout`` is what the handler reads.

    # First two attempts return 401 (bad password) — under the cap.
    for _ in range(2):
        resp = await client.post(
            "/proxy/login",
            data={"password": "wrong"},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    # Third attempt — over the per-minute cap — returns 429 without
    # touching bcrypt. Use the right password to prove the cap fires
    # before the password check.
    resp = await client.post(
        "/proxy/login",
        data={"password": "correct-horse-battery-staple"},
        follow_redirects=False,
    )
    assert resp.status_code == 429, resp.text
    assert "too many login attempts" in resp.text.lower()


# ── Audit log records lockout, rate-limit, fails, and success ────────


@pytest.mark.asyncio
async def test_audit_records_failures_with_counter(proxy_app):
    _, client = proxy_app
    await _set_admin_password()

    for _ in range(3):
        await client.post(
            "/proxy/login",
            data={"password": "wrong"},
            follow_redirects=False,
        )

    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT status, detail FROM audit_log "
                "WHERE action = 'auth.login' ORDER BY timestamp",
            ),
        )).all()

    failures = [r for r in rows if r[0] == "error"]
    assert len(failures) == 3, [tuple(r) for r in rows]
    # The detail string must carry the per-IP failure counter so the
    # audit reader can spot escalating brute-force without recomputing
    # state from scratch.
    assert "consecutive_fails=1" in failures[0][1]
    assert "consecutive_fails=2" in failures[1][1]
    assert "consecutive_fails=3" in failures[2][1]


@pytest.mark.asyncio
async def test_audit_records_success_with_ip(proxy_app):
    _, client = proxy_app
    await _set_admin_password()

    resp = await client.post(
        "/proxy/login",
        data={"password": "correct-horse-battery-staple"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT status, detail FROM audit_log "
                "WHERE action = 'auth.login' ORDER BY timestamp DESC LIMIT 1",
            ),
        )).first()
    assert row is not None
    status, detail = row
    assert status == "success"
    assert detail is not None and "ip=" in detail
