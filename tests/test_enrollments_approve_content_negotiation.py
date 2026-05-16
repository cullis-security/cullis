"""Content negotiation regression tests for enrollment approve/reject.

`mcp_proxy/dashboard/router.py:_enroll_error_response` returns 303+flash
for browsers (`Accept: text/html`) and 400+JSON for script callers
(`Accept: */*`, `application/json`). These tests pin both branches so a
future "let's just always 303" regression breaks here.

Validation branches (missing agent_id / reason) short-circuit before the
service layer is touched, so they exercise the helper directly. The
EnrollmentError branch uses a nonexistent session_id to drive the
service into raising before any CA work is needed.
"""
from __future__ import annotations

import json as _json
import time as _time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


def _admin_cookie(csrf_token: str = "test-csrf-token") -> tuple[str, str]:
    """Mint a signed session cookie + matching CSRF token."""
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _sign

    payload = _json.dumps(
        {"role": "admin", "csrf_token": csrf_token, "exp": int(_time.time()) + 3600}
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

    from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()
    reset_agent_rate_limiter()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


# ── Approve: missing agent_id ─────────────────────────────────────


@pytest.mark.asyncio
async def test_approve_missing_agent_id_returns_400_for_json_client(proxy_app):
    """CLI/script POST without Accept: text/html gets a 400 JSON."""
    _, client = proxy_app
    csrf = "csrf-json"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        "/proxy/enrollments/some-session-id/approve",
        data={"csrf_token": csrf, "agent_id": ""},
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json() == {"detail": "agent_id is required"}


@pytest.mark.asyncio
async def test_approve_missing_agent_id_returns_303_for_browser(proxy_app):
    """Browser POST with Accept: text/html keeps the 303+flash UX."""
    _, client = proxy_app
    csrf = "csrf-html"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        "/proxy/enrollments/some-session-id/approve",
        data={"csrf_token": csrf, "agent_id": ""},
        headers={"Accept": "text/html,application/xhtml+xml"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    # quote() encodes spaces as %20 (unlike quote_plus's '+'). Both are
    # valid percent-encodings; the dashboard template decodes the message
    # back from the query string either way.
    assert "error=agent_id%20is%20required" in resp.headers["location"]


@pytest.mark.asyncio
async def test_approve_curl_default_accept_gets_400(proxy_app):
    """curl default Accept */* (no text/html) gets 400, not 303."""
    _, client = proxy_app
    csrf = "csrf-curl"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        "/proxy/enrollments/some-session-id/approve",
        data={"csrf_token": csrf, "agent_id": ""},
        headers={"Accept": "*/*"},
        follow_redirects=False,
    )
    assert resp.status_code == 400


# ── Reject: missing reason ────────────────────────────────────────


@pytest.mark.asyncio
async def test_reject_missing_reason_returns_400_for_json_client(proxy_app):
    """Symmetric: reject without reason → 400 for JSON, 303 for HTML."""
    _, client = proxy_app
    csrf = "csrf-reject-json"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        "/proxy/enrollments/some-session-id/reject",
        data={"csrf_token": csrf, "reason": ""},
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert resp.json() == {"detail": "Rejection reason is required"}


@pytest.mark.asyncio
async def test_reject_missing_reason_returns_303_for_browser(proxy_app):
    _, client = proxy_app
    csrf = "csrf-reject-html"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        "/proxy/enrollments/some-session-id/reject",
        data={"csrf_token": csrf, "reason": ""},
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "error=Rejection%20reason%20is%20required" in resp.headers["location"]


# ── EnrollmentError branch (service raises) ───────────────────────


@pytest.mark.asyncio
async def test_approve_enrollment_error_returns_400_for_json_client(proxy_app):
    """When the service raises EnrollmentError (e.g. session not found),
    JSON client gets 400 with the error message in detail."""
    _, client = proxy_app
    csrf = "csrf-enroll-err"
    cookie_name, cookie_value = _admin_cookie(csrf_token=csrf)
    client.cookies.set(cookie_name, cookie_value)

    resp = await client.post(
        "/proxy/enrollments/nonexistent-session-xyz/approve",
        data={
            "csrf_token": csrf,
            "agent_id": "test-agent",
            "capabilities": "",
            "groups": "",
        },
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    body = resp.json()
    assert "detail" in body
    assert body["detail"]
