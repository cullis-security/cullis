"""Tests for the Connector audit API — ``GET /v1/audit/session/{session_id}``.

Covers:
  * 200 + ordering when the caller is a peer of the session
  * 403 when the caller has no entries linking them to the session
  * 404 when no entries exist for the session_id at all
  * 401 when the cert headers are missing or the cert pin fails
  * Response cap at _MAX_ENTRIES (smoke, not a full stress test)

Auth migrated to ADR-014 mTLS client cert (PR-C).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from mcp_proxy.audit.router import _MAX_ENTRIES
from mcp_proxy.db import dispose_db, get_db, init_db, log_audit
from tests._mtls_helpers import provision_internal_agent


_SESSION_A = "sess-aaaa-1111"
_SESSION_B = "sess-bbbb-2222"


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "audit.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}"
    )
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


@pytest_asyncio.fixture
async def seeded_agents(proxy_app):
    """Provision two agents and seed audit rows for two sessions.

    Layout:
      * acme::alice → participated in _SESSION_A (two entries, increasing ts)
      * acme::bob   → participated in _SESSION_B (one entry)
      * _SESSION_A also has one row from a ``system`` actor to exercise the
        non-caller ``agent_id`` path
    """
    alice_headers = await provision_internal_agent(
        "acme::alice", display_name="Alice", capabilities=["chat"],
    )
    bob_headers = await provision_internal_agent(
        "acme::bob", display_name="Bob", capabilities=["chat"],
    )

    base = datetime(2026, 4, 14, 12, 0, 0, tzinfo=timezone.utc)

    # Helper: log then manually overwrite the timestamp so we can test
    # ordering without sleeping.
    async def _seed(ts, agent_id, action, request_id, *, tool=None, detail=None,
                    duration=None, status="ok"):
        await log_audit(
            agent_id=agent_id,
            action=action,
            status=status,
            tool_name=tool,
            detail=detail,
            request_id=request_id,
            duration_ms=duration,
        )
        async with get_db() as conn:
            await conn.execute(
                text(
                    "UPDATE audit_log SET timestamp = :ts "
                    "WHERE id = (SELECT MAX(id) FROM audit_log)"
                ),
                {"ts": ts.isoformat()},
            )

    await _seed(base + timedelta(seconds=1), "acme::alice", "session.open",
                _SESSION_A, tool="open_session", duration=12.5)
    await _seed(base + timedelta(seconds=2), "system", "policy.evaluate",
                _SESSION_A, detail="allow", duration=3.0)
    await _seed(base + timedelta(seconds=3), "acme::alice", "session.send",
                _SESSION_A, tool="send_message", duration=7.0)
    await _seed(base + timedelta(seconds=1), "acme::bob", "session.open",
                _SESSION_B, tool="open_session", duration=11.0)

    return {"alice_headers": alice_headers, "bob_headers": bob_headers}


@pytest.mark.asyncio
async def test_audit_returns_entries_for_peer(proxy_app, seeded_agents):
    _, client = proxy_app
    resp = await client.get(
        f"/v1/audit/session/{_SESSION_A}",
        headers=seeded_agents["alice_headers"],
    )
    assert resp.status_code == 200, resp.text
    entries = resp.json()
    # 3 rows for session A (two alice + one system).
    assert len(entries) == 3
    # Ordering is ascending by timestamp.
    ts_list = [e["timestamp"] for e in entries]
    assert ts_list == sorted(ts_list)
    # Schema sanity.
    first = entries[0]
    assert first["agent_id"] == "acme::alice"
    assert first["action"] == "session.open"
    assert first["tool_name"] == "open_session"
    assert first["status"] == "ok"
    assert first["duration_ms"] == pytest.approx(12.5)


@pytest.mark.asyncio
async def test_audit_forbids_non_peer(proxy_app, seeded_agents):
    _, client = proxy_app
    # bob never touched session A → 403.
    resp = await client.get(
        f"/v1/audit/session/{_SESSION_A}",
        headers=seeded_agents["bob_headers"],
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_audit_404_on_unknown_session(proxy_app, seeded_agents):
    _, client = proxy_app
    resp = await client.get(
        "/v1/audit/session/sess-does-not-exist",
        headers=seeded_agents["alice_headers"],
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_audit_requires_client_cert(proxy_app, seeded_agents):
    _, client = proxy_app
    resp = await client.get(f"/v1/audit/session/{_SESSION_A}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_audit_rejects_unverified_cert(proxy_app, seeded_agents):
    _, client = proxy_app
    # Cert header present but verify=FAILED → 401.
    bad_headers = dict(seeded_agents["alice_headers"])
    bad_headers["X-SSL-Client-Verify"] = "FAILED"
    resp = await client.get(
        f"/v1/audit/session/{_SESSION_A}",
        headers=bad_headers,
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_audit_caps_response_length(tmp_path, monkeypatch):
    """Insert more than _MAX_ENTRIES rows for a single session and confirm
    the response is capped. Uses a fresh DB to avoid coupling to the other
    seeded fixtures."""
    db_file = tmp_path / "audit_cap.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)

    try:
        capper_headers = await provision_internal_agent(
            "acme::capper", display_name="Capper", capabilities=["chat"],
        )
        sid = "sess-cap-9999"
        insert_count = _MAX_ENTRIES + 25
        for i in range(insert_count):
            await log_audit(
                agent_id="acme::capper",
                action=f"action.{i}",
                status="ok",
                request_id=sid,
            )

        from mcp_proxy.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            async with app.router.lifespan_context(app):
                resp = await client.get(
                    f"/v1/audit/session/{sid}",
                    headers=capper_headers,
                )
        assert resp.status_code == 200, resp.text
        entries = resp.json()
        assert len(entries) == _MAX_ENTRIES
    finally:
        await dispose_db()
        get_settings.cache_clear()
