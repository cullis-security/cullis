"""ADR-001 Phase 3a — local session lifecycle in the proxy.

Covers:
  - LocalSessionStore: create, activate, reject, close, find_stale, cap
  - persistence: save + restore round-trip on local_sessions table
  - egress router interception when PROXY_INTRA_ORG=on and target is intra
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.local.models import SessionCloseReason, SessionStatus
from mcp_proxy.local.persistence import restore_sessions, save_session
from mcp_proxy.local.session import (
    LocalAgentSessionCapExceeded,
    LocalSessionStore,
)


# ── LocalSessionStore unit tests ────────────────────────────────────

def test_create_and_get():
    store = LocalSessionStore()
    s = store.create("alice", "bob", ["cap.read"])
    assert s.status == SessionStatus.pending
    assert s.initiator_agent_id == "alice"
    assert s.responder_agent_id == "bob"
    assert store.get(s.session_id) is s


def test_activate_pending_to_active():
    store = LocalSessionStore()
    s = store.create("alice", "bob", [])
    activated = store.activate(s.session_id)
    assert activated.status == SessionStatus.active


def test_activate_closed_is_noop():
    store = LocalSessionStore()
    s = store.create("alice", "bob", [])
    store.close(s.session_id)
    result = store.activate(s.session_id)
    assert result.status == SessionStatus.closed


def test_reject_sets_denied_with_reason():
    store = LocalSessionStore()
    s = store.create("alice", "bob", [])
    store.reject(s.session_id)
    assert s.status == SessionStatus.denied
    assert s.close_reason == SessionCloseReason.rejected


def test_close_default_reason_is_normal():
    store = LocalSessionStore()
    s = store.create("alice", "bob", [])
    store.close(s.session_id)
    assert s.status == SessionStatus.closed
    assert s.close_reason == SessionCloseReason.normal


def test_close_preserves_first_reason():
    store = LocalSessionStore()
    s = store.create("alice", "bob", [])
    store.close(s.session_id, SessionCloseReason.policy_revoked)
    store.close(s.session_id, SessionCloseReason.normal)
    assert s.close_reason == SessionCloseReason.policy_revoked


def test_cap_enforced_on_active_sessions():
    store = LocalSessionStore(active_cap_per_agent=2)
    s1 = store.create("alice", "bob", [])
    s2 = store.create("alice", "carol", [])
    store.activate(s1.session_id)
    store.activate(s2.session_id)
    with pytest.raises(LocalAgentSessionCapExceeded) as exc:
        store.create("alice", "dave", [])
    assert exc.value.current == 2
    assert exc.value.cap == 2


def test_cap_does_not_count_pending_or_closed():
    store = LocalSessionStore(active_cap_per_agent=1)
    s1 = store.create("alice", "bob", [])  # pending
    store.create("alice", "carol", [])     # also pending — fine
    store.activate(s1.session_id)          # 1 active (at cap)
    store.close(s1.session_id)             # 0 active again
    store.create("alice", "dave", [])      # allowed


def test_list_for_agent_matches_both_roles():
    store = LocalSessionStore()
    s1 = store.create("alice", "bob", [])
    s2 = store.create("bob", "alice", [])
    s3 = store.create("carol", "dave", [])
    alice_sessions = {s.session_id for s in store.list_for_agent("alice")}
    assert alice_sessions == {s1.session_id, s2.session_id}
    assert s3.session_id not in alice_sessions


def test_find_stale_flags_idle_active_sessions():
    store = LocalSessionStore()
    s = store.create("alice", "bob", [])
    store.activate(s.session_id)
    # Force last_activity_at into the past.
    s.last_activity_at = datetime.now(timezone.utc) - timedelta(seconds=3600)
    stale = store.find_stale(idle_timeout_seconds=60)
    assert any(
        sid == s.session_id and reason == SessionCloseReason.idle_timeout
        for (sess, reason) in stale
        for sid in [sess.session_id]
    )


def test_find_stale_flags_ttl_expired():
    store = LocalSessionStore(session_ttl_minutes=1)
    s = store.create("alice", "bob", [])
    s.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    stale = store.find_stale()
    assert any(
        reason == SessionCloseReason.ttl_expired for (_s, reason) in stale
    )


def test_get_flips_expired_to_closed():
    store = LocalSessionStore()
    s = store.create("alice", "bob", [])
    s.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    fetched = store.get(s.session_id)
    assert fetched.status == SessionStatus.closed
    assert fetched.close_reason == SessionCloseReason.ttl_expired


# ── Persistence round-trip ──────────────────────────────────────────

@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    await init_db(url)
    yield url
    await dispose_db()


@pytest.mark.asyncio
async def test_save_and_restore_roundtrip(proxy_db):
    store1 = LocalSessionStore()
    s = store1.create("alice", "bob", ["cap.read"])
    store1.activate(s.session_id)
    await save_session(s)

    store2 = LocalSessionStore()
    restored = await restore_sessions(store2)
    assert restored == 1
    s2 = store2.get(s.session_id)
    assert s2 is not None
    assert s2.initiator_agent_id == "alice"
    assert s2.responder_agent_id == "bob"
    assert s2.status == SessionStatus.active


@pytest.mark.asyncio
async def test_restore_skips_closed_sessions(proxy_db):
    store1 = LocalSessionStore()
    s_active = store1.create("alice", "bob", [])
    store1.activate(s_active.session_id)
    s_closed = store1.create("alice", "carol", [])
    store1.close(s_closed.session_id)
    await save_session(s_active)
    await save_session(s_closed)

    store2 = LocalSessionStore()
    restored = await restore_sessions(store2)
    assert restored == 1
    assert store2.get(s_active.session_id) is not None
    assert store2.get(s_closed.session_id) is None


# ── Egress router interception ──────────────────────────────────────

@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    # Settings singleton is lru_cache'd — flush between tests
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    # Force the lifespan to run by using the ASGI transport.
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _provision_internal_agent(agent_id: str = "sender-bot") -> str:
    """Create an internal agent with API key and return the raw key."""
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import create_agent
    raw_key = generate_api_key(agent_id)
    await create_agent(
        agent_id=agent_id,
        display_name=agent_id,
        capabilities=["cap.read"],
        api_key_hash=hash_api_key(raw_key),
    )
    return raw_key


@pytest.mark.asyncio
async def test_router_opens_local_session_for_intra_target(proxy_app):
    app, client = proxy_app
    api_key = await _provision_internal_agent("sender-bot")

    resp = await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": api_key},
        json={
            "target_agent_id": "acme::peer-bot",
            "target_org_id": "acme",
            "capabilities": ["cap.read"],
        },
    )
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["session_id"]

    store: LocalSessionStore = app.state.local_session_store
    session = store.get(session_id)
    assert session is not None
    assert session.status == SessionStatus.pending
    assert session.responder_agent_id == "acme::peer-bot"


@pytest.mark.asyncio
async def test_router_accept_close_round_trip(proxy_app):
    app, client = proxy_app
    initiator_key = await _provision_internal_agent("sender-bot")
    responder_key = await _provision_internal_agent("peer-bot")

    open_resp = await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": initiator_key},
        json={
            "target_agent_id": "peer-bot",
            "target_org_id": "acme",
            "capabilities": [],
        },
    )
    session_id = open_resp.json()["session_id"]

    accept_resp = await client.post(
        f"/v1/egress/sessions/{session_id}/accept",
        headers={"X-API-Key": responder_key},
    )
    assert accept_resp.status_code == 200, accept_resp.text

    store: LocalSessionStore = app.state.local_session_store
    assert store.get(session_id).status == SessionStatus.active

    close_resp = await client.post(
        f"/v1/egress/sessions/{session_id}/close",
        headers={"X-API-Key": initiator_key},
    )
    assert close_resp.status_code == 200, close_resp.text
    assert store.get(session_id).status == SessionStatus.closed


@pytest.mark.asyncio
async def test_accept_rejects_non_responder(proxy_app):
    app, client = proxy_app
    initiator_key = await _provision_internal_agent("sender-bot")
    await _provision_internal_agent("peer-bot")
    stranger_key = await _provision_internal_agent("stranger-bot")

    open_resp = await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": initiator_key},
        json={"target_agent_id": "peer-bot", "target_org_id": "acme", "capabilities": []},
    )
    session_id = open_resp.json()["session_id"]

    resp = await client.post(
        f"/v1/egress/sessions/{session_id}/accept",
        headers={"X-API-Key": stranger_key},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_sessions_returns_local_only_without_broker(proxy_app):
    app, client = proxy_app
    api_key = await _provision_internal_agent("sender-bot")

    # Explicitly clear the broker bridge so list_sessions falls back to local.
    app.state.broker_bridge = None

    await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": api_key},
        json={"target_agent_id": "peer-bot", "target_org_id": "acme", "capabilities": []},
    )

    resp = await client.get("/v1/egress/sessions", headers={"X-API-Key": api_key})
    assert resp.status_code == 200
    sessions = resp.json()["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["scope"] == "local"
