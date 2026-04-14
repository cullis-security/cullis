"""ADR-001 Phase 3d — local mini-broker sweeper.

Covers:
  - sweep_once closes idle sessions + TTL-expired sessions
  - sweep_once expires TTL-lapsed queue rows
  - sweeper_loop respects stop_event and wakes out of sleep
  - sweeper emits session_closed + message_expired on the WS manager
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.local import message_queue as local_queue
from mcp_proxy.local.models import SessionCloseReason, SessionStatus
from mcp_proxy.local.session import LocalSessionStore
from mcp_proxy.local.sweeper import sweep_once, sweeper_loop
from mcp_proxy.local.ws_manager import LocalConnectionManager


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    await init_db(url)
    yield url
    await dispose_db()


class _FakeWS:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send_json(self, data: dict) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        pass


@pytest.mark.asyncio
async def test_sweep_closes_idle_session(proxy_db):
    store = LocalSessionStore()
    s = store.create("alice", "bob", [])
    store.activate(s.session_id)
    # Force last_activity into the past.
    s.last_activity_at = datetime.now(timezone.utc) - timedelta(seconds=3600)

    closed, expired = await sweep_once(store, idle_timeout_seconds=60)
    assert closed == 1
    assert expired == 0
    assert store.get(s.session_id).status == SessionStatus.closed
    assert store.get(s.session_id).close_reason == SessionCloseReason.idle_timeout


@pytest.mark.asyncio
async def test_sweep_closes_ttl_expired_session(proxy_db):
    store = LocalSessionStore(session_ttl_minutes=1)
    s = store.create("alice", "bob", [])
    s.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    closed, _ = await sweep_once(store)
    assert closed == 1
    # store.get already flips expired sessions to closed before find_stale,
    # so the sweeper may see them as already-closed and skip the transition.
    # Either way, status is closed and the reason is ttl_expired.
    sess = store.get(s.session_id)
    assert sess.status == SessionStatus.closed
    assert sess.close_reason == SessionCloseReason.ttl_expired


@pytest.mark.asyncio
async def test_sweep_expires_ttl_lapsed_messages(proxy_db):
    store = LocalSessionStore()
    msg_id, _ = await local_queue.enqueue(
        session_id="s1",
        sender_agent_id="alice",
        recipient_agent_id="bob",
        payload_ciphertext="x",
        ttl_seconds=10,
    )
    past = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text("UPDATE local_messages SET expires_at=:p WHERE msg_id=:m"),
            {"p": past, "m": msg_id},
        )

    _, expired = await sweep_once(store)
    assert expired == 1
    assert await local_queue.fetch_pending_for_recipient("bob") == []


@pytest.mark.asyncio
async def test_sweep_notifies_peers_on_session_close(proxy_db):
    store = LocalSessionStore()
    ws = LocalConnectionManager()
    alice_ws, bob_ws = _FakeWS(), _FakeWS()
    await ws.connect("alice", alice_ws)
    await ws.connect("bob", bob_ws)

    s = store.create("alice", "bob", [])
    store.activate(s.session_id)
    s.last_activity_at = datetime.now(timezone.utc) - timedelta(seconds=3600)

    await sweep_once(store, ws, idle_timeout_seconds=60)

    for recorded in (alice_ws.sent, bob_ws.sent):
        assert any(
            f.get("type") == "session_closed"
            and f.get("session_id") == s.session_id
            and f.get("reason") == SessionCloseReason.idle_timeout.value
            for f in recorded
        )


@pytest.mark.asyncio
async def test_sweep_notifies_sender_on_message_expiry(proxy_db):
    store = LocalSessionStore()
    ws = LocalConnectionManager()
    alice_ws = _FakeWS()
    await ws.connect("alice", alice_ws)

    msg_id, _ = await local_queue.enqueue(
        session_id="s1",
        sender_agent_id="alice",
        recipient_agent_id="bob",
        payload_ciphertext="x",
        ttl_seconds=10,
    )
    past = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text("UPDATE local_messages SET expires_at=:p WHERE msg_id=:m"),
            {"p": past, "m": msg_id},
        )

    await sweep_once(store, ws)

    assert any(
        f.get("type") == "message_expired"
        and f.get("msg_id") == msg_id
        and f.get("reason") == "ttl"
        for f in alice_ws.sent
    )


@pytest.mark.asyncio
async def test_sweeper_loop_stops_on_event(proxy_db):
    store = LocalSessionStore()
    stop_event = asyncio.Event()

    task = asyncio.create_task(
        sweeper_loop(store, interval_seconds=100, stop_event=stop_event),
    )
    # Give the loop one cycle to start.
    await asyncio.sleep(0.05)
    stop_event.set()
    # Should return without needing the full 100s interval thanks to
    # asyncio.wait_for on stop_event.wait().
    await asyncio.wait_for(task, timeout=5.0)
    assert task.done()
