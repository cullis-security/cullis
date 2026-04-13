"""M3.6 — WS queue drain unit tests.

Covers ``_drain_queue_for_agent`` — the helper invoked after
``auth_ok`` and at the end of ``_handle_ws_resume`` to push queued
offline messages to a just-connected recipient. The full WS flow is
covered by e2e/smoke; here we verify the helper in isolation with an
in-memory SQLite DB + a FakeWS that captures sent frames.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.broker import message_queue as mq
from app.broker.router import _drain_queue_for_agent
from app.db.database import Base


class FakeWS:
    def __init__(self):
        self.sent: list[dict] = []

    async def send_json(self, payload: dict) -> None:
        self.sent.append(payload)


@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
async def test_drain_pushes_pending_in_seq_order(db_session):
    payload_b = {"iv": "aa", "ciphertext": "bb"}
    ct = json.dumps(payload_b, sort_keys=True, separators=(",", ":")).encode()

    await mq.enqueue(
        db_session,
        session_id="00000000-0000-0000-0000-000000000001",
        recipient_agent_id="org-x::agent-recv",
        sender_agent_id="org-x::agent-send",
        ciphertext=ct, seq=2, ttl_seconds=300,
    )
    await mq.enqueue(
        db_session,
        session_id="00000000-0000-0000-0000-000000000001",
        recipient_agent_id="org-x::agent-recv",
        sender_agent_id="org-x::agent-send",
        ciphertext=ct, seq=1, ttl_seconds=300,
    )

    ws = FakeWS()
    n = await _drain_queue_for_agent(ws, "org-x::agent-recv", db_session)
    assert n == 2
    assert len(ws.sent) == 2
    # Ordered by seq ascending
    assert [f["message"]["seq"] for f in ws.sent] == [1, 2]
    # Each frame has msg_id + queued flag + reconstructed payload
    for f in ws.sent:
        assert f["type"] == "new_message"
        assert f["queued"] is True
        assert "msg_id" in f
        assert f["message"]["sender_agent_id"] == "org-x::agent-send"
        assert f["message"]["payload"] == payload_b


@pytest.mark.asyncio
async def test_drain_is_noop_when_no_pending(db_session):
    ws = FakeWS()
    n = await _drain_queue_for_agent(ws, "org-x::empty-recv", db_session)
    assert n == 0
    assert ws.sent == []


@pytest.mark.asyncio
async def test_drain_does_not_mutate_queue_state(db_session):
    ct = json.dumps({"k": "v"}, sort_keys=True, separators=(",", ":")).encode()
    await mq.enqueue(
        db_session,
        session_id="00000000-0000-0000-0000-000000000002",
        recipient_agent_id="org-y::recv",
        sender_agent_id="org-y::send",
        ciphertext=ct, seq=0, ttl_seconds=300,
    )
    ws = FakeWS()
    await _drain_queue_for_agent(ws, "org-y::recv", db_session)

    # Row must still be pending (ack is separate) — a second drain re-delivers.
    ws2 = FakeWS()
    n2 = await _drain_queue_for_agent(ws2, "org-y::recv", db_session)
    assert n2 == 1


@pytest.mark.asyncio
async def test_drain_skips_recipient_mismatch(db_session):
    ct = json.dumps({"k": "v"}, sort_keys=True, separators=(",", ":")).encode()
    await mq.enqueue(
        db_session,
        session_id="00000000-0000-0000-0000-000000000003",
        recipient_agent_id="org-z::target",
        sender_agent_id="org-z::src",
        ciphertext=ct, seq=0, ttl_seconds=300,
    )
    ws = FakeWS()
    n = await _drain_queue_for_agent(ws, "org-z::other", db_session)
    assert n == 0
