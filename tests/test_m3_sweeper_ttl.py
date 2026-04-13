"""M3.6 — session sweeper TTL expiry tests.

Verifies that ``_sweep_message_queue`` flips expired rows and emits
``message_expired`` frames to the sender best-effort. Uses the real
AsyncSessionLocal DB (setup by tests/conftest.py) and monkeypatches
ws_manager.send_to_agent to capture frames.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from app.broker import message_queue as mq
from app.broker.db_models import ProxyMessageQueueRecord
from app.db.database import AsyncSessionLocal


pytestmark = pytest.mark.asyncio


async def _insert_expired(session_id: str, sender: str, recipient: str) -> str:
    """Insert a queue row already past its TTL."""
    async with AsyncSessionLocal() as db:
        ct = json.dumps({"x": 1}, sort_keys=True, separators=(",", ":")).encode()
        msg_id, _ = await mq.enqueue(
            db,
            session_id=session_id,
            recipient_agent_id=recipient,
            sender_agent_id=sender,
            ciphertext=ct, seq=0, ttl_seconds=1,
        )
        # Backdate ttl_expires_at so sweep_expired picks it up immediately.
        from sqlalchemy import update
        await db.execute(
            update(ProxyMessageQueueRecord)
            .where(ProxyMessageQueueRecord.msg_id == msg_id)
            .values(ttl_expires_at=datetime.now(timezone.utc) - timedelta(seconds=60))
        )
        await db.commit()
        return msg_id


async def test_sweep_message_queue_expires_and_notifies(monkeypatch):
    # Bypass the under-pytest skip guard added in session_sweeper to avoid
    # SQLite StaticPool contention — this test exercises the function
    # deliberately, so we want it to run.
    monkeypatch.delenv("CULLIS_DISABLE_QUEUE_OPS", raising=False)

    captured: list[tuple[str, dict]] = []

    async def fake_send(agent_id: str, data: dict) -> None:
        captured.append((agent_id, data))

    from app.broker import ws_manager as ws_mod
    monkeypatch.setattr(ws_mod.ws_manager, "send_to_agent", fake_send)

    sid = "00000000-0000-0000-0000-00000000ab01"
    msg_id = await _insert_expired(sid, "org-q::sender", "org-q::recipient")

    from app.broker.session_sweeper import _sweep_message_queue
    n = await _sweep_message_queue()
    assert n == 1

    # Row flipped to expired (status=2).
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        status = (await db.execute(
            select(ProxyMessageQueueRecord.delivery_status).where(
                ProxyMessageQueueRecord.msg_id == msg_id,
            )
        )).scalar_one()
        assert status == mq.DELIVERY_EXPIRED

    # Sender got a message_expired frame.
    assert len(captured) == 1
    recv_agent, payload = captured[0]
    assert recv_agent == "org-q::sender"
    assert payload["type"] == "message_expired"
    assert payload["msg_id"] == msg_id
    assert payload["reason"] == "ttl"
    assert payload["recipient_agent_id"] == "org-q::recipient"


async def test_sweep_message_queue_noop_when_empty(monkeypatch):
    monkeypatch.delenv("CULLIS_DISABLE_QUEUE_OPS", raising=False)
    from app.broker.session_sweeper import _sweep_message_queue
    n = await _sweep_message_queue()
    assert n == 0


async def test_sweep_message_queue_tolerates_ws_failures(monkeypatch):
    monkeypatch.delenv("CULLIS_DISABLE_QUEUE_OPS", raising=False)

    async def fake_send(*_args, **_kwargs):
        raise RuntimeError("boom")

    from app.broker import ws_manager as ws_mod
    monkeypatch.setattr(ws_mod.ws_manager, "send_to_agent", fake_send)

    sid = "00000000-0000-0000-0000-00000000ab02"
    msg_id = await _insert_expired(sid, "org-qq::s", "org-qq::r")

    from app.broker.session_sweeper import _sweep_message_queue
    n = await _sweep_message_queue()
    # Even though ws_manager raises, the row was still expired.
    assert n == 1

    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        status = (await db.execute(
            select(ProxyMessageQueueRecord.delivery_status).where(
                ProxyMessageQueueRecord.msg_id == msg_id,
            )
        )).scalar_one()
        assert status == mq.DELIVERY_EXPIRED
