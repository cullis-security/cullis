"""M3 message durability — queue module unit tests.

Uses an in-memory SQLite async DB so the tests run without external
dependencies. The production target is Postgres (validated in
imp/m0_storage_spike.md) but the schema and ops are dialect-portable.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.broker import message_queue as mq
from app.broker.db_models import ProxyMessageQueueRecord
from app.db.database import Base


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    """Isolated in-memory SQLite DB per test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


# ─────────────────────────────────────────────────────────────────────
# enqueue
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enqueue_without_idempotency_always_inserts(db_session):
    mid1, inserted1 = await mq.enqueue(
        db_session,
        session_id="sess-1", recipient_agent_id="r",
        sender_agent_id="s", ciphertext=b"c1", seq=0, ttl_seconds=60,
    )
    mid2, inserted2 = await mq.enqueue(
        db_session,
        session_id="sess-1", recipient_agent_id="r",
        sender_agent_id="s", ciphertext=b"c2", seq=1, ttl_seconds=60,
    )
    assert inserted1 is True and inserted2 is True
    assert mid1 != mid2


@pytest.mark.asyncio
async def test_enqueue_with_idempotency_key_dedupes(db_session):
    key = "order-12345"
    mid1, inserted1 = await mq.enqueue(
        db_session,
        session_id="sess-1", recipient_agent_id="r",
        sender_agent_id="s", ciphertext=b"c1", seq=0, ttl_seconds=60,
        idempotency_key=key,
    )
    mid2, inserted2 = await mq.enqueue(
        db_session,
        session_id="sess-1", recipient_agent_id="r",
        sender_agent_id="s", ciphertext=b"c2-REPLAY", seq=1, ttl_seconds=60,
        idempotency_key=key,
    )
    assert inserted1 is True
    assert inserted2 is False
    assert mid1 == mid2  # canonical msg_id returned for the replay


@pytest.mark.asyncio
async def test_enqueue_same_key_different_recipient_both_succeed(db_session):
    """UNIQUE is (recipient, idempotency_key) — same key can target two peers."""
    key = "broadcast-1"
    mid_a, ia = await mq.enqueue(
        db_session,
        session_id="s", recipient_agent_id="A",
        sender_agent_id="origin", ciphertext=b"x", seq=0, ttl_seconds=60,
        idempotency_key=key,
    )
    mid_b, ib = await mq.enqueue(
        db_session,
        session_id="s", recipient_agent_id="B",
        sender_agent_id="origin", ciphertext=b"x", seq=0, ttl_seconds=60,
        idempotency_key=key,
    )
    assert ia is True and ib is True
    assert mid_a != mid_b


# ─────────────────────────────────────────────────────────────────────
# fetch + ack
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fetch_pending_returns_in_seq_order(db_session):
    for seq in (2, 0, 1):
        await mq.enqueue(
            db_session,
            session_id="sess-1", recipient_agent_id="r",
            sender_agent_id="s", ciphertext=b"c", seq=seq, ttl_seconds=60,
        )
    pending = await mq.fetch_pending_for_recipient(db_session, "r")
    assert [m.seq for m in pending] == [0, 1, 2]


@pytest.mark.asyncio
async def test_mark_delivered_removes_from_pending(db_session):
    mid, _ = await mq.enqueue(
        db_session,
        session_id="sess-1", recipient_agent_id="r",
        sender_agent_id="s", ciphertext=b"c", seq=0, ttl_seconds=60,
    )
    ok = await mq.mark_delivered(db_session, mid)
    assert ok is True
    # Second ack of the same msg: must NOT raise, but returns False
    again = await mq.mark_delivered(db_session, mid)
    assert again is False
    pending = await mq.fetch_pending_for_recipient(db_session, "r")
    assert pending == []


@pytest.mark.asyncio
async def test_mark_delivered_scoped_to_recipient_blocks_spoofing(db_session):
    mid, _ = await mq.enqueue(
        db_session,
        session_id="sess-1", recipient_agent_id="victim",
        sender_agent_id="s", ciphertext=b"c", seq=0, ttl_seconds=60,
    )
    # Attacker guesses msg_id but ack'ing with their own agent_id fails
    acked = await mq.mark_delivered(db_session, mid, recipient_agent_id="attacker")
    assert acked is False
    # Legitimate recipient can still ack
    acked = await mq.mark_delivered(db_session, mid, recipient_agent_id="victim")
    assert acked is True


# ─────────────────────────────────────────────────────────────────────
# sweep
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sweep_expired_flips_status_and_returns_notices(db_session):
    # Enqueue one fresh + one expired
    mid_fresh, _ = await mq.enqueue(
        db_session,
        session_id="s", recipient_agent_id="r",
        sender_agent_id="a", ciphertext=b"c", seq=0, ttl_seconds=60,
    )
    mid_exp, _ = await mq.enqueue(
        db_session,
        session_id="s", recipient_agent_id="r",
        sender_agent_id="a", ciphertext=b"c", seq=1, ttl_seconds=60,
    )
    # Force one row into the past
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    row = await db_session.get(ProxyMessageQueueRecord, mid_exp)
    row.ttl_expires_at = past
    await db_session.commit()

    notices = await mq.sweep_expired(db_session)
    assert len(notices) == 1
    assert notices[0].msg_id == mid_exp
    assert notices[0].sender_agent_id == "a"

    # Expired row is no longer in pending; fresh row is.
    pending = await mq.fetch_pending_for_recipient(db_session, "r")
    assert [p.msg_id for p in pending] == [mid_fresh]


@pytest.mark.asyncio
async def test_queue_depth_counts_only_pending(db_session):
    assert await mq.queue_depth_for_recipient(db_session, "r") == 0
    mid, _ = await mq.enqueue(
        db_session,
        session_id="s", recipient_agent_id="r",
        sender_agent_id="a", ciphertext=b"c", seq=0, ttl_seconds=60,
    )
    assert await mq.queue_depth_for_recipient(db_session, "r") == 1
    await mq.mark_delivered(db_session, mid)
    assert await mq.queue_depth_for_recipient(db_session, "r") == 0


@pytest.mark.asyncio
async def test_sweep_expired_concurrent_no_duplicate_notices():
    """L4-H5 regression: two concurrent sweep_expired calls on the same
    expired rows must together emit each msg_id EXACTLY ONCE.

    Two *separate* AsyncSession objects share the same in-memory SQLite DB
    to model the multi-worker scenario (each worker has its own session).
    SQLite serialises writes so the race is deterministic: the first
    sweeper's UPDATE claims all rows; the second's UPDATE matches 0 rows
    (delivery_status is no longer PENDING) and returns an empty list.
    The semantic invariant is: rowcount-as-truth means no duplicates.
    """
    import asyncio

    engine = create_async_engine(
        "sqlite+aiosqlite:///file:mq_concurrent?mode=memory&cache=shared&uri=true",
        future=True,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    # Seed expired rows using one session.
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    msg_ids = []
    async with maker() as seed_session:
        for i in range(3):
            mid, _ = await mq.enqueue(
                seed_session,
                session_id="s", recipient_agent_id="r",
                sender_agent_id="a", ciphertext=b"c", seq=i, ttl_seconds=1,
            )
            row = await seed_session.get(ProxyMessageQueueRecord, mid)
            row.ttl_expires_at = past
            msg_ids.append(mid)
        await seed_session.commit()

    # Open two independent sessions to simulate two sweeper workers.
    async with maker() as session_a, maker() as session_b:
        notices_a, notices_b = await asyncio.gather(
            mq.sweep_expired(session_a),
            mq.sweep_expired(session_b),
        )

    await engine.dispose()

    all_emitted = [n.msg_id for n in notices_a] + [n.msg_id for n in notices_b]

    # Every expired msg_id must appear at most once across both calls.
    assert len(all_emitted) == len(set(all_emitted)), (
        f"Duplicate expiry notices detected: {all_emitted}"
    )
    # And together they must cover all three expired messages.
    assert set(all_emitted) == set(msg_ids), (
        f"Expected all expired ids {msg_ids}, got {all_emitted}"
    )


@pytest.mark.asyncio
async def test_bump_attempts_increments_only_pending(db_session):
    mid, _ = await mq.enqueue(
        db_session,
        session_id="s", recipient_agent_id="r",
        sender_agent_id="a", ciphertext=b"c", seq=0, ttl_seconds=60,
    )
    await mq.bump_attempts(db_session, mid)
    await mq.bump_attempts(db_session, mid)
    row = await db_session.get(ProxyMessageQueueRecord, mid)
    await db_session.refresh(row)
    assert row.attempts == 2
    # After delivery, bump is a no-op
    await mq.mark_delivered(db_session, mid)
    await mq.bump_attempts(db_session, mid)
    await db_session.refresh(row)
    assert row.attempts == 2
