"""Tests for audit TSA anchoring + export bundle (issue #75 Slice 2)."""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import delete

from app.audit.tsa_client import (
    MockTsaClient,
    Rfc3161TsaClient,
    TimestampedAnchor,
    TsaClient,
    get_tsa_client,
)
from app.audit.tsa_worker import anchor_all_orgs_once
from app.db.audit import AuditLog, AuditTsaAnchor, log_event
from tests.conftest import TestSessionLocal


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def clean_audit():
    async with TestSessionLocal() as s:
        await s.execute(delete(AuditTsaAnchor))
        await s.execute(delete(AuditLog))
        await s.commit()
    yield
    async with TestSessionLocal() as s:
        await s.execute(delete(AuditTsaAnchor))
        await s.execute(delete(AuditLog))
        await s.commit()


# ── MockTsaClient unit ─────────────────────────────────────────────

async def test_mock_tsa_round_trip():
    c = MockTsaClient()
    anchor = await c.timestamp("deadbeef" * 8)
    assert isinstance(anchor, TimestampedAnchor)
    assert anchor.token.startswith(b"MK|")
    assert c.verify(anchor.token, "deadbeef" * 8) is True
    assert c.verify(anchor.token, "0" * 64) is False


async def test_mock_tsa_rejects_unknown_magic():
    c = MockTsaClient()
    assert c.verify(b"T1|garbage", "a" * 64) is False
    assert c.verify(b"random", "a" * 64) is False


async def test_rfc3161_client_skeleton_raises_without_lib(monkeypatch):
    """Without the optional rfc3161-client + httpx deps, timestamp()
    must raise a clear RuntimeError rather than failing cryptically."""
    import sys

    # Force import failure of rfc3161_client for this test
    monkeypatch.setitem(sys.modules, "rfc3161_client", None)
    c = Rfc3161TsaClient(url="http://test-tsa")
    with pytest.raises(RuntimeError, match="rfc3161-client"):
        await c.timestamp("ab" * 32)


# ── Factory ────────────────────────────────────────────────────────

def test_factory_picks_mock_by_default():
    class S:
        audit_tsa_backend = "mock"
        audit_tsa_url = "mock://x"
    assert isinstance(get_tsa_client(S()), MockTsaClient)


def test_factory_picks_rfc3161_when_configured():
    class S:
        audit_tsa_backend = "rfc3161"
        audit_tsa_url = "https://tsa.example/tsr"
    assert isinstance(get_tsa_client(S()), Rfc3161TsaClient)


def test_factory_falls_back_on_unknown_backend():
    class S:
        audit_tsa_backend = "typo"
        audit_tsa_url = ""
    assert isinstance(get_tsa_client(S()), MockTsaClient)


# ── Worker end-to-end with mock TSA ────────────────────────────────

async def test_anchor_all_orgs_once_creates_one_anchor_per_advanced_org(clean_audit):
    async with TestSessionLocal() as db:
        await log_event(db, "e", "ok", org_id="acme")
        await log_event(db, "e", "ok", org_id="acme")
        await log_event(db, "e", "ok", org_id="bravo")

    client = MockTsaClient()
    created = await anchor_all_orgs_once(client, session_factory=TestSessionLocal)
    assert created == 2  # one anchor per org

    async with TestSessionLocal() as db:
        anchors = (await db.execute(
            AuditTsaAnchor.__table__.select()
        )).all()
    by_org = {a.org_id: a for a in anchors}
    assert set(by_org) == {"acme", "bravo"}
    # acme anchor covers seq=2 (latest head)
    assert by_org["acme"].chain_seq == 2
    assert by_org["bravo"].chain_seq == 1


async def test_anchor_skips_orgs_without_new_events(clean_audit):
    client = MockTsaClient()
    async with TestSessionLocal() as db:
        await log_event(db, "e", "ok", org_id="acme")

    # First tick anchors org acme.
    c1 = await anchor_all_orgs_once(client, session_factory=TestSessionLocal)
    assert c1 == 1

    # No new events → second tick creates nothing.
    c2 = await anchor_all_orgs_once(client, session_factory=TestSessionLocal)
    assert c2 == 0


async def test_anchor_advances_on_new_entries(clean_audit):
    client = MockTsaClient()
    async with TestSessionLocal() as db:
        await log_event(db, "e", "ok", org_id="acme")
    await anchor_all_orgs_once(client, session_factory=TestSessionLocal)

    async with TestSessionLocal() as db:
        await log_event(db, "e", "ok", org_id="acme")
        await log_event(db, "e", "ok", org_id="acme")
    c = await anchor_all_orgs_once(client, session_factory=TestSessionLocal)
    assert c == 1  # new anchor for the advanced acme chain

    async with TestSessionLocal() as db:
        rows = (await db.execute(
            AuditTsaAnchor.__table__.select()
        )).all()
    seqs = sorted(r.chain_seq for r in rows)
    assert seqs == [1, 3]  # first anchor at seq=1, second at seq=3


async def test_anchor_token_verifies_against_stored_row_hash(clean_audit):
    client = MockTsaClient()
    async with TestSessionLocal() as db:
        entry = await log_event(db, "e", "ok", org_id="acme")

    await anchor_all_orgs_once(client, session_factory=TestSessionLocal)
    from sqlalchemy import select
    async with TestSessionLocal() as db:
        anchor = (await db.execute(select(AuditTsaAnchor))).scalars().one()

    # The stored token must verify against the anchored row_hash,
    # and the row_hash must match the actual chain head hash.
    assert client.verify(anchor.tsa_token, anchor.row_hash) is True
    assert anchor.row_hash == entry.entry_hash


# ── TSA failure resilience ─────────────────────────────────────────

class _BrokenTsa(TsaClient):
    url = "broken://x"
    async def timestamp(self, digest_hex):
        raise RuntimeError("TSA down")
    def verify(self, token, digest_hex):
        return False


async def test_start_worker_task_returns_cancellable_task(clean_audit):
    """Lifespan wiring: start_worker_task must return (task, stop_event)
    and stop cleanly when the event is set, without leaking a running
    loop. This mirrors how app.main.lifespan drives shutdown."""
    import asyncio
    from app.audit.tsa_worker import start_worker_task

    class _S:
        audit_tsa_backend = "mock"
        audit_tsa_url = "mock://x"
        audit_tsa_interval_seconds = 3600  # long — we'll cancel via event

    task, stop = start_worker_task(_S())
    try:
        # Let the first tick run (empty DB → no anchors, returns fast).
        await asyncio.sleep(0.05)
        stop.set()
        await asyncio.wait_for(task, timeout=2.0)
    finally:
        if not task.done():
            task.cancel()


async def test_worker_continues_when_tsa_fails(clean_audit):
    """TSA backend failure must not corrupt the chain nor raise out
    of the worker. Next tick retries."""
    async with TestSessionLocal() as db:
        await log_event(db, "e", "ok", org_id="acme")

    created = await anchor_all_orgs_once(
        _BrokenTsa(), session_factory=TestSessionLocal
    )
    assert created == 0  # failed gracefully

    async with TestSessionLocal() as db:
        n = (await db.execute(
            AuditTsaAnchor.__table__.select()
        )).all()
    assert len(n) == 0  # no bogus anchor persisted
