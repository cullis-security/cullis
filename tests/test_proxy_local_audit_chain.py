"""ADR-006 Fase 1 / PR #2 — proxy writes hash-chained entries to local_audit.

Verifies:
  - append_local_audit inserts rows with byte-compatible entry_hash
    (matching mcp_proxy.local.audit_chain.compute_entry_hash)
  - chain_seq is monotonic per org; each row's previous_hash matches
    the prior row's entry_hash
  - verify_local_chain returns (True, None) on clean data and
    (False, <reason>) after tampering
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.local.audit import append_local_audit, verify_local_chain


@pytest_asyncio.fixture
async def fresh_db(tmp_path):
    db_file = tmp_path / "audit.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    yield
    await dispose_db()


@pytest.mark.asyncio
async def test_first_append_is_genesis(fresh_db):
    entry = await append_local_audit(
        event_type="session_opened",
        org_id="acme",
        agent_id="alice",
        session_id="s1",
    )
    assert entry["chain_seq"] == 1
    assert entry["previous_hash"] is None
    assert len(entry["entry_hash"]) == 64  # SHA-256 hex


@pytest.mark.asyncio
async def test_second_append_chains_to_first(fresh_db):
    first = await append_local_audit(event_type="session_opened", org_id="acme")
    second = await append_local_audit(
        event_type="message_sent",
        org_id="acme",
        details={"msg_id": "m1"},
    )
    assert second["chain_seq"] == 2
    assert second["previous_hash"] == first["entry_hash"]


@pytest.mark.asyncio
async def test_per_org_chains_are_independent(fresh_db):
    acme1 = await append_local_audit(event_type="session_opened", org_id="acme")
    contoso1 = await append_local_audit(event_type="session_opened", org_id="contoso")
    acme2 = await append_local_audit(event_type="session_closed", org_id="acme")
    assert acme1["chain_seq"] == 1
    assert contoso1["chain_seq"] == 1
    assert acme2["chain_seq"] == 2
    assert acme2["previous_hash"] == acme1["entry_hash"]


@pytest.mark.asyncio
async def test_verify_local_chain_intact(fresh_db):
    for i in range(5):
        await append_local_audit(
            event_type="message_sent",
            org_id="acme",
            agent_id=f"alice-{i}",
            details={"seq": i},
        )
    ok, reason = await verify_local_chain("acme")
    assert ok is True
    assert reason is None


@pytest.mark.asyncio
async def test_verify_local_chain_detects_tampering(fresh_db):
    await append_local_audit(event_type="session_opened", org_id="acme")
    await append_local_audit(event_type="message_sent", org_id="acme")
    # Tamper: rewrite details on the second row so the stored entry_hash
    # no longer matches the canonical recomputation.
    async with get_db() as conn:
        await conn.execute(
            text("UPDATE local_audit SET details = :d WHERE chain_seq = 2"),
            {"d": '{"forged":true}'},
        )
    ok, reason = await verify_local_chain("acme")
    assert ok is False
    assert reason is not None
    assert "entry_hash mismatch" in reason


@pytest.mark.asyncio
async def test_concurrent_appends_keep_chain_monotonic(fresh_db):
    import asyncio

    # 20 concurrent appends must still produce a strictly increasing
    # chain_seq with no duplicates and no gaps.
    results = await asyncio.gather(
        *[
            append_local_audit(event_type="message_sent", org_id="acme", details={"i": i})
            for i in range(20)
        ]
    )
    seqs = sorted(r["chain_seq"] for r in results)
    assert seqs == list(range(1, 21))
    ok, reason = await verify_local_chain("acme")
    assert ok is True, reason
