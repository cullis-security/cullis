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
    # Tamper: simulate an attacker with raw DB write that bypasses the
    # CRIT-3 trigger (e.g. owns the DB host, dropped the trigger).
    # We drop the SQLite triggers locally then mutate; on Postgres the
    # equivalent owner-level DROP is the threat model. After the
    # mutation, ``verify_local_chain`` must detect the entry_hash
    # mismatch — the chain is the second layer of defence behind the
    # trigger.
    async with get_db() as conn:
        await conn.execute(text("DROP TRIGGER IF EXISTS local_audit_no_update"))
        await conn.execute(
            text("UPDATE local_audit SET details = :d WHERE chain_seq = 2"),
            {"d": '{"forged":true}'},
        )
    ok, reason = await verify_local_chain("acme")
    assert ok is False
    assert reason is not None
    assert "entry_hash mismatch" in reason


@pytest.mark.asyncio
@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
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


# ── F-A-410 — caller-controlled details payload cap ───────────────

@pytest.mark.asyncio
async def test_fa410_local_audit_oversized_details_rejected(fresh_db):
    """``append_local_audit`` rejects details > 16 KiB.

    Sister of ``app/db/audit.py::log_event`` — same cap, same reject
    semantics, no orphan row on rejection.
    """
    from mcp_proxy.local.audit import AUDIT_DETAILS_MAX_BYTES

    # 32 KiB blob — well above the 16 KiB cap.
    oversized = {"blob": "x" * (32 * 1024)}

    # Seed one valid row so we can prove no extra row landed.
    seed = await append_local_audit(event_type="seed", org_id="acme")

    with pytest.raises(RuntimeError, match="audit details too large"):
        await append_local_audit(
            event_type="over_cap",
            org_id="acme",
            details=oversized,
        )

    async with get_db() as conn:
        cnt = (await conn.execute(
            text("SELECT COUNT(*) FROM local_audit WHERE org_id = :o"),
            {"o": "acme"},
        )).scalar_one()
    assert cnt == 1, "rejected call must not write a row"
    assert seed["chain_seq"] == 1
    assert AUDIT_DETAILS_MAX_BYTES == 16 * 1024


@pytest.mark.asyncio
async def test_fa410_local_audit_under_cap_accepted(fresh_db):
    """8 KiB details payload appends normally (well under the cap)."""
    payload = {"blob": "x" * (8 * 1024)}
    entry = await append_local_audit(
        event_type="under_cap",
        org_id="acme",
        details=payload,
    )
    assert entry["chain_seq"] == 1
    assert entry["entry_hash"] is not None
