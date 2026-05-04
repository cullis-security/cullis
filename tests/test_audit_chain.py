"""Tests for the audit log cryptographic hash chain."""
import pytest
import pytest_asyncio
from sqlalchemy import update

from app.db.audit import AuditLog, log_event, verify_chain, compute_entry_hash
from tests.conftest import TestSessionLocal

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def audit_db():
    """Provide a clean DB session with empty audit table."""
    from sqlalchemy import delete
    # Clean BEFORE to avoid pollution from other test modules
    async with TestSessionLocal() as session:
        await session.execute(delete(AuditLog))
        await session.commit()
    async with TestSessionLocal() as session:
        yield session
    # Clean AFTER as well
    async with TestSessionLocal() as session:
        await session.execute(delete(AuditLog))
        await session.commit()


async def test_log_event_creates_hash(audit_db):
    """First audit entry should have entry_hash and previous_hash=None."""
    entry = await log_event(audit_db, "test.event", "ok", details={"key": "val"})
    assert entry.entry_hash is not None
    assert len(entry.entry_hash) == 64  # SHA-256 hex
    assert entry.previous_hash is None


async def test_chain_linkage(audit_db):
    """Each entry's previous_hash must equal the prior entry's entry_hash."""
    e1 = await log_event(audit_db, "event.1", "ok")
    e2 = await log_event(audit_db, "event.2", "ok")
    e3 = await log_event(audit_db, "event.3", "denied")

    assert e1.previous_hash is None
    assert e2.previous_hash == e1.entry_hash
    assert e3.previous_hash == e2.entry_hash


async def test_hash_determinism(audit_db):
    """Recomputing the hash from entry fields must match entry_hash."""
    from datetime import timezone
    entry = await log_event(audit_db, "test.determinism", "ok",
                           agent_id="org::agent", session_id="sess-1",
                           org_id="org", details={"foo": "bar"})
    ts = entry.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    recomputed = compute_entry_hash(
        entry.id, ts, entry.event_type,
        entry.agent_id, entry.session_id, entry.org_id,
        entry.result, entry.details, entry.previous_hash,
        chain_seq=entry.chain_seq,
        peer_org_id=entry.peer_org_id,
    )
    assert entry.entry_hash == recomputed


async def test_verify_chain_valid(audit_db):
    """verify_chain on a valid chain returns (True, N, 0)."""
    for i in range(5):
        await log_event(audit_db, f"event.{i}", "ok")

    is_valid, total, broken_id = await verify_chain(audit_db)
    assert is_valid is True
    assert total == 5
    assert broken_id == 0


async def test_verify_chain_detects_tamper(audit_db):
    """Modifying an entry's details must break the chain."""
    await log_event(audit_db, "event.1", "ok", details={"original": True})
    e2 = await log_event(audit_db, "event.2", "ok")
    await log_event(audit_db, "event.3", "ok")

    # Tamper with entry 2's details
    await audit_db.execute(
        update(AuditLog).where(AuditLog.id == e2.id).values(details='{"tampered": true}')
    )
    await audit_db.commit()

    is_valid, total, broken_id = await verify_chain(audit_db)
    assert is_valid is False
    assert broken_id == e2.id


async def test_verify_chain_empty(audit_db):
    """verify_chain on empty table returns (True, 0, 0)."""
    is_valid, total, broken_id = await verify_chain(audit_db)
    assert is_valid is True
    assert total == 0
    assert broken_id == 0


# ── Per-org chain tests (hash chain split per org_id) ─────────────

async def test_per_org_chains_independent(audit_db):
    """Events for different orgs must land in different chains — an
    entry for org A does not link to the previous entry for org B."""
    a1 = await log_event(audit_db, "e1", "ok", org_id="acme")
    b1 = await log_event(audit_db, "e1", "ok", org_id="bravo")
    a2 = await log_event(audit_db, "e2", "ok", org_id="acme")
    b2 = await log_event(audit_db, "e2", "ok", org_id="bravo")

    # Genesis of each chain (seq=1) has no predecessor.
    assert a1.chain_seq == 1
    assert b1.chain_seq == 1
    assert a1.previous_hash is None
    assert b1.previous_hash is None

    # Second event per-org links to its own org's first event.
    assert a2.chain_seq == 2
    assert b2.chain_seq == 2
    assert a2.previous_hash == a1.entry_hash
    assert b2.previous_hash == b1.entry_hash


async def test_per_org_chain_seq_monotonic(audit_db):
    seqs = []
    for i in range(5):
        e = await log_event(audit_db, f"e{i}", "ok", org_id="acme")
        seqs.append(e.chain_seq)
    assert seqs == [1, 2, 3, 4, 5]


async def test_events_without_org_land_in_system_chain(audit_db):
    e1 = await log_event(audit_db, "sys.bootstrap", "ok")  # no org_id
    e2 = await log_event(audit_db, "sys.shutdown", "ok")
    assert e1.org_id == "__system__"
    assert e2.org_id == "__system__"
    assert e2.previous_hash == e1.entry_hash


async def test_verify_chain_per_org_filter(audit_db):
    """verify_chain(org_id=X) checks only that org, succeeds on valid."""
    for _ in range(3):
        await log_event(audit_db, "e", "ok", org_id="acme")
    for _ in range(3):
        await log_event(audit_db, "e", "ok", org_id="bravo")

    is_valid, total, _ = await verify_chain(audit_db, org_id="acme")
    assert is_valid is True
    assert total == 3


async def test_tamper_in_one_org_does_not_break_other(audit_db):
    """A broken chain in org A does not invalidate org B's chain."""
    await log_event(audit_db, "e1", "ok", org_id="acme")
    a2 = await log_event(audit_db, "e2", "ok", org_id="acme")
    await log_event(audit_db, "e1", "ok", org_id="bravo")
    await log_event(audit_db, "e2", "ok", org_id="bravo")

    # Tamper acme's row 2
    await audit_db.execute(
        update(AuditLog).where(AuditLog.id == a2.id).values(details='{"bad": 1}')
    )
    await audit_db.commit()

    # acme chain broken
    ok_a, _, broken = await verify_chain(audit_db, org_id="acme")
    assert ok_a is False
    assert broken == a2.id
    # bravo chain still intact
    ok_b, total_b, _ = await verify_chain(audit_db, org_id="bravo")
    assert ok_b is True
    assert total_b == 2


# ── Cross-org dual-write ──────────────────────────────────────────

async def test_cross_org_dual_write_creates_two_rows(audit_db):
    from app.db.audit import log_event_cross_org

    row_a, row_b = await log_event_cross_org(
        audit_db, "session.opened", "ok",
        org_a="acme", org_b="bravo",
        session_id="sess-xyz",
        details={"initiator": "acme::buyer", "target": "bravo::supplier"},
    )
    # Same logical fact recorded on both sides
    assert row_a.session_id == row_b.session_id
    assert row_a.details == row_b.details
    assert row_a.event_type == row_b.event_type
    # Distinct chains
    assert row_a.org_id == "acme"
    assert row_b.org_id == "bravo"
    assert row_a.chain_seq == 1
    assert row_b.chain_seq == 1
    # Cross-reference linkage in both directions
    assert row_a.peer_org_id == "bravo"
    assert row_b.peer_org_id == "acme"
    assert row_a.peer_row_hash == row_b.entry_hash
    assert row_b.peer_row_hash == row_a.entry_hash


async def test_cross_org_both_chains_verify(audit_db):
    from app.db.audit import log_event_cross_org

    await log_event_cross_org(
        audit_db, "session.opened", "ok",
        org_a="acme", org_b="bravo",
        details={"x": 1},
    )
    await log_event_cross_org(
        audit_db, "message.forwarded", "ok",
        org_a="acme", org_b="bravo",
        details={"payload_hash": "abc123"},
    )
    ok_a, total_a, _ = await verify_chain(audit_db, org_id="acme")
    ok_b, total_b, _ = await verify_chain(audit_db, org_id="bravo")
    assert ok_a is True and total_a == 2
    assert ok_b is True and total_b == 2


async def test_cross_org_requires_distinct_orgs(audit_db):
    from app.db.audit import log_event_cross_org

    with pytest.raises(ValueError, match="distinct"):
        await log_event_cross_org(
            audit_db, "x", "ok", org_a="acme", org_b="acme"
        )


async def test_cross_org_mixed_with_intra_org(audit_db):
    """A cross-org event and a subsequent intra-org event both chain
    correctly per-org (seq keeps going)."""
    from app.db.audit import log_event_cross_org

    await log_event_cross_org(
        audit_db, "e", "ok", org_a="acme", org_b="bravo"
    )
    intra = await log_event(audit_db, "intra", "ok", org_id="acme")
    assert intra.chain_seq == 2  # follows cross-org acme row at seq=1
    assert intra.previous_hash is not None

    ok, total, _ = await verify_chain(audit_db, org_id="acme")
    assert ok is True and total == 2


# ─────────────────────────────────────────────────────────────────────────────
# ADR-020 Phase 2 — principal_type column
# ─────────────────────────────────────────────────────────────────────────────


async def test_adr020_default_principal_type_is_agent(audit_db):
    """log_event without principal_type stores 'agent' (back-compat default)."""
    entry = await log_event(audit_db, "test.default", "ok", org_id="acme")
    assert entry.principal_type == "agent"


async def test_adr020_explicit_user_principal_type(audit_db):
    """A user-attributed event records principal_type='user'."""
    entry = await log_event(
        audit_db, "test.user", "ok",
        agent_id="acme::mario", org_id="acme",
        principal_type="user",
    )
    assert entry.principal_type == "user"


async def test_adr020_explicit_workload_principal_type(audit_db):
    entry = await log_event(
        audit_db, "test.workload", "ok",
        agent_id="acme::byoca-haiku", org_id="acme",
        principal_type="workload",
    )
    assert entry.principal_type == "workload"


async def test_adr020_agent_hash_unchanged_vs_pre_adr020(audit_db):
    """Crucially: an 'agent' row's entry_hash is byte-for-byte equal
    to what compute_entry_hash would produce WITHOUT principal_type
    (i.e. the pre-ADR-020 algorithm). This is the back-compat property
    that lets the column be added with no chain rewrite."""
    from datetime import timezone

    entry = await log_event(audit_db, "test.compat", "ok", org_id="acme",
                            principal_type="agent")
    ts = entry.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    recomputed_pre_adr = compute_entry_hash(
        entry.id, ts, entry.event_type,
        entry.agent_id, entry.session_id, entry.org_id,
        entry.result, entry.details, entry.previous_hash,
        chain_seq=entry.chain_seq,
        peer_org_id=entry.peer_org_id,
        # principal_type omitted — exactly the pre-ADR-020 call shape
    )
    recomputed_agent = compute_entry_hash(
        entry.id, ts, entry.event_type,
        entry.agent_id, entry.session_id, entry.org_id,
        entry.result, entry.details, entry.previous_hash,
        chain_seq=entry.chain_seq,
        peer_org_id=entry.peer_org_id,
        principal_type="agent",
    )
    assert recomputed_pre_adr == recomputed_agent == entry.entry_hash


async def test_adr020_user_hash_includes_principal_type_marker(audit_db):
    """A user row's canonical includes |pt=user, so its hash differs
    from the same row hashed as 'agent'. This is the chain-v2 marker."""
    from datetime import timezone

    entry = await log_event(
        audit_db, "test.usermark", "ok",
        agent_id="acme::mario", org_id="acme",
        principal_type="user",
    )
    ts = entry.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    hash_user = compute_entry_hash(
        entry.id, ts, entry.event_type,
        entry.agent_id, entry.session_id, entry.org_id,
        entry.result, entry.details, entry.previous_hash,
        chain_seq=entry.chain_seq,
        peer_org_id=entry.peer_org_id,
        principal_type="user",
    )
    hash_as_agent = compute_entry_hash(
        entry.id, ts, entry.event_type,
        entry.agent_id, entry.session_id, entry.org_id,
        entry.result, entry.details, entry.previous_hash,
        chain_seq=entry.chain_seq,
        peer_org_id=entry.peer_org_id,
        principal_type="agent",
    )
    assert hash_user == entry.entry_hash
    assert hash_user != hash_as_agent  # type marker actually changed the hash


async def test_adr020_verify_chain_mixed_principals(audit_db):
    """A chain that mixes user, agent, workload rows still verifies."""
    await log_event(audit_db, "e1", "ok", org_id="acme")  # agent default
    await log_event(audit_db, "e2", "ok", org_id="acme",
                    principal_type="user")
    await log_event(audit_db, "e3", "ok", org_id="acme",
                    principal_type="workload")
    await log_event(audit_db, "e4", "ok", org_id="acme",
                    principal_type="user")
    is_valid, total, broken_id = await verify_chain(audit_db, org_id="acme")
    assert is_valid is True
    assert total == 4
    assert broken_id == 0


async def test_adr020_cross_org_propagates_principal_type(audit_db):
    """log_event_cross_org tags both rows with the same principal_type."""
    from app.db.audit import log_event_cross_org

    row_a, row_b = await log_event_cross_org(
        audit_db, "u2u.message", "ok",
        org_a="acme", org_b="bravo",
        agent_id="acme::mario",
        principal_type="user",
    )
    assert row_a.principal_type == "user"
    assert row_b.principal_type == "user"
