"""Regression tests for audit race-safety fixes (F-D-1 + F-D-8).

F-D-1 — binding revocation lag: ``revoke_binding`` must also invalidate
the agent's active access tokens. Moving the invalidation INSIDE
``revoke_binding`` (rather than leaving it as a caller-responsibility)
closes the dashboard bypass path where the direct call did not chain
through ``invalidate_agent_tokens``.

F-D-8 — multi-worker audit chain: the ``UNIQUE(org_id, chain_seq)``
constraint + retry-on-IntegrityError in ``log_event`` must turn a
concurrent race into correctly-ordered rows with distinct sequence
numbers. Chain integrity must hold afterwards.
"""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.audit import AuditLog, log_event, verify_chain
from app.registry.binding_store import (
    BindingRecord,
    approve_binding,
    create_binding,
    revoke_binding,
)
from app.registry.store import AgentRecord
from tests.conftest import TestSessionLocal

pytestmark = pytest.mark.asyncio


# ────────────────────────────────────────────────────────────────────
# F-D-1 — revoke_binding must invalidate agent tokens
# ────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def race_db():
    """Session with the F-D-8 tables cleaned before + after."""
    async with TestSessionLocal() as session:
        await session.execute(delete(AuditLog))
        await session.execute(delete(BindingRecord))
        await session.execute(delete(AgentRecord))
        await session.commit()
    async with TestSessionLocal() as session:
        yield session
    async with TestSessionLocal() as session:
        await session.execute(delete(AuditLog))
        await session.execute(delete(BindingRecord))
        await session.execute(delete(AgentRecord))
        await session.commit()


@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
async def test_revoke_binding_sets_token_invalidated_at(race_db: AsyncSession):
    """Audit F-D-1: ``revoke_binding`` must stamp ``token_invalidated_at``
    on the agent row so tokens issued before the revoke fail the
    revocation check in ``get_current_agent``.

    The dashboard delete-agent / delete-org paths call ``revoke_binding``
    directly, without the per-endpoint ``invalidate_agent_tokens`` that
    the REST binding router adds on top. Moving the invalidation inside
    ``revoke_binding`` itself makes every caller automatically safe.
    """
    org_id = "fd1-org"
    agent_id = f"{org_id}::agent-1"

    # Seed an agent row — revoke_binding reads the agent to stamp it.
    agent = AgentRecord(
        agent_id=agent_id,
        org_id=org_id,
        display_name="FD1 agent",
        cert_pem="",
        capabilities_json="[]",
    )
    race_db.add(agent)
    binding = await create_binding(race_db, org_id, agent_id, ["cap.read"])
    await approve_binding(race_db, binding.id, "admin")

    # Sanity: no invalidation yet.
    fresh = (await race_db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one()
    assert fresh.token_invalidated_at is None

    # Dashboard path: call revoke_binding directly, NOT via the REST
    # router. The fix moves the invalidation into this function.
    revoked = await revoke_binding(race_db, binding.id)
    assert revoked is not None
    assert revoked.status == "revoked"

    # After revoke, the agent's token watermark is set.
    race_db.expire_all()
    updated = (await race_db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one()
    assert updated.token_invalidated_at is not None, (
        "revoke_binding must set token_invalidated_at on the agent row — "
        "otherwise the token retains broker capability for up to 60 min "
        "(audit F-D-1)"
    )


# ────────────────────────────────────────────────────────────────────
# F-D-8 — concurrent log_event from two independent sessions
# ────────────────────────────────────────────────────────────────────


@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
async def test_concurrent_log_event_produces_distinct_seq(race_db: AsyncSession):
    """Audit F-D-8, happy path under gather pressure.

    Fires N concurrent ``log_event`` calls (each with its own
    AsyncSession) for the same org and asserts distinct ``chain_seq``
    + intact hash chain. Within a single process the per-org
    ``asyncio.Lock`` already serialises these — so this test pins the
    correct single-worker behaviour. The multi-worker race is covered
    by ``test_log_event_retries_on_chain_seq_collision`` below, which
    manually forges a conflicting row to exercise the
    IntegrityError-retry path without spawning actual workers.
    """
    org_id = "fd8-org"
    n_concurrent = 8

    async def _one_write(i: int):
        async with TestSessionLocal() as s:
            return await log_event(
                s, f"fd8.evt.{i}", "ok", org_id=org_id
            )

    entries = await asyncio.gather(*[_one_write(i) for i in range(n_concurrent)])

    seqs = sorted(e.chain_seq for e in entries)
    assert seqs == list(range(1, n_concurrent + 1)), (
        f"expected distinct seqs 1..{n_concurrent}, got {seqs}"
    )
    # Chain integrity must hold across the concurrent batch.
    ok, total, broken = await verify_chain(race_db, org_id=org_id)
    assert ok is True, f"chain broken after concurrent writes at row {broken}"
    assert total == n_concurrent


@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
async def test_log_event_retries_on_chain_seq_collision(race_db: AsyncSession):
    """Audit F-D-8: simulate a multi-worker collision by inserting a row
    with the seq our next ``log_event`` will try, bypassing the
    process-local lock. The retry loop in ``log_event`` must catch the
    ``IntegrityError``, re-read the head, and land at the next seq.

    This is the path that single-process xdist tests cannot reach via
    ``asyncio.gather`` alone — the per-org lock serialises call-sites
    and only the DB-side UNIQUE can surface the race.
    """
    org_id = "fd8-retry-org"

    # Seed the chain with one entry so there's a head to read.
    e1 = await log_event(race_db, "seed", "ok", org_id=org_id)
    assert e1.chain_seq == 1

    # Manually insert the would-be next row (chain_seq=2) from a
    # separate session — this is what a second worker would do between
    # our read-of-head and our insert. The insert commits directly.
    async with TestSessionLocal() as interloper:
        rogue = AuditLog(
            event_type="rogue.worker",
            org_id=org_id,
            details=None,
            result="ok",
            previous_hash=e1.entry_hash,
            chain_seq=2,
            entry_hash="00" * 32,  # placeholder — we don't re-verify
        )
        interloper.add(rogue)
        await interloper.commit()

    # Now log_event must see chain_seq=2 is taken and retry at 3.
    # Using a fresh session so we don't reuse the cached read-head.
    async with TestSessionLocal() as s:
        entry = await log_event(s, "recover", "ok", org_id=org_id)
    # The retry path re-reads the head and picks the next available.
    assert entry.chain_seq == 3, (
        f"log_event failed to retry around conflicting seq=2; "
        f"got chain_seq={entry.chain_seq}"
    )


# ────────────────────────────────────────────────────────────────────
# F-D-8 — proxy-side twin: mcp_proxy.local.audit.append_local_audit
# ────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_audit_db(tmp_path):
    """Isolated proxy DB with the multi-worker migration applied."""
    from mcp_proxy.db import dispose_db, init_db

    db_file = tmp_path / "proxy-audit.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    yield url
    await dispose_db()


@pytest.mark.asyncio
@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
async def test_proxy_local_audit_unique_constraint_triggers_retry(proxy_audit_db):
    """Audit F-D-8 proxy twin: append_local_audit must retry on
    ``UNIQUE(org_id, chain_seq)`` collision (simulating a second worker
    that committed the next seq between our read and insert).
    """
    from sqlalchemy import text

    from mcp_proxy.db import get_db
    from mcp_proxy.local.audit import append_local_audit

    org_id = "proxy-fd8-org"

    # Seed one row via the public API so we have a chain head.
    first = await append_local_audit(event_type="seed", org_id=org_id)
    assert first["chain_seq"] == 1

    # Simulate a second worker: raw INSERT of seq=2 bypassing the
    # process-local lock.
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO local_audit (
                    timestamp, event_type, agent_id, session_id, org_id,
                    details, result, previous_hash, chain_seq,
                    peer_org_id, peer_row_hash, entry_hash
                ) VALUES (
                    :ts, 'rogue', NULL, NULL, :org_id,
                    NULL, 'ok', :prev, 2,
                    NULL, NULL, :eh
                )
                """
            ),
            {
                "ts": "2026-04-17T00:00:00+00:00",
                "org_id": org_id,
                "prev": first["entry_hash"],
                "eh": "aa" * 32,
            },
        )

    # Now ``append_local_audit`` must retry past seq=2.
    recovered = await append_local_audit(event_type="recover", org_id=org_id)
    assert recovered["chain_seq"] == 3, (
        f"expected retry to land at chain_seq=3, got {recovered['chain_seq']}"
    )
