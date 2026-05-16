"""Unit tests for ``mcp_proxy/audit_chain.py`` (F0.4 Tier 2 unlock).

The class is the centrepiece of ADR-033 batched audit chain. Six
gates:

1. Size threshold triggers a synchronous flush.
2. Periodic interval flushes a partial batch.
3. Post-batch ``verify_audit_chain`` still returns OK (hash chain
   integrity preserved across batches).
4. Concurrent appenders never break the chain (internal
   ``asyncio.Lock`` serialises hash computation, UNIQUE(chain_seq)
   retry catches cross-instance races).
5. ``stop()`` drains pending rows on shutdown — no in-memory rows lost
   during a clean stop.
6. ``batch_size=1`` is the per-row backward-compat opt-out and
   produces the same chain as the legacy ``log_audit()``.
"""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "f04_batched.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


def _row(agent_id: str = "alice", action: str = "t.invoke", **overrides):
    from datetime import datetime, timezone
    base = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "action": action,
        "tool_name": None,
        "status": "ok",
        "detail": None,
        "request_id": None,
        "duration_ms": None,
        "dpop_jkt": None,
    }
    base.update(overrides)
    return base


async def _count_chain_rows() -> int:
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT COUNT(*) FROM audit_log WHERE chain_seq IS NOT NULL"),
        )).first()
    return int(row[0])


# ── Gate 1: size-threshold flush ─────────────────────────────────────


@pytest.mark.asyncio
async def test_size_threshold_triggers_synchronous_flush(proxy_app):
    """append() into a batch_size=3 chain: the 3rd append flushes
    synchronously, so the row count reflects the batch immediately —
    no periodic task required."""
    from mcp_proxy.audit_chain import BatchedAuditChain

    chain = BatchedAuditChain(batch_size=3, flush_interval_s=60.0)

    await chain.append(_row(detail="row-0"))
    await chain.append(_row(detail="row-1"))
    # First two stay queued — DB still empty.
    assert chain.pending_count == 2
    assert await _count_chain_rows() == 0

    await chain.append(_row(detail="row-2"))
    # Third append crossed the threshold → synchronous flush.
    assert chain.pending_count == 0
    assert await _count_chain_rows() == 3


# ── Gate 2: periodic flush ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_periodic_flush_drains_partial_batch(proxy_app):
    """Low-throughput scenario: 2 rows in a batch_size=100 chain
    never trip the size threshold. The periodic task with a tight
    interval drains them anyway."""
    from mcp_proxy.audit_chain import BatchedAuditChain

    chain = BatchedAuditChain(batch_size=100, flush_interval_s=0.05)
    await chain.start()
    try:
        await chain.append(_row(detail="periodic-0"))
        await chain.append(_row(detail="periodic-1"))
        assert chain.pending_count == 2

        # Two flush ticks at 50ms each — generous slack for slow
        # CI runners.
        for _ in range(20):
            if await _count_chain_rows() == 2:
                break
            await asyncio.sleep(0.05)

        assert await _count_chain_rows() == 2
        assert chain.pending_count == 0
    finally:
        await chain.stop()


# ── Gate 3: chain integrity post-batch ──────────────────────────────


@pytest.mark.asyncio
async def test_verify_audit_chain_after_batch_flush(proxy_app):
    """25 rows through a batch_size=10 chain produce 3 batches
    (10 + 10 + 5). The hash chain crosses every batch boundary —
    verify_audit_chain walks the whole thing and returns OK."""
    from mcp_proxy.audit_chain import BatchedAuditChain
    from mcp_proxy.db import verify_audit_chain

    chain = BatchedAuditChain(batch_size=10, flush_interval_s=60.0)

    for i in range(25):
        await chain.append(_row(detail=f"row-{i:02d}"))
    await chain.flush_now()

    assert await _count_chain_rows() == 25
    ok, broken, reason = await verify_audit_chain()
    assert ok is True, f"chain broken at {broken}: {reason}"


# ── Gate 4: concurrent appenders ────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_appenders_preserve_chain_integrity(proxy_app):
    """100 concurrent append() tasks against a single
    BatchedAuditChain instance: the internal asyncio.Lock serialises
    queue mutation, and verify_audit_chain must still return OK after
    the final flush."""
    from mcp_proxy.audit_chain import BatchedAuditChain
    from mcp_proxy.db import verify_audit_chain

    chain = BatchedAuditChain(batch_size=10, flush_interval_s=60.0)

    async def _writer(i: int) -> None:
        await chain.append(_row(agent_id=f"a{i % 5}", detail=f"c-{i:03d}"))

    await asyncio.gather(*[_writer(i) for i in range(100)])
    await chain.flush_now()

    assert await _count_chain_rows() == 100
    ok, broken, reason = await verify_audit_chain()
    assert ok is True, f"chain broken at {broken}: {reason}"

    # Chain seq is monotonically increasing 1..100 with no gaps.
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT chain_seq FROM audit_log "
                "WHERE chain_seq IS NOT NULL ORDER BY chain_seq",
            ),
        )).all()
    assert [int(r[0]) for r in rows] == list(range(1, 101))


# ── Gate 5: shutdown drain ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_stop_drains_pending_rows(proxy_app):
    """5 rows queued under a batch_size=100 chain, then stop() called.
    No periodic flush task can possibly have fired (interval=60s) —
    the drain happens because stop() explicitly calls flush_now()."""
    from mcp_proxy.audit_chain import BatchedAuditChain

    chain = BatchedAuditChain(batch_size=100, flush_interval_s=60.0)
    await chain.start()

    for i in range(5):
        await chain.append(_row(detail=f"shutdown-{i}"))
    assert chain.pending_count == 5
    assert await _count_chain_rows() == 0

    await chain.stop()

    assert chain.pending_count == 0
    assert await _count_chain_rows() == 5


# ── Gate 6: batch_size=1 backward-compat ────────────────────────────


@pytest.mark.asyncio
async def test_batch_size_1_is_per_row_equivalent(proxy_app):
    """Compliance opt-out: ``batch_size=1`` flushes on every append
    and produces the same chain shape as the legacy per-row
    ``log_audit()`` — useful for customers that demand a per-row
    immutability proof."""
    from mcp_proxy.audit_chain import BatchedAuditChain
    from mcp_proxy.db import verify_audit_chain

    chain = BatchedAuditChain(batch_size=1, flush_interval_s=60.0)

    for i in range(3):
        await chain.append(_row(detail=f"per-row-{i}"))
        # Every append must have synchronously persisted to the DB —
        # no row should ever linger in _pending under batch_size=1.
        assert chain.pending_count == 0
        assert await _count_chain_rows() == i + 1

    ok, broken, reason = await verify_audit_chain()
    assert ok is True, f"chain broken at {broken}: {reason}"
