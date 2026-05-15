"""P1.2 — DPoP jkt denormalized into ``audit_log``.

Two ways the column gets populated:

* explicit kwarg ``log_audit(..., dpop_jkt=<value>)`` — for callers
  that want to assert a specific thumbprint (audit replay, system
  tasks that synthesise a row from an out-of-band source).
* per-request contextvar set by the DPoP auth deps — the common path
  for live traffic, no per-callsite plumbing required.

These tests pin both. The forensic correlation column must never
participate in the hash chain (chain rewrites are dangerous on an
append-only ledger), so a parallel test asserts the chain hashes
unchanged whether or not ``dpop_jkt`` is populated.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "audit_jkt.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as _:
        async with app.router.lifespan_context(app):
            yield app
    get_settings.cache_clear()


async def _read_jkts(action: str = "test.action") -> list[str | None]:
    """Read the dpop_jkt column for every row produced by the test
    actions. Returned in chain_seq order so the assertions can pin
    "first row → expected, second row → expected" without sorting."""
    from mcp_proxy.db import get_db

    async with get_db() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT dpop_jkt FROM audit_log WHERE action=:a "
                    "ORDER BY chain_seq ASC"
                ),
                {"a": action},
            )
        ).fetchall()
    return [r[0] for r in rows]


# ── kwarg path: caller passes an explicit jkt ──────────────────────


@pytest.mark.asyncio
async def test_log_audit_persists_explicit_dpop_jkt(proxy_app):
    from mcp_proxy.db import log_audit

    await log_audit(
        agent_id="agent-1",
        action="test.action",
        status="success",
        dpop_jkt="abcd" * 16,
    )
    assert await _read_jkts() == ["abcd" * 16]


# ── contextvar path: auth dep stamps, log_audit reads ──────────────


@pytest.mark.asyncio
async def test_log_audit_reads_dpop_jkt_from_contextvar(proxy_app):
    """When no kwarg is passed, the contextvar set by the DPoP auth
    dependency wins. Simulates the live request path without spinning
    up the full auth stack."""
    from mcp_proxy.auth.dpop_context import set_dpop_jkt
    from mcp_proxy.db import log_audit

    set_dpop_jkt("deadbeef" * 8)
    try:
        await log_audit(
            agent_id="agent-2",
            action="test.action",
            status="success",
        )
    finally:
        set_dpop_jkt(None)

    assert await _read_jkts() == ["deadbeef" * 8]


@pytest.mark.asyncio
async def test_log_audit_kwarg_wins_over_contextvar(proxy_app):
    """When both are set, the explicit kwarg wins — useful for an
    audit replay that wants to assert the historical jkt rather than
    the current request's value."""
    from mcp_proxy.auth.dpop_context import set_dpop_jkt
    from mcp_proxy.db import log_audit

    set_dpop_jkt("from-ctx-var" + "0" * 52)
    try:
        await log_audit(
            agent_id="agent-3",
            action="test.action",
            status="success",
            dpop_jkt="from-kwarg" + "0" * 54,
        )
    finally:
        set_dpop_jkt(None)

    assert await _read_jkts() == ["from-kwarg" + "0" * 54]


@pytest.mark.asyncio
async def test_log_audit_null_when_no_context(proxy_app):
    """No kwarg, no contextvar → NULL. System / housekeeping rows
    look the same as pre-rollout rows; nothing fakes a thumbprint
    out of thin air."""
    from mcp_proxy.db import log_audit

    await log_audit(
        agent_id="agent-4",
        action="test.action",
        status="success",
    )
    assert await _read_jkts() == [None]


# ── chain invariant: dpop_jkt does NOT participate in the hash ─────


@pytest.mark.asyncio
async def test_dpop_jkt_does_not_enter_chain_hash(proxy_app):
    """Two rows with the same action / agent / status but different
    dpop_jkt values must produce identical row_hash values. Pinning
    this stops a future drive-by from accidentally re-anchoring the
    chain and breaking append-only verification on existing rows."""
    from mcp_proxy.db import get_db, log_audit
    from mcp_proxy.auth.dpop_context import set_dpop_jkt

    # First row: no jkt, NULL.
    await log_audit(
        agent_id="agent-chain",
        action="test.chain",
        status="success",
        request_id="req-1",
    )

    # Second row: with jkt set via contextvar.
    set_dpop_jkt("AA" * 32)
    try:
        await log_audit(
            agent_id="agent-chain",
            action="test.chain",
            status="success",
            request_id="req-1",
        )
    finally:
        set_dpop_jkt(None)

    async with get_db() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT chain_seq, row_hash, dpop_jkt FROM audit_log "
                    "WHERE action='test.chain' ORDER BY chain_seq ASC"
                )
            )
        ).fetchall()
    assert len(rows) == 2
    seq1, hash1, jkt1 = rows[0]
    seq2, hash2, jkt2 = rows[1]
    # Different jkt, same other inputs (plus prev_hash differs because
    # of the chain). The strong invariant we want is: row_hash is
    # *insensitive* to dpop_jkt. We assert it by recomputing the hash
    # with each row's stored values and confirming the recompute
    # agrees with the stored row_hash regardless of dpop_jkt.
    from mcp_proxy.db import compute_audit_row_hash

    async with get_db() as conn:
        timestamps = (
            await conn.execute(
                text(
                    "SELECT timestamp, prev_hash FROM audit_log "
                    "WHERE action='test.chain' ORDER BY chain_seq ASC"
                )
            )
        ).fetchall()
    (ts1, prev1), (ts2, prev2) = timestamps

    recomputed1 = compute_audit_row_hash(
        chain_seq=seq1, timestamp=ts1, agent_id="agent-chain",
        action="test.chain", tool_name=None, status="success",
        detail=None, request_id="req-1", prev_hash=prev1,
    )
    recomputed2 = compute_audit_row_hash(
        chain_seq=seq2, timestamp=ts2, agent_id="agent-chain",
        action="test.chain", tool_name=None, status="success",
        detail=None, request_id="req-1", prev_hash=prev2,
    )
    assert recomputed1 == hash1, "row 1 hash changed under dpop_jkt"
    assert recomputed2 == hash2, "row 2 hash changed under dpop_jkt"
    assert jkt1 is None and jkt2 == "AA" * 32
