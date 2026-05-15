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


# ── #2 follow-up — cert+DPoP path stamps the contextvar ────────────


@pytest.mark.asyncio
async def test_get_agent_from_dpop_client_cert_stamps_contextvar(monkeypatch):
    """The cert + DPoP egress dep must set the per-request contextvar
    so ``log_audit()`` downstream picks the proof_jkt into
    ``audit_log.dpop_jkt``. Before this wire-up only the Bearer-DPoP
    (``dependencies.py``) and LOCAL_TOKEN (``local_agent_dep.py``)
    paths set it; cert+DPoP requests on ``/v1/chat/completions`` etc.
    landed audit rows with the column NULL.

    Patches the chain of dependencies down to ``verify_dpop_proof``
    so the test runs in-process without a real Mastio.
    """
    from unittest.mock import MagicMock

    from mcp_proxy.auth import dpop_client_cert
    from mcp_proxy.auth.dpop_context import (
        current_dpop_jkt, reset_dpop_jkt, set_dpop_jkt,
    )
    from mcp_proxy.models import InternalAgent

    # Isolate the test from any contextvar value leftover from a prior
    # test in this worker.
    token = set_dpop_jkt(None)
    try:
        fake_agent = InternalAgent(
            agent_id="org-x::alice",
            display_name="alice",
            capabilities=[],
            created_at="2026-05-15T00:00:00Z",
            is_active=True,
            cert_pem=None,
            dpop_jkt="THUMBPRINT_FROM_DB" + "0" * 25,
            reach="both",
        )

        async def _noop_api_token(_req):
            return None

        async def _noop_local_agent(_req):
            return None

        async def _fake_cert(_req):
            return fake_agent

        async def _fake_verify(*_a, **_kw):
            # Same jkt as stored so the pinning passes.
            return fake_agent.dpop_jkt

        # ``_maybe_api_token_principal`` is imported locally inside
        # the dep body (line 92), so patch the source module.
        import mcp_proxy.auth.api_token as _api_token_mod
        monkeypatch.setattr(
            _api_token_mod, "_maybe_api_token_principal", _noop_api_token,
        )
        # _maybe_local_internal_agent is imported locally inside the dep
        # at runtime, so patch its source module.
        import mcp_proxy.auth.local_agent_dep as _lad
        monkeypatch.setattr(
            _lad, "_maybe_local_internal_agent", _noop_local_agent,
        )
        monkeypatch.setattr(
            dpop_client_cert, "get_agent_from_client_cert", _fake_cert,
        )
        # Force ``optional`` so the missing-DPoP branch wouldn't short-
        # circuit; we'll supply a DPoP header below.
        monkeypatch.setenv("MCP_PROXY_EGRESS_DPOP_MODE", "optional")
        # Hide the original verify_dpop_proof behind a late-import shim
        # by patching it on its source module.
        import mcp_proxy.auth.dpop as _dpop_mod
        monkeypatch.setattr(_dpop_mod, "verify_dpop_proof", _fake_verify)

        req = MagicMock()
        req.method = "POST"
        req.headers = {"DPoP": "proof.proof.proof"}
        req.url = MagicMock()
        req.url.path = "/v1/llm/chat"

        agent = await dpop_client_cert.get_agent_from_dpop_client_cert(req)
        assert agent.agent_id == "org-x::alice"

        # Contextvar now carries the verified jkt.
        assert current_dpop_jkt() == fake_agent.dpop_jkt
    finally:
        reset_dpop_jkt(token)


@pytest.mark.asyncio
async def test_get_agent_from_dpop_client_cert_does_not_stamp_on_mismatch(
    monkeypatch,
):
    """When the proof jkt does NOT match the pinned dpop_jkt, the dep
    raises 401 BEFORE setting the contextvar. Audit rows for the
    rejected request must not carry a thumbprint the verifier just
    rejected — that would be misleading forensics."""
    from unittest.mock import MagicMock

    import pytest as _pytest
    from fastapi import HTTPException

    from mcp_proxy.auth import dpop_client_cert
    from mcp_proxy.auth.dpop_context import (
        current_dpop_jkt, reset_dpop_jkt, set_dpop_jkt,
    )
    from mcp_proxy.models import InternalAgent

    token = set_dpop_jkt(None)
    try:
        fake_agent = InternalAgent(
            agent_id="org-x::alice",
            display_name="alice",
            capabilities=[],
            created_at="2026-05-15T00:00:00Z",
            is_active=True,
            cert_pem=None,
            dpop_jkt="STORED_AND_PINNED" + "0" * 26,
            reach="both",
        )

        async def _noop(_req):
            return None

        async def _fake_cert(_req):
            return fake_agent

        async def _fake_verify_mismatch(*_a, **_kw):
            # Different jkt → pinning mismatch.
            return "EPHEMERAL_DIFFERENT_KEY" + "0" * 20

        import mcp_proxy.auth.api_token as _api_token_mod
        monkeypatch.setattr(
            _api_token_mod, "_maybe_api_token_principal", _noop,
        )
        import mcp_proxy.auth.local_agent_dep as _lad
        monkeypatch.setattr(
            _lad, "_maybe_local_internal_agent", _noop,
        )
        monkeypatch.setattr(
            dpop_client_cert, "get_agent_from_client_cert", _fake_cert,
        )
        monkeypatch.setenv("MCP_PROXY_EGRESS_DPOP_MODE", "required")
        import mcp_proxy.auth.dpop as _dpop_mod
        monkeypatch.setattr(
            _dpop_mod, "verify_dpop_proof", _fake_verify_mismatch,
        )

        req = MagicMock()
        req.method = "POST"
        req.headers = {"DPoP": "proof.proof.proof"}
        req.url = MagicMock()
        req.url.path = "/v1/llm/chat"

        with _pytest.raises(HTTPException) as ei:
            await dpop_client_cert.get_agent_from_dpop_client_cert(req)
        assert ei.value.status_code == 401
        # Contextvar still NOT stamped — the rejected jkt must not
        # bleed into any audit row written by a sibling task.
        assert current_dpop_jkt() is None
    finally:
        reset_dpop_jkt(token)
