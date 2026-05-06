"""
H4 lane7 regression: mcp_proxy ``audit_log`` carries a forward-integrity
hash chain, like the Court does.

The Mastio's audit table used to be a straight append — rows had a
timestamp but no link backwards. SECURITY.md claimed an "append-only
cryptographic audit log" which the Court enforces (per-org chain in
``app/db/audit.py``) but the Mastio did not. An operator with DB
write access could rewrite an old detail field, drop a row, or splice
in a forged row, and the table itself wouldn't reveal it.

This file locks in:

- Every new row gets a monotonically-increasing ``chain_seq``, a
  ``prev_hash`` linking to the previous row's ``row_hash``, and a
  ``row_hash`` over a canonical encoding of every authoritative field.
- ``verify_audit_chain()`` walks the chain and surfaces the first
  break (recomputed hash mismatch, prev_hash mismatch, sequence gap).
- Tampering with ANY field of an existing row makes verify fail at
  that row's chain_seq.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "h4_audit.sqlite"
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


# ── Chain growth ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_log_audit_assigns_monotonic_chain_seq(proxy_app):
    _, _ = proxy_app
    from mcp_proxy.db import get_db, log_audit
    from sqlalchemy import text

    for i in range(3):
        await log_audit(agent_id="alice", action="t.invoke", status="ok",
                        detail=f"row-{i}")

    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT chain_seq, prev_hash, row_hash FROM audit_log "
                "WHERE chain_seq IS NOT NULL ORDER BY chain_seq",
            ),
        )).all()

    assert len(rows) == 3
    assert [r[0] for r in rows] == [1, 2, 3]
    assert rows[0][1] == "genesis"
    assert rows[1][1] == rows[0][2]
    assert rows[2][1] == rows[1][2]
    # row_hash values are unique
    assert len({r[2] for r in rows}) == 3


@pytest.mark.asyncio
async def test_verify_chain_returns_ok_on_clean_log(proxy_app):
    _, _ = proxy_app
    from mcp_proxy.db import log_audit, verify_audit_chain

    for i in range(5):
        await log_audit(agent_id="alice", action="t.invoke", status="ok",
                        detail=f"row-{i}")

    ok, broken, reason = await verify_audit_chain()
    assert ok is True, f"clean chain should verify (broken={broken} reason={reason})"


# ── Tamper detection ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_chain_catches_detail_tamper(proxy_app):
    _, _ = proxy_app
    from mcp_proxy.db import get_db, log_audit, verify_audit_chain
    from sqlalchemy import text

    for i in range(5):
        await log_audit(agent_id="alice", action="t.invoke", status="ok",
                        detail=f"row-{i}")

    # Rewrite row 3's detail without touching row_hash — the kind of
    # mutation an operator with DB write access could do.
    async with get_db() as conn:
        await conn.execute(
            text("UPDATE audit_log SET detail = 'rewritten' WHERE chain_seq = 3"),
        )

    ok, broken, reason = await verify_audit_chain()
    assert ok is False
    assert broken == 3
    assert reason is not None and "row_hash mismatch" in reason


@pytest.mark.asyncio
async def test_verify_chain_catches_dropped_row(proxy_app):
    _, _ = proxy_app
    from mcp_proxy.db import get_db, log_audit, verify_audit_chain
    from sqlalchemy import text

    for i in range(5):
        await log_audit(agent_id="alice", action="t.invoke", status="ok",
                        detail=f"row-{i}")

    async with get_db() as conn:
        await conn.execute(
            text("DELETE FROM audit_log WHERE chain_seq = 3"),
        )

    ok, broken, reason = await verify_audit_chain()
    assert ok is False
    assert broken == 4
    assert reason is not None and (
        "chain_seq gap" in reason or "prev_hash mismatch" in reason
    )


@pytest.mark.asyncio
async def test_verify_chain_catches_prev_hash_tamper(proxy_app):
    """An attacker who recomputes row_hash for a tampered row but
    forgets to fix the next row's prev_hash is caught at seq+1."""
    _, _ = proxy_app
    from mcp_proxy.db import (
        compute_audit_row_hash, get_db, log_audit, verify_audit_chain,
    )
    from sqlalchemy import text

    for i in range(5):
        await log_audit(agent_id="alice", action="t.invoke", status="ok",
                        detail=f"row-{i}")

    # Rewrite row 3's detail AND fix its row_hash to match — but
    # leave row 4's prev_hash untouched. The chain walker should
    # flag row 4 as the break point.
    async with get_db() as conn:
        row3 = (await conn.execute(
            text(
                "SELECT timestamp, agent_id, action, tool_name, status, "
                "detail, request_id, prev_hash FROM audit_log WHERE chain_seq = 3",
            ),
        )).first()
        new_hash = compute_audit_row_hash(
            chain_seq=3,
            timestamp=str(row3[0]),
            agent_id=str(row3[1]),
            action=str(row3[2]),
            tool_name=row3[3],
            status=str(row3[4]),
            detail="rewritten",
            request_id=row3[6],
            prev_hash=str(row3[7]),
        )
        await conn.execute(
            text(
                "UPDATE audit_log SET detail = 'rewritten', row_hash = :h "
                "WHERE chain_seq = 3",
            ),
            {"h": new_hash},
        )

    ok, broken, reason = await verify_audit_chain()
    assert ok is False
    assert broken == 4
    assert reason is not None and "prev_hash mismatch" in reason


# ── Existing log_audit callers keep working ───────────────────────────


@pytest.mark.asyncio
async def test_existing_audit_query_pattern_still_works(proxy_app):
    """Other code reads ``audit_log`` by ``timestamp`` + ``request_id``;
    the new chain columns must not break those queries."""
    _, _ = proxy_app
    from mcp_proxy.db import get_db, log_audit
    from sqlalchemy import text

    await log_audit(agent_id="alice", action="t.invoke", status="ok",
                    request_id="req-abc")

    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT agent_id, action, status FROM audit_log "
                "WHERE request_id = :rid",
            ),
            {"rid": "req-abc"},
        )).first()

    assert row is not None
    assert (row[0], row[1], row[2]) == ("alice", "t.invoke", "ok")


# ── Phase A.1: structured details kwarg ───────────────────────────────


@pytest.mark.asyncio
async def test_log_audit_details_dict_serialised_to_canonical_json(proxy_app):
    """``details`` is canonical JSON (sort_keys, no whitespace) so
    downstream consumers can rely on byte-stable serialisation across
    workers and Python versions."""
    import json as _json

    _, _ = proxy_app
    from mcp_proxy.db import get_db, log_audit
    from sqlalchemy import text

    await log_audit(
        agent_id="alice", action="egress_llm_chat", status="success",
        details={
            "event": "llm.chat_completion",
            "model": "claude-haiku-4-5",
            "prompt_tokens": 12,
            "completion_tokens": 3,
            "cost_usd": 0.000123,
            "cache_hit": False,
        },
    )

    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT detail FROM audit_log WHERE action = :a"),
            {"a": "egress_llm_chat"},
        )).first()

    assert row is not None
    raw = row[0]
    assert raw.startswith("{") and raw.endswith("}")
    parsed = _json.loads(raw)
    assert parsed["model"] == "claude-haiku-4-5"
    assert parsed["cost_usd"] == 0.000123
    assert parsed["cache_hit"] is False
    keys = list(parsed.keys())
    assert keys == sorted(keys), "details must be serialised with sort_keys"


@pytest.mark.asyncio
async def test_log_audit_details_wins_over_detail_string(proxy_app):
    """If both ``detail`` and ``details`` are passed the dict wins; this
    keeps the call site single-source-of-truth and avoids two
    representations diverging in the audit row."""
    import json as _json

    _, _ = proxy_app
    from mcp_proxy.db import get_db, log_audit
    from sqlalchemy import text

    await log_audit(
        agent_id="alice", action="t.invoke", status="ok",
        detail="legacy human readable",
        details={"x": 1, "y": "two"},
    )

    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT detail FROM audit_log WHERE action = :a"),
            {"a": "t.invoke"},
        )).first()

    parsed = _json.loads(row[0])
    assert parsed == {"x": 1, "y": "two"}


@pytest.mark.asyncio
async def test_log_audit_details_chain_still_verifies(proxy_app):
    """The hash chain treats ``detail`` (now JSON) the same as before:
    ``verify_audit_chain`` must walk a mixed chain (legacy strings +
    structured JSON rows) without breaks."""
    _, _ = proxy_app
    from mcp_proxy.db import log_audit, verify_audit_chain

    await log_audit(agent_id="alice", action="t.invoke", status="ok",
                    detail="legacy")
    await log_audit(agent_id="alice", action="egress_llm_chat", status="success",
                    details={"event": "llm.chat_completion", "cost_usd": 0.5})
    await log_audit(agent_id="bob", action="t.invoke", status="ok",
                    detail="legacy 2")

    ok, broken, reason = await verify_audit_chain()
    assert ok is True, f"chain broken at {broken}: {reason}"
