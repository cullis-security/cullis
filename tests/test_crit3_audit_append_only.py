"""CRIT-3 — DB-level append-only enforcement on local_audit (Wave A PR5).

Audit ref: imp/audits/2026-05-11-track-3-audit-pdp.md F-2.

Pre-fix:
- ``local_audit`` claimed "append-only" but every row was inserted
  with placeholder ``entry_hash=""`` then back-filled via UPDATE in
  ``mcp_proxy/local/audit.py:172``. The application itself proved the
  schema accepted UPDATE on the table.
- An attacker with DB write credentials could rewrite or delete rows
  undetected.

Post-fix:
- ``compute_entry_hash_v2`` lets callers compute the hash without the
  DB-assigned ``entry_id`` (uses ``(org_id, chain_seq)`` instead).
- ``append_local_audit`` now writes the row atomically with the final
  hash + ``hash_format='v2'``; no back-fill UPDATE remains.
- Migration 0031 installs a BEFORE UPDATE / DELETE trigger on
  ``local_audit`` that raises an error, blocking both attacker-driven
  mutation AND any leftover application UPDATE attempt.
- ``verify_local_chain`` dispatches on ``hash_format`` so legacy v1
  rows keep verifying.
"""
from __future__ import annotations

import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.local.audit import append_local_audit, verify_local_chain
from mcp_proxy.local.audit_chain import (
    HASH_FORMAT_V2,
    compute_entry_hash_v2,
)

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def fresh_db(tmp_path, monkeypatch):
    db_file = tmp_path / "audit.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()


# ─── append_local_audit writes atomically with v2 hash ───


async def test_append_writes_v2_hash_format(fresh_db):
    summary = await append_local_audit(
        event_type="test.event",
        result="ok",
        org_id="acme",
        details={"k": "v"},
    )
    assert summary["chain_seq"] == 1
    assert summary["entry_hash"] != ""
    # Row stored with hash_format='v2'
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT entry_hash, hash_format FROM local_audit "
                " WHERE chain_seq = 1 AND org_id = 'acme'"
            ),
        )).first()
    assert row[0] == summary["entry_hash"]
    assert row[1] == HASH_FORMAT_V2


async def test_chain_seq_advances_per_org(fresh_db):
    s1 = await append_local_audit(event_type="e1", org_id="acme")
    s2 = await append_local_audit(event_type="e2", org_id="acme")
    s3 = await append_local_audit(event_type="e3", org_id="orga")
    assert (s1["chain_seq"], s2["chain_seq"]) == (1, 2)
    assert s3["chain_seq"] == 1  # different org, separate chain
    assert s2["previous_hash"] == s1["entry_hash"]
    # verify chain integrity
    ok, reason = await verify_local_chain("acme")
    assert ok, reason
    ok, reason = await verify_local_chain("orga")
    assert ok, reason


# ─── trigger blocks UPDATE / DELETE ───


async def test_trigger_blocks_update_on_local_audit(fresh_db):
    """The DB trigger installed by 0031 must reject any UPDATE on
    local_audit, even when the connecting role has write privilege.
    SQLite RAISE(ABORT) surfaces as IntegrityError; Postgres RAISE
    EXCEPTION surfaces as InternalError. Both subclass DBAPIError."""
    await append_local_audit(event_type="seed", org_id="acme")
    with pytest.raises(DBAPIError) as exc_info:
        async with get_db() as conn:
            await conn.execute(
                text(
                    "UPDATE local_audit SET entry_hash = 'tampered' "
                    " WHERE chain_seq = 1 AND org_id = 'acme'"
                )
            )
    msg = str(exc_info.value).lower()
    assert "append-only" in msg or "crit-3" in msg


async def test_trigger_blocks_delete_on_local_audit(fresh_db):
    """Same defence on DELETE."""
    await append_local_audit(event_type="seed", org_id="acme")
    with pytest.raises(DBAPIError) as exc_info:
        async with get_db() as conn:
            await conn.execute(
                text(
                    "DELETE FROM local_audit "
                    " WHERE chain_seq = 1 AND org_id = 'acme'"
                )
            )
    msg = str(exc_info.value).lower()
    assert "append-only" in msg or "crit-3" in msg


# ─── verify dispatches on hash_format ───


async def test_verify_dispatches_to_v1_for_legacy_row(fresh_db):
    """A row written with the v1 hash_format (entry_id-bound canonical
    string) must continue verifying via compute_entry_hash. We can't
    insert v1 directly through append_local_audit (which now writes v2),
    so we craft one with raw SQL to mimic a row written by an older
    Mastio. The trigger blocks UPDATE so we have to disable it for the
    setup, exercise verify, then re-enable."""
    from datetime import datetime, timezone
    from mcp_proxy.local.audit_chain import compute_entry_hash
    # Disable triggers for the setup-only insert (SQLite doesn't have
    # session-level toggle, so we DROP+recreate the triggers around
    # the legacy seed).
    async with get_db() as conn:
        await conn.execute(text("DROP TRIGGER IF EXISTS local_audit_no_update"))
        await conn.execute(text("DROP TRIGGER IF EXISTS local_audit_no_delete"))
    now = datetime.now(timezone.utc)
    # Raw INSERT mimicking the legacy back-fill path: insert with
    # placeholder, then UPDATE — produces a v1-style row.
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO local_audit "
                "(timestamp, event_type, agent_id, session_id, org_id, "
                " details, result, previous_hash, chain_seq, "
                " peer_org_id, peer_row_hash, entry_hash, hash_format) "
                "VALUES (:ts, 'legacy', NULL, NULL, 'legacyorg', NULL, "
                " 'ok', NULL, 1, NULL, NULL, '', NULL)"
            ),
            {"ts": now.isoformat()},
        )
        row = (await conn.execute(
            text(
                "SELECT id FROM local_audit WHERE org_id = 'legacyorg' "
                " AND chain_seq = 1"
            )
        )).first()
        row_id = row[0]
        v1_hash = compute_entry_hash(
            entry_id=row_id, timestamp=now, event_type="legacy",
            agent_id=None, session_id=None, org_id="legacyorg",
            result="ok", details=None, previous_hash=None,
            chain_seq=1, peer_org_id=None,
        )
        await conn.execute(
            text(
                "UPDATE local_audit SET entry_hash = :h WHERE id = :id"
            ),
            {"h": v1_hash, "id": row_id},
        )
    # verify dispatches to v1 for hash_format=NULL
    ok, reason = await verify_local_chain("legacyorg")
    assert ok, reason


async def test_verify_dispatches_to_v2_for_new_row(fresh_db):
    """A v2 row (default for new appends) must verify via compute_entry_hash_v2."""
    s = await append_local_audit(event_type="new", org_id="newco")
    ok, reason = await verify_local_chain("newco")
    assert ok, reason
    # Sanity check: the stored hash matches the v2 form
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT entry_hash, hash_format FROM local_audit "
                " WHERE org_id = 'newco' AND chain_seq = 1"
            )
        )).first()
    assert row[1] == HASH_FORMAT_V2
    assert row[0] == s["entry_hash"]


# ─── v1 vs v2 hash collision impossibility ───


def test_v1_v2_hash_forms_cryptographically_distinct():
    """The v2 canonical string starts with the literal ``"v2|"`` while
    v1 starts with an integer entry_id. SHA-256 collisions across
    distinct preimages are negligible — but the discriminator means
    the preimage spaces don't even overlap."""
    from datetime import datetime, timezone
    from mcp_proxy.local.audit_chain import compute_entry_hash
    ts = datetime(2026, 5, 11, 19, 0, 0, tzinfo=timezone.utc)
    v1 = compute_entry_hash(
        entry_id=42, timestamp=ts, event_type="x",
        agent_id=None, session_id=None, org_id="o",
        result="ok", details=None, previous_hash=None,
        chain_seq=1, peer_org_id=None,
    )
    v2 = compute_entry_hash_v2(
        timestamp=ts, event_type="x", agent_id=None, session_id=None,
        org_id="o", result="ok", details=None, previous_hash=None,
        chain_seq=1, peer_org_id=None,
    )
    assert v1 != v2
