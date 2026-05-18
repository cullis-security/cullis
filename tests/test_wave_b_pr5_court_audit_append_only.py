"""Wave B PR5 — Court-side CRIT-3 mirror.

Audit ref: imp/audits/2026-05-11-track-3-audit-pdp.md F-2 (Court half).

Pre-fix the broker ``audit_log`` table back-filled ``entry_hash`` via
UPDATE after a flush(). Post-fix the row is inserted atomically with
the v2 hash already computed; a BEFORE UPDATE/DELETE trigger blocks
both attacker mutation and the legacy back-fill simultaneously.

Note on test setup: ``tests/conftest.py`` bypasses Alembic in test
mode (``SKIP_ALEMBIC=1``) and bootstraps the schema via
``Base.metadata.create_all``. That path does not run the
``q7l8m9n0o1p2_audit_append_only`` migration's trigger DDL, so the
trigger-coverage tests below install the triggers inline using the
same SQL the migration emits for SQLite.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import text


pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.xdist_group(name="serial_wave_b_pr5_court_audit_append_only"),
]


_SQLITE_TRIGGER_SQL = [
    """
    CREATE TRIGGER IF NOT EXISTS audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only (CRIT-3 Court): UPDATE not permitted');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only (CRIT-3 Court): DELETE not permitted');
    END
    """,
]


async def _install_triggers(db) -> None:
    """Install the SQLite trigger SQL the migration would have emitted.
    No-op on Postgres (those tests would need the alembic chain).
    Idempotent (uses CREATE TRIGGER IF NOT EXISTS)."""
    bind = db.get_bind()
    if bind.dialect.name != "sqlite":
        return
    for sql in _SQLITE_TRIGGER_SQL:
        await db.execute(text(sql))
    await db.commit()


@pytest_asyncio.fixture(autouse=True)
async def _drop_audit_log_triggers_after_test():
    """The append-only triggers installed by ``_install_triggers`` use
    ``CREATE TRIGGER IF NOT EXISTS`` on the session-scoped ``:memory:``
    SQLite (one DB per xdist worker process). Without an explicit DROP
    they survive into the next test on the same worker, which then sees
    ``DELETE FROM audit_log`` rejected with ``RAISE(ABORT)`` —
    deterministically breaking ``test_audit_export_tsa`` and the
    conftest auto-wipe fixture.

    ``--dist=loadfile`` used to mask this because audit-related tests
    landed on a dedicated worker; ``loadgroup`` distributes more
    aggressively and surfaces the leak.
    """
    yield
    from app.db.database import get_db
    async for db in get_db():
        bind = db.get_bind()
        if bind.dialect.name != "sqlite":
            break
        await db.execute(text("DROP TRIGGER IF EXISTS audit_log_no_update"))
        await db.execute(text("DROP TRIGGER IF EXISTS audit_log_no_delete"))
        await db.commit()
        break


async def test_log_event_writes_v2_hash_format(client):
    from app.db.audit import HASH_FORMAT_V2, log_event
    from app.db.database import get_db

    async for db in get_db():
        entry = await log_event(
            db,
            event_type="court.test",
            result="ok",
            org_id="acme",
        )
        assert entry.entry_hash != ""
        assert entry.hash_format == HASH_FORMAT_V2
        break


async def test_chain_seq_advances_per_org(client):
    from app.db.audit import log_event, verify_chain
    from app.db.database import get_db

    # Use a fresh org id so this test doesn't interleave with rows
    # from other tests sharing the in-memory DB.
    org = "wave-b-pr5-chainseq"
    async for db in get_db():
        e1 = await log_event(db, event_type="e1", result="ok", org_id=org)
        e2 = await log_event(db, event_type="e2", result="ok", org_id=org)
        assert (e1.chain_seq, e2.chain_seq) == (1, 2)
        assert e2.previous_hash == e1.entry_hash
        ok, _checked, _broken = await verify_chain(db, org_id=org)
        assert ok, _broken
        break


async def test_trigger_blocks_update_on_audit_log(client):
    """Attacker with DB write tries to UPDATE entry_hash. Trigger
    installed by the new Court migration must reject it."""
    from sqlalchemy.exc import DBAPIError

    from app.db.audit import log_event
    from app.db.database import get_db

    org = "wave-b-pr5-trigupd"
    async for db in get_db():
        await _install_triggers(db)
        await log_event(db, event_type="seed", result="ok", org_id=org)
        with pytest.raises(DBAPIError) as exc_info:
            await db.execute(
                text(
                    "UPDATE audit_log SET entry_hash = 'tampered' "
                    " WHERE org_id = :o"
                ),
                {"o": org},
            )
            await db.commit()
        msg = str(exc_info.value).lower()
        assert "append-only" in msg or "crit-3" in msg
        await db.rollback()
        break


async def test_trigger_blocks_delete_on_audit_log(client):
    from sqlalchemy.exc import DBAPIError

    from app.db.audit import log_event
    from app.db.database import get_db

    org = "wave-b-pr5-trigdel"
    async for db in get_db():
        await _install_triggers(db)
        await log_event(db, event_type="seed", result="ok", org_id=org)
        with pytest.raises(DBAPIError) as exc_info:
            await db.execute(
                text(
                    "DELETE FROM audit_log WHERE org_id = :o"
                ),
                {"o": org},
            )
            await db.commit()
        msg = str(exc_info.value).lower()
        assert "append-only" in msg or "crit-3" in msg
        await db.rollback()
        break


async def test_v1_v2_hash_forms_are_distinct():
    """The v2 canonical string starts with literal ``v2|``; v1 starts
    with an integer entry_id. Cryptographic distinction by preimage
    space, not just by SHA-256 collision resistance."""
    from datetime import datetime, timezone

    from app.db.audit import compute_entry_hash, compute_entry_hash_v2

    ts = datetime(2026, 5, 11, 22, 0, 0, tzinfo=timezone.utc)
    v1 = compute_entry_hash(
        entry_id=42, timestamp=ts, event_type="x",
        agent_id=None, session_id=None, org_id="o",
        result="ok", details=None, previous_hash=None,
        chain_seq=1, peer_org_id=None,
    )
    v2 = compute_entry_hash_v2(
        timestamp=ts, event_type="x",
        agent_id=None, session_id=None, org_id="o",
        result="ok", details=None, previous_hash=None,
        chain_seq=1, peer_org_id=None,
    )
    assert v1 != v2


async def test_cross_org_dual_write_no_back_fill(client):
    """Wave B PR5 (CRIT-3 Court) — log_event_cross_org used to back-fill
    row_first.peer_row_hash after row_second was inserted. The trigger
    blocked that UPDATE. Post-fix the back-fill is gone (peer_row_hash
    on row_first stays NULL); row_second still carries the cross-ref
    via peer_row_hash=row_first.entry_hash at INSERT time."""
    from app.db.audit import log_event_cross_org
    from app.db.database import get_db

    async for db in get_db():
        row_a, row_b = await log_event_cross_org(
            db,
            event_type="cross.test",
            result="ok",
            org_a="orga",
            org_b="orgb",
        )
        # One side (whichever sorts second by org_id) carries the link.
        # The other side stays NULL — accepted asymmetry per code
        # comment block.
        assert row_a.entry_hash is not None
        assert row_b.entry_hash is not None
        # At least one of the two has peer_row_hash filled.
        assert (row_a.peer_row_hash is not None) or (
            row_b.peer_row_hash is not None
        )
        break
