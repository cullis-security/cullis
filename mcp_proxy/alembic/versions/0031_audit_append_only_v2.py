"""Audit DB-level append-only enforcement + v2 hash format (CRIT-3).

Revision ID: 0031_audit_append_only_v2
Revises: 0030_user_pubkey_thumbprint
Create Date: 2026-05-11 21:00:00.000000

Audit ref: imp/audits/2026-05-11-MASTER.md CRIT-3 / Track 3 F-2.

Pre-CRIT-3 the ``local_audit`` table claimed "append-only" but every
row was inserted with a placeholder ``entry_hash=""`` and immediately
back-filled via ``UPDATE local_audit SET entry_hash WHERE id`` — the
application itself proved the schema accepted UPDATE on the
"append-only" table. An attacker with DB write credentials could
rewrite or delete rows undetected.

This migration:
1. Adds ``hash_format`` TEXT NULL — NULL or 'v1' for legacy rows that
   were back-filled, 'v2' for new rows inserted atomically with the
   hash already computed (no UPDATE).
2. Installs a BEFORE UPDATE OR DELETE trigger on ``local_audit`` that
   raises an error, blocking both attacker-driven mutation AND the
   pre-fix back-fill code path. Implemented in dialect-aware SQL:
   Postgres uses CREATE FUNCTION + CREATE TRIGGER; SQLite uses CREATE
   TRIGGER ... FOR EACH ROW BEGIN SELECT RAISE(...) END.

The trigger fires AFTER ``mcp_proxy/local/audit.py`` was refactored to
write the hash atomically on INSERT. Existing v1 rows are untouched
(no in-place migration to v2 — verify_local_chain dispatches on
``hash_format`` so legacy rows keep verifying with v1 inputs).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0031_audit_append_only_v2"
down_revision: Union[str, Sequence[str], None] = "0030_user_pubkey_thumbprint"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "local_audit"


_PG_TRIGGER_FN = """
CREATE OR REPLACE FUNCTION local_audit_no_mutate()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'local_audit is append-only (CRIT-3): % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_PG_TRIGGER = """
CREATE TRIGGER local_audit_no_update_or_delete
BEFORE UPDATE OR DELETE ON local_audit
FOR EACH ROW EXECUTE FUNCTION local_audit_no_mutate();
"""

_SQLITE_TRIGGER_UPDATE = """
CREATE TRIGGER IF NOT EXISTS local_audit_no_update
BEFORE UPDATE ON local_audit
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'local_audit is append-only (CRIT-3): UPDATE not permitted');
END;
"""

_SQLITE_TRIGGER_DELETE = """
CREATE TRIGGER IF NOT EXISTS local_audit_no_delete
BEFORE DELETE ON local_audit
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'local_audit is append-only (CRIT-3): DELETE not permitted');
END;
"""


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if _TABLE not in existing:
        # Cold-start install where 0009 never ran — nothing to harden,
        # later migrations will rebuild the table from scratch.
        return

    cols = {c["name"] for c in inspector.get_columns(_TABLE)}
    if "hash_format" not in cols:
        op.add_column(
            _TABLE,
            sa.Column("hash_format", sa.Text(), nullable=True),
        )

    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(_PG_TRIGGER_FN)
        # Drop any prior install of the trigger so this migration is
        # idempotent on environments that re-stamp.
        op.execute("DROP TRIGGER IF EXISTS local_audit_no_update_or_delete ON local_audit")
        op.execute(_PG_TRIGGER)
    elif dialect == "sqlite":
        op.execute(_SQLITE_TRIGGER_UPDATE)
        op.execute(_SQLITE_TRIGGER_DELETE)
    else:
        # Other dialects (mysql etc.) are not in scope for this audit
        # finding; document and continue. Future PR can extend.
        pass


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if _TABLE not in existing:
        return

    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS local_audit_no_update_or_delete ON local_audit")
        op.execute("DROP FUNCTION IF EXISTS local_audit_no_mutate()")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS local_audit_no_update")
        op.execute("DROP TRIGGER IF EXISTS local_audit_no_delete")

    cols = {c["name"] for c in inspector.get_columns(_TABLE)}
    if "hash_format" in cols:
        op.drop_column(_TABLE, "hash_format")
