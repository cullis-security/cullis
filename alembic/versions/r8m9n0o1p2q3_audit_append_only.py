"""Court-side audit_log append-only enforcement (Wave B PR5 / CRIT-3).

Revision ID: q7l8m9n0o1p2
Revises: p6k7l8m9n0o1
Create Date: 2026-05-11 23:30:00.000000

Audit ref: imp/audits/2026-05-11-track-3-audit-pdp.md F-2 (Court-side
mirror — Mastio twin landed as ``0031_audit_append_only_v2``).

Pre-fix the Court ``audit_log`` table claimed "append-only" but
``_append_row`` inserted the row, ``flush()``'d to get the auto-
assigned ``id``, then UPDATE'd to back-fill ``entry_hash``. An
attacker with DB write credentials could rewrite or delete rows
undetected; detection was opt-in (operator clicks "verify chain").

This migration:
1. Adds ``hash_format`` TEXT NULL on ``audit_log``. NULL or 'v1' for
   legacy rows back-filled the old way; 'v2' for new rows inserted
   atomically with the hash already computed (no UPDATE).
2. Installs a BEFORE UPDATE OR DELETE trigger on ``audit_log`` that
   raises an error, blocking both attacker mutation AND the pre-fix
   back-fill code path. Implemented in dialect-aware SQL:
   Postgres uses CREATE FUNCTION + CREATE TRIGGER; SQLite uses
   CREATE TRIGGER ... SELECT RAISE(ABORT, ...).
3. The same trigger is installed on ``audit_tsa_anchors`` because
   the per-org TSA anchor row is similarly meant to be immutable
   once written.

The trigger fires AFTER ``app/db/audit.py:_append_row`` was
refactored to write the hash atomically on INSERT. Existing v1 rows
are untouched (no in-place migration to v2 — verify_chain dispatches
on ``hash_format`` so legacy rows keep verifying with v1 inputs).
"""
from alembic import op
import sqlalchemy as sa


revision = "r8m9n0o1p2q3_audit"
down_revision = "q7l8m9n0o1p2"
branch_labels = None
depends_on = None


_TABLES = ("audit_log", "audit_tsa_anchors")


def _pg_trigger_fn(table: str) -> str:
    return f"""
CREATE OR REPLACE FUNCTION {table}_no_mutate()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        '{table} is append-only (CRIT-3 Court): % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;
"""


def _pg_trigger(table: str) -> str:
    return f"""
CREATE TRIGGER {table}_no_update_or_delete
BEFORE UPDATE OR DELETE ON {table}
FOR EACH ROW EXECUTE FUNCTION {table}_no_mutate();
"""


def _sqlite_trigger(table: str, op_kind: str) -> str:
    return f"""
CREATE TRIGGER IF NOT EXISTS {table}_no_{op_kind.lower()}
BEFORE {op_kind} ON {table}
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, '{table} is append-only (CRIT-3 Court): {op_kind} not permitted');
END;
"""


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    # 1. Add hash_format column on audit_log.
    if "audit_log" in existing:
        cols = {c["name"] for c in inspector.get_columns("audit_log")}
        if "hash_format" not in cols:
            op.add_column(
                "audit_log",
                sa.Column("hash_format", sa.String(length=8), nullable=True),
            )

    # 2. Install triggers per dialect.
    dialect = bind.dialect.name
    for table in _TABLES:
        if table not in existing:
            continue
        if dialect == "postgresql":
            op.execute(_pg_trigger_fn(table))
            op.execute(
                f"DROP TRIGGER IF EXISTS {table}_no_update_or_delete ON {table}"
            )
            op.execute(_pg_trigger(table))
        elif dialect == "sqlite":
            op.execute(_sqlite_trigger(table, "UPDATE"))
            op.execute(_sqlite_trigger(table, "DELETE"))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    dialect = bind.dialect.name
    for table in _TABLES:
        if table not in existing:
            continue
        if dialect == "postgresql":
            op.execute(
                f"DROP TRIGGER IF EXISTS {table}_no_update_or_delete ON {table}"
            )
            op.execute(f"DROP FUNCTION IF EXISTS {table}_no_mutate()")
        elif dialect == "sqlite":
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_update")
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_delete")

    if "audit_log" in existing:
        cols = {c["name"] for c in inspector.get_columns("audit_log")}
        if "hash_format" in cols:
            op.drop_column("audit_log", "hash_format")
