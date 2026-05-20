"""F-A-402 + F-A-403 — Mastio audit_log append-only trigger + hash v2.

Revision ID: 0042_audit_log_v2
Revises: 0041_agents_principal_type
Create Date: 2026-05-20 15:00:00.000000

Audit ref: imp/audits/2026-05-20/findings/track-a/F-A-{402,403}.md

Closes two sister-file gaps on the Mastio primary audit chain:

F-A-402 (HIGH): ``audit_log`` had hash chain semantics
(``chain_seq``, ``prev_hash``, ``row_hash``) but no BEFORE UPDATE/DELETE
trigger. The Court ``audit_log`` (migration r8m9n0o1p2q3) and the
Mastio ``local_audit`` (migration 0031) both have the trigger. An
attacker with DB write could UPDATE a row, recompute every
subsequent ``row_hash`` (no signing key, just SHA-256 over data they
control), and ``verify_audit_chain`` would still pass.

F-A-403 (HIGH): ``compute_audit_row_hash`` canonical excluded
``dpop_jkt`` (ADR-014 DPoP binding) and ``on_behalf_of_user_id``
(ADR-032 OBO principal attribution). Both columns were added by
later migrations (0033, 0034) without bumping the hash format.
Result: an attacker could swap ``on_behalf_of_user_id='attacker'``
to ``'victim'`` on a high-value row and ``verify_audit_chain`` would
not notice. The Court ``compute_entry_hash_v2`` already binds
``principal_type``, so this is sister-file divergence (third instance
of the dual-tier gap, see ``feedback_mcp_proxy_csr_gate_f001_missing``).

This migration:
1. Installs the BEFORE UPDATE/DELETE trigger on ``audit_log`` (Postgres
   CREATE FUNCTION + CREATE TRIGGER; SQLite CREATE TRIGGER ... RAISE).
2. Adds ``hash_format`` TEXT NULL column. ``log_audit`` sets it to
   ``'v2'`` for new rows; legacy rows stay NULL and ``verify_audit_chain``
   verifies them with the v1 canonical (preserve historical chain).

The v2 canonical extends the v1 canonical with ``|{dpop_jkt or ''}|{
on_behalf_of_user_id or ''}`` so both attribution columns are bound
to the chain.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0042_audit_log_v2"
down_revision: Union[str, Sequence[str], None] = "0041_agents_principal_type"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "audit_log"


_PG_TRIGGER_FN = """
CREATE OR REPLACE FUNCTION audit_log_no_mutate()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'audit_log is append-only (F-A-402): % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_PG_TRIGGER = """
CREATE TRIGGER audit_log_no_update_or_delete
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION audit_log_no_mutate();
"""

_SQLITE_TRIGGER_UPDATE = """
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only (F-A-402): UPDATE not permitted');
END;
"""

_SQLITE_TRIGGER_DELETE = """
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only (F-A-402): DELETE not permitted');
END;
"""


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if _TABLE not in existing:
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
        op.execute(
            "DROP TRIGGER IF EXISTS audit_log_no_update_or_delete ON audit_log"
        )
        op.execute(_PG_TRIGGER)
    elif dialect == "sqlite":
        op.execute(_SQLITE_TRIGGER_UPDATE)
        op.execute(_SQLITE_TRIGGER_DELETE)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if _TABLE not in existing:
        return

    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS audit_log_no_update_or_delete ON audit_log"
        )
        op.execute("DROP FUNCTION IF EXISTS audit_log_no_mutate()")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")

    cols = {c["name"] for c in inspector.get_columns(_TABLE)}
    if "hash_format" in cols:
        op.drop_column(_TABLE, "hash_format")
