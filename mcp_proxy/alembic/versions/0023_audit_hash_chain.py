"""Add hash chain columns to mcp_proxy audit_log — H4 lane7.

Revision ID: 0023_audit_hash_chain
Revises: 0022_drop_api_key_hash
Create Date: 2026-05-01 00:00:00.000000

The Mastio's audit_log was an append-only insert, but the rows had no
forward integrity: an operator with DB write access could rewrite an
old detail field, drop a row, or insert one between others, and the
table itself would not reveal it. SECURITY.md claimed "append-only
cryptographic audit log", which the Court enforces (per-org
hash chain in app/db/audit.py) but the Mastio did not.

This migration adds three nullable columns on ``audit_log``:

- ``chain_seq INTEGER`` — monotonically increasing sequence per
  Mastio. ``UNIQUE(chain_seq)`` so no two rows share a slot.
- ``prev_hash TEXT`` — the row_hash of the previous entry in the
  chain (``"genesis"`` for the first row).
- ``row_hash TEXT`` — SHA-256 over a canonical encoding of
  ``(chain_seq, timestamp, agent_id, action, tool_name, status,
  detail, request_id, prev_hash)``.

Existing rows stay nullable on these fields so the migration doesn't
have to backfill historical data — verifying the chain skips
pre-migration rows. New rows MUST populate all three; the application
log_audit helper enforces that.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0023_audit_hash_chain"
down_revision: Union[str, Sequence[str], None] = "0022_drop_api_key_hash"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    cols = {c["name"] for c in inspector.get_columns(table_name)}
    return column_name in cols


def _has_index(table_name: str, index_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    names = {ix["name"] for ix in inspector.get_indexes(table_name)}
    return index_name in names


def upgrade() -> None:
    with op.batch_alter_table("audit_log") as batch_op:
        if not _has_column("audit_log", "chain_seq"):
            batch_op.add_column(sa.Column("chain_seq", sa.Integer(), nullable=True))
        if not _has_column("audit_log", "prev_hash"):
            batch_op.add_column(sa.Column("prev_hash", sa.Text(), nullable=True))
        if not _has_column("audit_log", "row_hash"):
            batch_op.add_column(sa.Column("row_hash", sa.Text(), nullable=True))
    # Idempotency: the legacy partial-seed path (see
    # ``mcp_proxy/db.py:_run_migrations_sync``) calls
    # ``metadata.create_all`` before stamping, and the post-0023
    # ``AuditLogEntry`` declares the index in its ``__table_args__``.
    # Without this guard the migration would CREATE INDEX on top of
    # itself and fail with ``index ... already exists``.
    if not _has_index("audit_log", "idx_audit_log_chain_seq"):
        op.create_index(
            "idx_audit_log_chain_seq",
            "audit_log",
            ["chain_seq"],
            unique=True,
        )


def downgrade() -> None:
    if _has_index("audit_log", "idx_audit_log_chain_seq"):
        op.drop_index("idx_audit_log_chain_seq", table_name="audit_log")
    with op.batch_alter_table("audit_log") as batch_op:
        if _has_column("audit_log", "row_hash"):
            batch_op.drop_column("row_hash")
        if _has_column("audit_log", "prev_hash"):
            batch_op.drop_column("prev_hash")
        if _has_column("audit_log", "chain_seq"):
            batch_op.drop_column("chain_seq")
