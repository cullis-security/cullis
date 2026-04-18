"""ADR-011 Phase 1a — enrollment metadata on ``internal_agents``.

Revision ID: 0016_enrollment_metadata
Revises: 0015_enrollment_dpop_jkt
Create Date: 2026-04-18 00:00:00.000000

Adds three nullable columns to ``internal_agents`` so the Mastio can
distinguish how an agent got enrolled and carry SPIFFE identity as a
first-class attribute (not a credential):

  * ``enrollment_method`` — enum-typed text, values ``admin`` /
    ``connector`` / ``byoca`` / ``spiffe``. Existing rows backfilled
    to ``admin`` (they were all created via the admin path today).
  * ``spiffe_id`` — populated for rows where the enrollment carried an
    SVID or the Org CA attached the SPIFFE URI SAN. Optional.
  * ``enrolled_at`` — distinct from ``created_at`` so an admin can
    create a placeholder row and complete enrollment later. Backfilled
    to ``created_at`` on upgrade per ADR-011 §7.3.

Columns are nullable in the schema to keep the migration idempotent and
composable with ``metadata.create_all`` on fresh SQLite deploys. The
application layer enforces ``enrollment_method`` NOT NULL at INSERT
time via the model default.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0016_enrollment_metadata"
down_revision: Union[str, Sequence[str], None] = "0015_enrollment_dpop_jkt"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_NEW_COLUMNS = ("enrollment_method", "spiffe_id", "enrolled_at")


def upgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("internal_agents")}

    to_add = [c for c in _NEW_COLUMNS if c not in existing]
    if to_add:
        with op.batch_alter_table("internal_agents") as batch_op:
            if "enrollment_method" in to_add:
                batch_op.add_column(sa.Column("enrollment_method", sa.Text(), nullable=True))
            if "spiffe_id" in to_add:
                batch_op.add_column(sa.Column("spiffe_id", sa.Text(), nullable=True))
            if "enrolled_at" in to_add:
                batch_op.add_column(sa.Column("enrolled_at", sa.Text(), nullable=True))

    # Backfill existing rows so reads after the migration don't see NULLs.
    # Safe to re-run — UPDATE on already-populated rows is a no-op via the
    # ``IS NULL`` guard.
    op.execute(
        "UPDATE internal_agents SET enrollment_method = 'admin' "
        "WHERE enrollment_method IS NULL"
    )
    op.execute(
        "UPDATE internal_agents SET enrolled_at = created_at "
        "WHERE enrolled_at IS NULL"
    )


def downgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("internal_agents")}
    to_drop = [c for c in _NEW_COLUMNS if c in existing]
    if not to_drop:
        return
    with op.batch_alter_table("internal_agents") as batch_op:
        for col in to_drop:
            batch_op.drop_column(col)
