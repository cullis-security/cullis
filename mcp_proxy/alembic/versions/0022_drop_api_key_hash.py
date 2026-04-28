"""Drop api_key_hash columns — ADR-014 PR-C closes the api_key path.

Revision ID: 0022_drop_api_key_hash
Revises: 0021_anomaly_detector_tables
Create Date: 2026-04-27 21:00:00.000000

PR-B replaced ``X-API-Key`` with mTLS client cert auth on
``/v1/egress/*`` and ``/v1/agents/search``. PR-C removes the api_key
infrastructure entirely — this migration drops the two columns that
stored the hashed key:

- ``internal_agents.api_key_hash``  (NOT NULL bcrypt hash, was the
  bearer token shared between the SDK and the Mastio's
  ``get_agent_from_api_key`` lookup; the cert-DER pin against
  ``cert_pem`` is the replacement).
- ``pending_enrollments.api_key_hash``  (NULL until approval, where
  it was minted + carried forward to the final ``internal_agents``
  row; PR-C's enrollment flow no longer mints a key).

The downgrade re-adds both columns as ``nullable=True`` — restoring
the pre-migration ``NOT NULL`` on ``internal_agents`` would fail any
table that already shed the column, and a placeholder default would
silently re-enable a credential the application no longer accepts.
Operators rolling back to a pre-PR-C build before re-deploying must
re-enroll their agents.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0022_drop_api_key_hash"
down_revision: Union[str, Sequence[str], None] = "0021_anomaly_detector_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(table_name: str, column_name: str) -> bool:
    """Reflect the live DB to see if ``column_name`` exists on
    ``table_name``. Idempotency guard: legacy partial-seed boots create
    ``internal_agents`` via ``metadata.create_all`` which uses the
    post-0022 ``db_models`` schema (no ``api_key_hash``); the column
    that earlier migrations would have added never made it onto the
    table, so the DROP must skip rather than KeyError.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    cols = {c["name"] for c in inspector.get_columns(table_name)}
    return column_name in cols


def upgrade() -> None:
    # ``recreate="always"`` forces alembic to copy the table from
    # current DB state rather than from ``target_metadata`` (which
    # already lacks ``api_key_hash`` post-PR-C). The ``_has_column``
    # guard skips the drop on legacy partial-seed boots where the
    # column was never created in the first place.
    if _has_column("internal_agents", "api_key_hash"):
        with op.batch_alter_table(
            "internal_agents", recreate="always"
        ) as batch_op:
            batch_op.drop_column("api_key_hash")
    if _has_column("pending_enrollments", "api_key_hash"):
        with op.batch_alter_table(
            "pending_enrollments", recreate="always"
        ) as batch_op:
            batch_op.drop_column("api_key_hash")


def downgrade() -> None:
    with op.batch_alter_table(
        "internal_agents", recreate="always"
    ) as batch_op:
        batch_op.add_column(
            sa.Column("api_key_hash", sa.Text(), nullable=True),
        )
    with op.batch_alter_table(
        "pending_enrollments", recreate="always"
    ) as batch_op:
        batch_op.add_column(
            sa.Column("api_key_hash", sa.Text(), nullable=True),
        )
