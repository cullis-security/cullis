"""``local_agent_resource_bindings.principal_type`` (ADR-020).

Revision ID: 0024_bindings_principal_type
Revises: 0023_audit_hash_chain
Create Date: 2026-05-06 18:00:00.000000

Adds the ``principal_type`` column to ``local_agent_resource_bindings``
so a single binding row carries the ADR-020 principal type alongside
the existing ``agent_id`` (which becomes a generic principal_id at
the schema level — keeping the column name avoids a destructive
rename on Postgres + SQLite).

Why: shared-mode Frontdesk introduces *user* principals next to the
classic *agent* principals. Both can hold their own scoped bindings
to MCP resources. Without ``principal_type`` on the binding row the
aggregator can't disambiguate ``daniele@user`` from ``daniele@agent``,
and the unique key on ``(agent_id, resource_id)`` would force them to
collide on a single row. See ADR-020 + memory note
``feedback_frontdesk_shared_mode_capability_model``.

Schema move:

  - Add ``principal_type`` Text NOT NULL DEFAULT 'agent'.
  - Replace UNIQUE ``(agent_id, resource_id)`` with UNIQUE
    ``(agent_id, principal_type, resource_id)`` so the same name in
    two principal types can each have its own binding.
  - Existing rows backfill to ``principal_type='agent'`` so legacy
    deployments stay isofunctional after the upgrade.

The column name stays ``agent_id`` for compatibility with rows already
on disk; semantically it now holds a *principal_id* (the canonical
``{org}::{name}`` for agents, ``{org}::user::{name}`` /
``{org}::workload::{name}`` for typed principals as emitted by the
auth layer). A future ADR-020 follow-up may rename the table to
``local_principal_resource_bindings`` once we are past the data
migration window.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0024_bindings_principal_type"
down_revision: Union[str, Sequence[str], None] = "0023_audit_hash_chain"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "local_agent_resource_bindings"
_OLD_UNIQUE = "uq_local_bindings_agent_resource"
_NEW_UNIQUE = "uq_local_bindings_principal_resource"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    columns = {c["name"] for c in inspector.get_columns(_TABLE)}
    if "principal_type" not in columns:
        with op.batch_alter_table(_TABLE) as batch_op:
            batch_op.add_column(
                sa.Column(
                    "principal_type",
                    sa.Text(),
                    nullable=False,
                    server_default="agent",
                ),
            )

    # Refresh the unique constraint shape. ``batch_alter_table`` rebuilds
    # the table on SQLite (where ALTER CONSTRAINT is unsupported) and
    # issues straight DDL on Postgres.
    existing_uniques = {
        u["name"] for u in inspector.get_unique_constraints(_TABLE)
    }
    if _OLD_UNIQUE in existing_uniques and _NEW_UNIQUE not in existing_uniques:
        with op.batch_alter_table(_TABLE) as batch_op:
            batch_op.drop_constraint(_OLD_UNIQUE, type_="unique")
            batch_op.create_unique_constraint(
                _NEW_UNIQUE,
                ["agent_id", "principal_type", "resource_id"],
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_uniques = {
        u["name"] for u in inspector.get_unique_constraints(_TABLE)
    }
    if _NEW_UNIQUE in existing_uniques:
        with op.batch_alter_table(_TABLE) as batch_op:
            batch_op.drop_constraint(_NEW_UNIQUE, type_="unique")
            batch_op.create_unique_constraint(
                _OLD_UNIQUE,
                ["agent_id", "resource_id"],
            )

    columns = {c["name"] for c in inspector.get_columns(_TABLE)}
    if "principal_type" in columns:
        with op.batch_alter_table(_TABLE) as batch_op:
            batch_op.drop_column("principal_type")
