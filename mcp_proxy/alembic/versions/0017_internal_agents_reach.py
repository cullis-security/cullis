"""``internal_agents.reach`` — intra-org / cross-org / both.

Revision ID: 0017_internal_agents_reach
Revises: 0016_enrollment_metadata
Create Date: 2026-04-18 16:20:00.000000

Adds a ``reach`` column so an agent can be restricted to intra-org
communication only, cross-org only, or allowed to do both. The existing
``federated`` boolean remains as the publisher's signal (is this row
exposed on the Court registry?); ``reach`` is the semantic knob the
operator turns and the enforcement layer reads.

Back-compat mapping:
    federated=0 → reach='intra'  (not published, local-only chat)
    federated=1 → reach='both'   (published + can chat intra-org too)

The third state ``reach='cross'`` (published but cannot talk
intra-org — i.e. a purely outward-facing agent) is opt-in from the UI
and has no legacy rows to backfill.

Nullable=False + server_default='both' so any row written before the
enforcement layer lands stays permissive. Enforcement is a separate
PR that checks ``reach`` at session open / oneshot send time.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0017_internal_agents_reach"
down_revision: Union[str, Sequence[str], None] = "0016_enrollment_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent: ``init_db`` may have already created the column via
    # metadata.create_all on an unstamped SQLite legacy deploy.
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("internal_agents")}
    if "reach" in existing:
        return

    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.add_column(
            sa.Column(
                "reach",
                sa.String(length=10),
                nullable=False,
                server_default="both",
            ),
        )

    # Backfill from the legacy ``federated`` flag so pre-existing rows
    # keep their effective behaviour: non-federated = intra-only,
    # federated = both intra + cross. Operators who want a purely
    # outward ``cross`` agent will flip it from the dashboard.
    #
    # ``federated`` is declared as ``sa.Boolean()`` in migration 0010.
    # Use TRUE/FALSE literals rather than ``= 1`` so Postgres (strict
    # bool semantics) accepts the comparison — SQLite maps both forms
    # to the same value. See ``feedback_postgres_type_binding``.
    op.execute(
        """
        UPDATE internal_agents
           SET reach = CASE
               WHEN federated = TRUE THEN 'both'
               ELSE 'intra'
           END
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("internal_agents")}
    if "reach" not in existing:
        return
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.drop_column("reach")
