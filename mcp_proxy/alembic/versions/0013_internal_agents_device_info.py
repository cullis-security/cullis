"""Persist the Connector device_info JSON on internal_agents.

Revision ID: 0013_internal_agents_device_info
Revises: 0012_drop_local_agents
Create Date: 2026-04-17 23:00:00.000000

When a device-code enrollment is approved, the pending row holds a
free-form JSON blob describing the requester's machine (OS, hostname,
Connector version). Before this migration that blob was discarded once
the row became an ``internal_agents`` entry — the admin could see it in
the enrollment queue but every post-approval surface lost it.

Adding ``device_info`` to ``internal_agents`` lets the dashboard show
OS/host/version next to each agent without hopping back to
``pending_enrollments`` (which is pruned over time).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0013_internal_agents_device_info"
down_revision: Union[str, Sequence[str], None] = "0012_drop_local_agents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Idempotent add — ``init_db`` may call ``metadata.create_all`` before
    # stamping on legacy-unstamped SQLite deploys, in which case the table
    # already carries ``device_info`` from the current model. See the
    # "Alembic stamp partial schema" convention elsewhere in this repo.
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("internal_agents")}
    if "device_info" in existing:
        return
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.add_column(
            sa.Column("device_info", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("internal_agents")}
    if "device_info" not in existing:
        return
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.drop_column("device_info")
