"""ADR-010 Phase 6b — drop ``local_agents`` (doppione of ``internal_agents``).

Revision ID: 0012_drop_local_agents
Revises: 0011_last_pushed_revision
Create Date: 2026-04-17 22:00:00.000000

``local_agents`` was introduced in 0002 as the proxy's local-scope agent
registry (ADR-006 §2.4). ADR-010 makes ``internal_agents`` the sole
Mastio-authoritative registry, so the two tables overlap entirely. The
four production paths that read from ``local_agents`` are migrated to
``internal_agents``; callers that needed ``cert_thumbprint`` or
``org_id`` derive them on-the-fly (SHA-256 of cert DER / split of
``agent_id`` prefix).

The downgrade recreates the post-0005 schema so rolling back past this
migration lands on a coherent shape.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0012_drop_local_agents"
down_revision: Union[str, Sequence[str], None] = "0011_last_pushed_revision"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Indexes first — SQLite is forgiving, Postgres is not.
    op.drop_index("idx_local_agents_thumbprint", table_name="local_agents")
    op.drop_index("idx_local_agents_org", table_name="local_agents")
    op.drop_table("local_agents")


def downgrade() -> None:
    op.create_table(
        "local_agents",
        sa.Column("agent_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("capabilities", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("cert_pem", sa.Text(), nullable=True),
        sa.Column("api_key_hash", sa.Text(), nullable=True),
        sa.Column("scope", sa.Text(), nullable=False, server_default="local"),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("org_id", sa.Text(), nullable=True),
        sa.Column("cert_thumbprint", sa.Text(), nullable=True),
        sa.Column(
            "metadata_json", sa.Text(), nullable=False, server_default="{}",
        ),
    )
    op.create_index("idx_local_agents_org", "local_agents", ["org_id"])
    op.create_index(
        "idx_local_agents_thumbprint", "local_agents", ["cert_thumbprint"],
    )
