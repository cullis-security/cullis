"""Add federation cache tables — ADR-001 Phase 4b.

Revision ID: 0004_add_federation_cache
Revises: 0003_add_pending_enrollments
Create Date: 2026-04-14

Proxy-side read-only cache populated by the federation SSE subscriber.
The broker is authoritative for agents/policies/bindings; these tables
are a mirror that avoids a REST round-trip on every intra-org decision
and can be dropped+rebuilt at any time via `cullis-proxy rebuild-cache`.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_add_federation_cache"
down_revision: Union[str, Sequence[str], None] = "0003_add_pending_enrollments"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cached_federated_agents",
        sa.Column("agent_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("capabilities", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("thumbprint", sa.Text(), nullable=True),
        sa.Column("revoked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )
    op.create_index(
        "idx_cached_agents_org", "cached_federated_agents", ["org_id"],
    )

    op.create_table(
        "cached_policies",
        sa.Column("policy_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("policy_type", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )
    op.create_index("idx_cached_policies_org", "cached_policies", ["org_id"])

    op.create_table(
        "cached_bindings",
        sa.Column("binding_id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("org_id", sa.Text(), nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )
    op.create_index("idx_cached_bindings_org", "cached_bindings", ["org_id"])
    op.create_index("idx_cached_bindings_agent", "cached_bindings", ["agent_id"])

    op.create_table(
        "federation_cursor",
        sa.Column("org_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("last_seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("federation_cursor")
    op.drop_index("idx_cached_bindings_agent", table_name="cached_bindings")
    op.drop_index("idx_cached_bindings_org", table_name="cached_bindings")
    op.drop_table("cached_bindings")
    op.drop_index("idx_cached_policies_org", table_name="cached_policies")
    op.drop_table("cached_policies")
    op.drop_index("idx_cached_agents_org", table_name="cached_federated_agents")
    op.drop_table("cached_federated_agents")
