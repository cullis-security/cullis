"""Local MCP resources + agent bindings — ADR-007 Phase 1 PR #1.

Revision ID: 0007_mcp_resources
Revises: 0006_enrollment_api_key_hash
Create Date: 2026-04-16

Schema-only addition for Local Resource Mediation (ADR-007). Deploys two
tables that PR-3 will wire into the aggregated MCP server:

  local_mcp_resources          : registry of external MCP services the
                                 proxy is allowed to forward to.
  local_agent_resource_bindings: explicit N:N grant table — only bound
                                 agents see a resource in discovery and
                                 may call it.

Additive migration. No existing table touched, no handler reads from the
new tables in this PR. Audit hash chain (local_audit columns and
compute_entry_hash canonical form) is intentionally unchanged so that
byte-parity with the broker — gate tests/test_proxy_audit_chain_parity.py
— remains green by construction.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_mcp_resources"
down_revision: Union[str, Sequence[str], None] = "0006_enrollment_api_key_hash"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "local_mcp_resources",
        sa.Column("resource_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("org_id", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("endpoint_url", sa.Text(), nullable=False),
        sa.Column("auth_type", sa.Text(), nullable=False, server_default="none"),
        sa.Column("auth_secret_ref", sa.Text(), nullable=True),
        sa.Column("required_capability", sa.Text(), nullable=True),
        sa.Column("allowed_domains", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("enabled", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.Text(), nullable=False),
        sa.UniqueConstraint(
            "org_id", "name", name="uq_local_mcp_resources_org_name"
        ),
    )
    op.create_index(
        "idx_local_mcp_resources_org_enabled",
        "local_mcp_resources",
        ["org_id", "enabled"],
    )

    op.create_table(
        "local_agent_resource_bindings",
        sa.Column("binding_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("agent_id", sa.Text(), nullable=False),
        sa.Column("resource_id", sa.Text(), nullable=False),
        sa.Column("org_id", sa.Text(), nullable=True),
        sa.Column("granted_by", sa.Text(), nullable=False),
        sa.Column("granted_at", sa.Text(), nullable=False),
        sa.Column("revoked_at", sa.Text(), nullable=True),
        sa.UniqueConstraint(
            "agent_id", "resource_id",
            name="uq_local_bindings_agent_resource",
        ),
    )
    op.create_index(
        "idx_local_bindings_agent_revoked",
        "local_agent_resource_bindings",
        ["agent_id", "revoked_at"],
    )
    op.create_index(
        "idx_local_bindings_resource_revoked",
        "local_agent_resource_bindings",
        ["resource_id", "revoked_at"],
    )
    op.create_index(
        "idx_local_bindings_org",
        "local_agent_resource_bindings",
        ["org_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_local_bindings_org", table_name="local_agent_resource_bindings"
    )
    op.drop_index(
        "idx_local_bindings_resource_revoked",
        table_name="local_agent_resource_bindings",
    )
    op.drop_index(
        "idx_local_bindings_agent_revoked",
        table_name="local_agent_resource_bindings",
    )
    op.drop_table("local_agent_resource_bindings")

    op.drop_index(
        "idx_local_mcp_resources_org_enabled", table_name="local_mcp_resources"
    )
    op.drop_table("local_mcp_resources")
