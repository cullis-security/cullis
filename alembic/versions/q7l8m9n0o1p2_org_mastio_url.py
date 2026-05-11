"""ADR-029 Phase G — organizations.mastio_url

Revision ID: q7l8m9n0o1p2
Revises: p6k7l8m9n0o1
Create Date: 2026-05-11 21:00:00.000000

Per-org URL where the org's Mastio is reachable for cross-org PDP
federation calls (POST /v1/policy/tool-call). Until Phase G this had
to be wired into each originator Mastio's
``MCP_PROXY_TOOL_PDP_FEDERATION_URLS`` env JSON map by hand; Phase G
moves the source of truth into the Court registry so onboarding is
the only place an operator types the URL.

Nullable: orgs that have not yet published a URL are excluded from
the catalog; the originator falls back to the env JSON map first
and, on miss, default-denies the cross-org invocation (same
conservative posture as before Phase G).
"""
from alembic import op
import sqlalchemy as sa


revision = "q7l8m9n0o1p2"
down_revision = "p6k7l8m9n0o1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("mastio_url", sa.String(length=512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("organizations", "mastio_url")
