"""ADR-020 Phase 3 — reach_consents table for four-quadrant policy

Revision ID: m3h4i5j6k7l8
Revises: l2g3b4c5d6e7
Create Date: 2026-05-04 15:00:00.000000

Persists per-pair consent grants used by the reach policy (A2U / U2A
intra-org, A2A / A2U / U2A / U2U cross-org). A row authorises one
specific source — or any source of a given type from a given org when
``source_name='*'`` — to deliver to one specific recipient.

Soft-deletion via ``revoked_at`` non-null. The unique constraint on
the full (recipient, source) tuple lets a re-grant after revoke
update the existing row instead of piling up duplicates, mirroring
``local_agent_resource_bindings``.
"""
from alembic import op
import sqlalchemy as sa


revision = "m3h4i5j6k7l8"
down_revision = "l2g3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "reach_consents",
        sa.Column("consent_id", sa.String(length=64), primary_key=True),
        sa.Column("recipient_org_id", sa.String(length=128), nullable=False),
        sa.Column("recipient_principal_type", sa.String(length=16), nullable=False),
        sa.Column("recipient_name", sa.String(length=128), nullable=False),
        sa.Column("source_org_id", sa.String(length=128), nullable=False),
        sa.Column("source_principal_type", sa.String(length=16), nullable=False),
        sa.Column("source_name", sa.String(length=128), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("granted_by", sa.String(length=128), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "recipient_org_id", "recipient_principal_type", "recipient_name",
            "source_org_id", "source_principal_type", "source_name",
            name="uq_reach_consent_pair",
        ),
    )
    op.create_index(
        "idx_reach_consent_recipient_active",
        "reach_consents",
        ["recipient_org_id", "recipient_principal_type", "recipient_name"],
    )


def downgrade() -> None:
    op.drop_index("idx_reach_consent_recipient_active", table_name="reach_consents")
    op.drop_table("reach_consents")
