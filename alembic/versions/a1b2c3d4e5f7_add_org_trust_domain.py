"""add trust_domain to organizations

Revision ID: a1b2c3d4e5f7
Revises: f6a7b8c9d0e1
Create Date: 2026-04-15 20:00:00.000000

Adds a nullable, unique ``trust_domain`` column to ``organizations`` so
the broker can resolve an SVID presented by an agent (SPIFFE URI SAN,
no CN/O in subject) back to its owning org. The column is nullable for
backward compatibility: orgs onboarded before this migration continue
to authenticate via CN/O-based agent certs.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f7'
down_revision: Union[str, Sequence[str], None] = 'a7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("trust_domain", sa.String(length=256), nullable=True),
    )
    op.create_index(
        "ix_organizations_trust_domain",
        "organizations",
        ["trust_domain"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_organizations_trust_domain", table_name="organizations")
    op.drop_column("organizations", "trust_domain")
