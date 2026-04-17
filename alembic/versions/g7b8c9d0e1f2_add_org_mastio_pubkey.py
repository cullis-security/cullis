"""add org.mastio_pubkey for ADR-009 counter-signature

Revision ID: g7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-04-17 09:00:00.000000

Adds a nullable ``mastio_pubkey`` column to ``organizations`` so the Court
can pin the mastio/proxy ES256 public key at onboarding time. Runtime
requests carry an ``X-Cullis-Mastio-Signature`` header counter-signed by
the mastio; the Court verifies it against this pinned key when present.

NULL means "legacy mode" — no counter-signature enforcement. ADR-009
Phase 3 will make this column NOT NULL and the enforcement mandatory.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'g7b8c9d0e1f2'
down_revision: Union[str, Sequence[str], None] = 'b7c8d9e0f1a2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'organizations',
        sa.Column('mastio_pubkey', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('organizations', 'mastio_pubkey')
