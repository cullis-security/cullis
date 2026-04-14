"""add federation_events table

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-04-14 20:00:00.000000

Append-only per-org event log consumed by proxies over SSE to mirror
broker state (ADR-001 Phase 4a). See app/broker/federation.py for the
event type catalogue and publish helpers.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, Sequence[str], None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'federation_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('org_id', sa.String(length=128), nullable=False),
        sa.Column('seq', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('payload', sa.Text(), nullable=False),
        sa.Column(
            'created_at', sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text('CURRENT_TIMESTAMP'),
        ),
    )
    op.create_index(
        'ix_federation_events_org_id', 'federation_events',
        ['org_id'], unique=False,
    )
    op.create_index(
        'ix_federation_events_org_seq', 'federation_events',
        ['org_id', 'seq'], unique=True,
    )


def downgrade() -> None:
    op.drop_index('ix_federation_events_org_seq', table_name='federation_events')
    op.drop_index('ix_federation_events_org_id', table_name='federation_events')
    op.drop_table('federation_events')
