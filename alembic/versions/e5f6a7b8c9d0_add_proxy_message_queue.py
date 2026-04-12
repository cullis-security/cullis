"""add proxy_message_queue for M3 message durability

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-04-12 23:30:00.000000

M3 Session Reliability Layer — message durability:
messages awaiting recipient ack are persisted here with explicit TTL
and idempotency. Schema validated in imp/m0_storage_spike.md (6/6 PASS).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'proxy_message_queue',
        sa.Column('msg_id', sa.String(length=64), primary_key=True),
        sa.Column('session_id', sa.String(length=128), nullable=False),
        sa.Column('recipient_agent_id', sa.String(length=256), nullable=False),
        sa.Column('sender_agent_id', sa.String(length=256), nullable=False),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=False),
        sa.Column('seq', sa.Integer(), nullable=False),
        sa.Column('enqueued_at', sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column('ttl_expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('delivery_status', sa.SmallInteger(),
                  nullable=False, server_default='0'),
        sa.Column('attempts', sa.SmallInteger(),
                  nullable=False, server_default='0'),
        sa.Column('idempotency_key', sa.String(length=256), nullable=True),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expired_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            'recipient_agent_id', 'idempotency_key',
            name='uq_proxy_queue_idempotency',
        ),
    )
    op.create_index(
        'ix_proxy_message_queue_session_id',
        'proxy_message_queue', ['session_id'],
    )
    op.create_index(
        'ix_proxy_message_queue_delivery_status',
        'proxy_message_queue', ['delivery_status'],
    )
    op.create_index(
        'idx_proxy_queue_recipient_pending',
        'proxy_message_queue', ['recipient_agent_id', 'seq'],
    )
    op.create_index(
        'idx_proxy_queue_ttl',
        'proxy_message_queue', ['ttl_expires_at'],
    )


def downgrade() -> None:
    op.drop_index('idx_proxy_queue_ttl', table_name='proxy_message_queue')
    op.drop_index(
        'idx_proxy_queue_recipient_pending',
        table_name='proxy_message_queue',
    )
    op.drop_index(
        'ix_proxy_message_queue_delivery_status',
        table_name='proxy_message_queue',
    )
    op.drop_index(
        'ix_proxy_message_queue_session_id',
        table_name='proxy_message_queue',
    )
    op.drop_table('proxy_message_queue')
