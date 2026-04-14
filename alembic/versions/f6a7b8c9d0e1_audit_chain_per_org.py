"""audit chain per-org + TSA anchors

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-04-14 17:00:00.000000

Converts the audit_log hash chain from a single global chain into
independent per-org chains. Existing rows are grandfathered: they keep
their globally-chained `previous_hash` and are treated as "legacy"
(chain_seq IS NULL) by verify_chain. New rows get a monotonic
`chain_seq` scoped per org_id and `previous_hash` referencing the last
entry for the same org.

Cross-org events can be stored as two rows (one per involved org)
sharing the same payload hash via the new peer_org_id / peer_row_hash
columns, so a dispute verifier can cross-reference both orgs' exports.

Also introduces `audit_tsa_anchors` for RFC 3161 timestamping of
per-org chain heads, wired by a later migration / PR 2.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Per-org chain ordering; NULL = legacy row (pre-per-org migration).
    op.add_column(
        'audit_log',
        sa.Column('chain_seq', sa.Integer(), nullable=True),
    )
    # Cross-org linkage: when an event is dual-written to two chains, the
    # companion row's org_id + entry_hash go here so verifiers can confirm
    # both sides agree.
    op.add_column(
        'audit_log',
        sa.Column('peer_org_id', sa.String(length=128), nullable=True),
    )
    op.add_column(
        'audit_log',
        sa.Column('peer_row_hash', sa.String(length=64), nullable=True),
    )
    op.create_index(
        'ix_audit_log_org_chain_seq', 'audit_log',
        ['org_id', 'chain_seq'], unique=False,
    )
    op.create_index(
        op.f('ix_audit_log_peer_org_id'), 'audit_log',
        ['peer_org_id'], unique=False,
    )

    # RFC 3161 TimeStampToken anchors for per-org chain heads.
    op.create_table(
        'audit_tsa_anchors',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('org_id', sa.String(length=128), nullable=False),
        sa.Column('chain_seq', sa.Integer(), nullable=False),
        sa.Column('row_hash', sa.String(length=64), nullable=False),
        sa.Column('tsa_token', sa.LargeBinary(), nullable=False),
        sa.Column('tsa_url', sa.String(length=256), nullable=False),
        sa.Column('tsa_cert_chain', sa.Text(), nullable=True),
        sa.Column(
            'created_at', sa.DateTime(timezone=True), nullable=False,
            server_default=sa.text('CURRENT_TIMESTAMP'),
        ),
        sa.UniqueConstraint('org_id', 'chain_seq', name='uq_tsa_anchor_org_seq'),
    )
    op.create_index(
        op.f('ix_audit_tsa_anchors_org_id'), 'audit_tsa_anchors',
        ['org_id'], unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_audit_tsa_anchors_org_id'), table_name='audit_tsa_anchors')
    op.drop_table('audit_tsa_anchors')
    op.drop_index(op.f('ix_audit_log_peer_org_id'), table_name='audit_log')
    op.drop_index('ix_audit_log_org_chain_seq', table_name='audit_log')
    op.drop_column('audit_log', 'peer_row_hash')
    op.drop_column('audit_log', 'peer_org_id')
    op.drop_column('audit_log', 'chain_seq')
