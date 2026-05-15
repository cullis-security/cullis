"""P1.4 — index cert_thumbprint on agents and user_principals.

Revision ID: t0o1p2q3r4s5_idx_thumb
Revises: s9n0o1p2q3r4_replica
Create Date: 2026-05-15 12:30:00.000000

Both registry tables carry a SHA-256 ``cert_thumbprint`` column used
on the cert-rotation, revocation and TOFU-pin paths to find the row
that owns a presented certificate. Until now the lookup was a full
scan (the column was unindexed). A signed BTREE keeps the cost flat
as the agent / user roster grows and shrinks the latency tail on
cert verification — important once a deploy reaches ~10k+ identities.

NULL is allowed (column is nullable: the cert is only attached after
the CSR roundtrip), so NULL rows do not participate in the index.
Non-unique because rotation transiently keeps two rows pointing at
the same thumbprint during cutover; a UNIQUE constraint would
spuriously reject the rotation write.
"""
from alembic import op


revision = "t0o1p2q3r4s5_idx_thumb"
down_revision = "s9n0o1p2q3r4_replica"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "idx_agents_cert_thumbprint",
        "agents",
        ["cert_thumbprint"],
    )
    op.create_index(
        "idx_user_principals_cert_thumbprint",
        "user_principals",
        ["cert_thumbprint"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_user_principals_cert_thumbprint",
        table_name="user_principals",
    )
    op.drop_index(
        "idx_agents_cert_thumbprint",
        table_name="agents",
    )
