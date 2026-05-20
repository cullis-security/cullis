"""F-A-201 (CRITICAL) — TOFU pubkey_thumbprint on Court user_principals.

Revision ID: u1p2q3r4s5t6_user_pubkey
Revises: t0o1p2q3r4s5_idx_thumb
Create Date: 2026-05-20 14:00:00.000000

Ports the Mastio CRIT-1 TOFU defence
(``local_user_principals.pubkey_thumbprint``,
``mcp_proxy/registry/principals_csr.py:247-269``) to the Court so that
``/v1/principals/csr`` refuses to mint a fresh user-principal cert
keyed to a different SPKI than the one already bound to that
principal_id.

Pre-fix the broker signs any well-formed user-CSR a workload token
presents, even one keyed to an attacker's keypair, so a compromised
workload escalates to arbitrary user identity in its org
(F-A-201 audit 2026-05-20).

Column is nullable to preserve TOFU semantics: legacy rows that
predate this migration sit with ``pubkey_thumbprint=NULL`` until the
next CSR roundtrip, at which point ``sign_user_csr`` records the
presented SPKI digest and every subsequent CSR must match.
"""
from alembic import op
import sqlalchemy as sa


revision = "u1p2q3r4s5t6_user_pubkey"
down_revision = "t0o1p2q3r4s5_idx_thumb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user_principals",
        sa.Column(
            "pubkey_thumbprint",
            sa.String(length=64),
            nullable=True,
        ),
    )
    op.create_index(
        "idx_user_principals_pubkey_thumbprint",
        "user_principals",
        ["pubkey_thumbprint"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_user_principals_pubkey_thumbprint",
        table_name="user_principals",
    )
    op.drop_column("user_principals", "pubkey_thumbprint")
