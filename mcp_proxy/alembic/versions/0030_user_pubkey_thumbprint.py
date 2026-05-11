"""TOFU pubkey thumbprint pinning for typed principals (CRIT-1 fix).

Revision ID: 0030_user_pubkey_thumbprint
Revises: 0029_user_api_tokens
Create Date: 2026-05-11 18:30:00.000000

Adds ``pubkey_thumbprint`` to ``local_user_principals`` and
``local_workload_principals``. The column stores SHA-256 of the
SubjectPublicKeyInfo (SPKI) DER of the principal's keypair — stable
across cert rotation (Ambassador re-uses its keypair, only the cert
ruota every ~1h).

The CSR signer (``sign_user_csr``) and the cert auth dep
(``get_agent_from_client_cert`` for typed principals) read this column
to enforce TOFU: first CSR for a principal sets the pubkey, every
subsequent presentation must match.

Backfill is intentionally absent. Existing rows have NULL; the next
CSR refresh sets it. The cert-auth dep treats NULL as "not yet
enrolled" and returns 401, so a rogue cert that chains to the Org CA
but has no principal-side pubkey binding is rejected.

Closes audit finding T2-C1 / Track 2 CRIT-1 (impersonation via cert
mint + cert-pin bypass for typed principals).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0030_user_pubkey_thumbprint"
down_revision: Union[str, Sequence[str], None] = "0029_user_api_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_USERS = "local_user_principals"
_WORKLOADS = "local_workload_principals"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if _USERS in existing:
        cols = {c["name"] for c in inspector.get_columns(_USERS)}
        if "pubkey_thumbprint" not in cols:
            op.add_column(
                _USERS,
                sa.Column("pubkey_thumbprint", sa.Text(), nullable=True),
            )

    if _WORKLOADS in existing:
        cols = {c["name"] for c in inspector.get_columns(_WORKLOADS)}
        if "pubkey_thumbprint" not in cols:
            op.add_column(
                _WORKLOADS,
                sa.Column("pubkey_thumbprint", sa.Text(), nullable=True),
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if _USERS in existing:
        cols = {c["name"] for c in inspector.get_columns(_USERS)}
        if "pubkey_thumbprint" in cols:
            op.drop_column(_USERS, "pubkey_thumbprint")

    if _WORKLOADS in existing:
        cols = {c["name"] for c in inspector.get_columns(_WORKLOADS)}
        if "pubkey_thumbprint" in cols:
            op.drop_column(_WORKLOADS, "pubkey_thumbprint")
