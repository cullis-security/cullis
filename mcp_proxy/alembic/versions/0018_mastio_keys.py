"""``mastio_keys`` — multi-key store for the Mastio ES256 identity.

Revision ID: 0018_mastio_keys
Revises: 0017_internal_agents_reach
Create Date: 2026-04-21 21:40:00.000000

ADR-012 Phase 2.0 — split the Mastio ES256 leaf key out of the
single-row ``proxy_config`` convention into a dedicated table that can
hold multiple historical keypairs. This is the foundation that makes
key rotation (Phase 2.1) and grace-period verification (Phase 2.2)
structurally possible without hacking around a single-row schema.

Invariant once populated:
    exactly one row has
    ``activated_at IS NOT NULL AND deprecated_at IS NULL``
    (the current signer used by ``LocalIssuer`` and the ADR-009
    counter-signature path).

Schema-only migration. The data migration from the pre-2.0
``proxy_config.mastio_leaf_{key,cert}`` pair runs at proxy boot (see
``AgentManager.ensure_mastio_identity``) rather than here, because
seeding the first row requires parsing the leaf cert with
``cryptography`` — a dependency the standalone ``proxy-init`` container
(``demo_network``/``sandbox``) does not carry. Keeping this migration
dependency-free lets schema bootstrap run in any minimal
alembic-only environment.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0018_mastio_keys"
down_revision: Union[str, Sequence[str], None] = "0017_internal_agents_reach"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "mastio_keys" in existing_tables:
        return

    op.create_table(
        "mastio_keys",
        sa.Column("kid", sa.Text(), primary_key=True),
        sa.Column("pubkey_pem", sa.Text(), nullable=False),
        sa.Column("privkey_pem", sa.Text(), nullable=False),
        sa.Column("cert_pem", sa.Text(), nullable=True),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("activated_at", sa.Text(), nullable=True),
        sa.Column("deprecated_at", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_mastio_keys_active",
        "mastio_keys",
        ["activated_at", "deprecated_at"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    if "mastio_keys" not in existing:
        return
    op.drop_index("idx_mastio_keys_active", table_name="mastio_keys")
    op.drop_table("mastio_keys")
