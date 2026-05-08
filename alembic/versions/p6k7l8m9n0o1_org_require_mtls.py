"""Wave 3 U4 Phase 2 — organizations.require_mastio_mtls

Revision ID: p6k7l8m9n0o1
Revises: o5j6k7l8m9n0
Create Date: 2026-05-08 20:30:00.000000

Per-org boolean: when true, federation endpoints reject Mastio calls that
do NOT present a TLS client cert binding to the pinned ``mastio_pubkey``.
Default false preserves the Phase 1 verify-if-present behavior so the flip
is opt-in. Operators turn it on once their nginx (or terminating layer)
is wired to forward the cert via ``X-Cullis-Mastio-Cert`` or once the
Court terminates TLS directly with ``ssl_cert_reqs=optional``.
"""
from alembic import op
import sqlalchemy as sa


revision = "p6k7l8m9n0o1"
down_revision = "o5j6k7l8m9n0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column(
            "require_mastio_mtls",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("organizations", "require_mastio_mtls")
