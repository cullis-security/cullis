"""ADR-020 Phase 2 — audit_log.principal_type column

Revision ID: l2g3b4c5d6e7
Revises: k1f2a3b4c5d6
Create Date: 2026-05-04 14:00:00.000000

Adds the ``principal_type`` column to ``audit_log`` with default
``'agent'`` so existing rows back-fill cleanly without rewriting the
hash chain. The column distinguishes the three principal categories
introduced by ADR-020:

  - ``agent``    autonomous workload, the legacy default
  - ``user``     human in a browser session
  - ``workload`` MCP server, BYOCA script, model gateway

Hash-chain compatibility (``app/db/audit.py::compute_entry_hash``) is
preserved by appending ``|pt=<type>`` to the canonical only when the
type is non-default. So every existing row, plus every new
``principal_type='agent'`` row, hashes byte-for-byte identical to the
pre-ADR-020 algorithm. Only ``user`` / ``workload`` rows produce a
v2-shaped canonical, and they verify with the same single code path.

An index on ``principal_type`` lets the dashboard filter by category
("show me everything humans did in the last 24h") without a full scan.
"""
from alembic import op
import sqlalchemy as sa


revision = "l2g3b4c5d6e7"
down_revision = "k1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add NOT NULL with server-side default 'agent'. Existing rows pick
    # up the default at upgrade time; the application code will keep
    # passing 'agent' until ADR-020 Phase 5 wires the resolver to
    # propagate the SPIFFE-derived value.
    op.add_column(
        "audit_log",
        sa.Column(
            "principal_type",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'agent'"),
        ),
    )
    op.create_index(
        "ix_audit_log_principal_type",
        "audit_log",
        ["principal_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_log_principal_type", table_name="audit_log")
    op.drop_column("audit_log", "principal_type")
