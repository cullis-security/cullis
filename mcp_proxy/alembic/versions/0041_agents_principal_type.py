"""``internal_agents`` — ``principal_type`` column.

Revision ID: 0041_agents_principal_type
Revises: 0040_merge_grace_webauthn
Create Date: 2026-05-19 15:00:00.000000

ADR-034 §2 — Frontdesk identity rewrite, PR-A foundation.

Pre-fix, the ``internal_agents`` table lacks any column to record the
caller's principal taxonomy (``agent`` / ``workload``). The dispatcher
in ``mcp_proxy/auth/client_cert.py`` defaulted every enrolled row to
``agent`` via the ``TokenPayload`` dataclass default
(``mcp_proxy/models.py:56``), so a Frontdesk shared bundle ended up
attributed as ``agent::frontdesk`` even though it is structurally a
web-tier workload (reverse-proxy + identity broker, not an AI agent).
The misclassification mistriggered reach policies (A2U cross-org deny)
and obscured the audit chain.

ADR-020 §1 declared the three principal types (``agent`` / ``user`` /
``workload``) as first-class. ``local_bindings`` and
``local_user_principals`` already carry the column. This migration
brings ``internal_agents`` in line so the agent-side enrollment can
mark a Connector as ``workload`` when ``AMBASSADOR_MODE=shared``.

Backfill is via ``server_default='agent'`` — every existing row stays
attributed as today; only future enrollments (or the explicit
``mastio frontdesk reclassify`` admin command in a follow-up PR) flip
the value.

NOT NULL with a server default keeps the column safe to add online
without a window where readers see NULL. Postgres ``ALTER TABLE ADD
COLUMN`` with default is a metadata-only rewrite on 11+; SQLite
rewrites the table but the migration footprint is tiny.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0041_agents_principal_type"
down_revision: Union[str, Sequence[str], None] = "0040_merge_grace_webauthn"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    internal_cols = {col["name"] for col in inspector.get_columns("internal_agents")}
    if "principal_type" not in internal_cols:
        op.add_column(
            "internal_agents",
            sa.Column(
                "principal_type",
                sa.Text(),
                nullable=False,
                server_default="agent",
            ),
        )

    # ``pending_enrollments`` carries the value forward from
    # ``start_enrollment`` to the approve handler so the INSERT into
    # ``internal_agents`` lands the right principal_type. Same default
    # so a Connector that doesn't ship the field (legacy single-mode)
    # ends up tagged ``agent`` exactly as today.
    pending_cols = {
        col["name"] for col in inspector.get_columns("pending_enrollments")
    }
    if "principal_type" not in pending_cols:
        op.add_column(
            "pending_enrollments",
            sa.Column(
                "principal_type",
                sa.Text(),
                nullable=False,
                server_default="agent",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    pending_cols = {
        col["name"] for col in inspector.get_columns("pending_enrollments")
    }
    if "principal_type" in pending_cols:
        op.drop_column("pending_enrollments", "principal_type")

    internal_cols = {col["name"] for col in inspector.get_columns("internal_agents")}
    if "principal_type" in internal_cols:
        op.drop_column("internal_agents", "principal_type")
