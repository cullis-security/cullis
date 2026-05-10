"""Revert AD-style password layer added in 0026 — Mastio is not the password store.

Revision ID: 0028_revert_user_password
Revises: 0027_ai_provider_creds
Create Date: 2026-05-10 23:00:00.000000

Migration 0026 added a local password store (``password_hash``,
``must_change_password``, ``disabled``, ``password_updated_at``) on
``local_user_principals`` so the Mastio dashboard could create users
with an initial password. Architectural review (post merge of PR #575
+ #577) flagged this as the wrong layer for the credential:

  * In Frontdesk shared-mode the credential lives in the
    Connector Ambassador's ``users.db`` (ADR-025 Phase 5) and the
    Frontdesk SPA already has admin UI for it
    (``frontend/cullis-chat/src/components/admin/AdminUsers.tsx``).
  * In Connector desktop single-user mode the credential lives on
    the laptop, again in the Connector's ``users.db``.
  * In SSO mode the IdP holds the credential.

Mastio receives the resulting cert (or SSO header) and attributes the
principal — it never holds the password. This migration drops the
columns that PR #575 added so the table goes back to display-only
metadata, matching the design intent.

Idempotent: skips drops when columns are already absent (covers fresh
DBs that never applied 0026 because they are stamped at 0028 directly).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0028_revert_user_password"
down_revision: Union[str, Sequence[str], None] = "0027_ai_provider_creds"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_USERS = "local_user_principals"


def _has_column(inspector: sa.engine.reflection.Inspector, table: str, col: str) -> bool:
    return any(c["name"] == col for c in inspector.get_columns(table))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _USERS not in set(inspector.get_table_names()):
        return
    for col in (
        "password_updated_at",
        "disabled",
        "must_change_password",
        "password_hash",
    ):
        if _has_column(inspector, _USERS, col):
            op.drop_column(_USERS, col)


def downgrade() -> None:
    """Re-add the columns dropped above. Mirrors 0026.upgrade.

    No data restoration: this is the intentional reversal direction.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _USERS not in set(inspector.get_table_names()):
        return
    if not _has_column(inspector, _USERS, "password_hash"):
        op.add_column(
            _USERS, sa.Column("password_hash", sa.Text(), nullable=True),
        )
    if not _has_column(inspector, _USERS, "must_change_password"):
        op.add_column(
            _USERS,
            sa.Column(
                "must_change_password", sa.Boolean(),
                nullable=False, server_default=sa.false(),
            ),
        )
    if not _has_column(inspector, _USERS, "disabled"):
        op.add_column(
            _USERS,
            sa.Column(
                "disabled", sa.Boolean(),
                nullable=False, server_default=sa.false(),
            ),
        )
    if not _has_column(inspector, _USERS, "password_updated_at"):
        op.add_column(
            _USERS, sa.Column("password_updated_at", sa.Text(), nullable=True),
        )
