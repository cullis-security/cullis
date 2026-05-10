"""AD-style local password credentials for user principals.

Revision ID: 0026_user_password
Revises: 0025_local_principals
Create Date: 2026-05-10 22:00:00.000000

Adds a local password layer on top of ``local_user_principals`` so an org
admin can pre-provision an employee account from the dashboard and hand
the credential out-of-band, mirroring the Active Directory flow:

  admin creates row with bcrypt(password) + must_change_password=True
  employee logs into Cullis Chat / dashboard with user_name + password
  /v1/principals/password-login mints a short-lived DPoP-bound JWT
  the JWT is presented to the existing /v1/principals/csr endpoint
  the user's cert is minted, must_change_password forces a change first

Backward compatible: the SSO upsert path (``upsert_from_csr``) leaves
``password_hash`` NULL, so SSO-only users keep working unchanged. The
login endpoint refuses NULL hashes with a clear "this is an SSO-only
account" message rather than treating it as a wrong-password attempt.

Boolean columns use ``server_default`` literals; the application always
binds ``bool(x)`` to dodge the Postgres BOOLEAN binding gotcha that
SQLite silently masks (memory: feedback_postgres_type_binding).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0026_user_password"
down_revision: Union[str, Sequence[str], None] = "0025_local_principals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_USERS = "local_user_principals"


def _has_column(inspector: sa.engine.reflection.Inspector, table: str, col: str) -> bool:
    return any(c["name"] == col for c in inspector.get_columns(table))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _USERS not in set(inspector.get_table_names()):
        # Migration 0025 not applied (fresh test stamp). The column adds
        # below would error; bail silently to keep the chain idempotent
        # alongside the 0025 ``if _USERS not in existing`` guard.
        return

    if not _has_column(inspector, _USERS, "password_hash"):
        op.add_column(
            _USERS,
            sa.Column("password_hash", sa.Text(), nullable=True),
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
            _USERS,
            sa.Column("password_updated_at", sa.Text(), nullable=True),
        )


def downgrade() -> None:
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
