"""Mastio-local principal directories for users + workloads.

Revision ID: 0025_local_principals
Revises: 0024_bindings_principal_type
Create Date: 2026-05-07 22:00:00.000000

Adds two read-mostly tables on the Mastio so the admin dashboard can
list user + workload principals with display metadata. The Frontdesk
SSO flow (``/v1/principals/csr``) upserts into ``local_user_principals``
on every signature, and the new ``POST /v1/admin/users`` /
``POST /v1/admin/workloads`` endpoints pre-populate rows so the
dashboard renders cleanly even before the first user logs in.

These tables intentionally hold *display* metadata only — the source
of truth for cert state remains the Org CA + audit log + the
broker-side ``user_principals`` table that bridges SSO subject to
principal_id. The Mastio table just lets the admin UI answer "who
are my users?" without crossing the broker boundary.

Workloads have no broker-side analogue — they are infra-local and
never federate by default (memory note: workloads stay intra-org;
Court federation registry is for users + agents). The table exists
so the dashboard's Workloads tab has somewhere to read from.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0025_local_principals"
down_revision: Union[str, Sequence[str], None] = "0024_bindings_principal_type"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_USERS = "local_user_principals"
_WORKLOADS = "local_workload_principals"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if _USERS not in existing:
        op.create_table(
            _USERS,
            sa.Column("principal_id",   sa.Text(), primary_key=True),
            sa.Column("user_name",      sa.Text(), nullable=False),
            sa.Column("display_name",   sa.Text(), nullable=True),
            # ADR-020 reach: intra | cross | both. Default intra so a
            # newly seeded user that never sets a reach stays scoped.
            sa.Column("reach",          sa.Text(), nullable=False,
                      server_default="intra"),
            # Free-form hint surfaced on the dashboard ("frontdesk",
            # "cullis-chat", "cli"). NULL means unknown.
            sa.Column("surface",        sa.Text(), nullable=True),
            sa.Column("cert_thumbprint", sa.Text(), nullable=True),
            sa.Column("created_at",     sa.Text(), nullable=False),
            sa.Column("last_active_at", sa.Text(), nullable=True),
        )
        op.create_index(
            "idx_local_user_principals_user_name",
            _USERS, ["user_name"],
        )

    if _WORKLOADS not in existing:
        op.create_table(
            _WORKLOADS,
            sa.Column("principal_id",   sa.Text(), primary_key=True),
            sa.Column("workload_name",  sa.Text(), nullable=False),
            sa.Column("display_name",   sa.Text(), nullable=True),
            sa.Column("image_digest",   sa.Text(), nullable=True),
            sa.Column("runtime_status", sa.Text(), nullable=False,
                      server_default="unknown"),
            sa.Column("created_at",     sa.Text(), nullable=False),
            sa.Column("last_active_at", sa.Text(), nullable=True),
        )
        op.create_index(
            "idx_local_workload_principals_name",
            _WORKLOADS, ["workload_name"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if _WORKLOADS in existing:
        op.drop_index("idx_local_workload_principals_name", _WORKLOADS)
        op.drop_table(_WORKLOADS)
    if _USERS in existing:
        op.drop_index("idx_local_user_principals_user_name", _USERS)
        op.drop_table(_USERS)
