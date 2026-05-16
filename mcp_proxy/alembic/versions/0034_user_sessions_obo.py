"""ADR-032 Layer 2 — user sessions + audit on_behalf_of_user_id.

Revision ID: 0034_user_sessions_obo
Revises: 0033_audit_dpop_jkt
Create Date: 2026-05-16 18:00:00.000000

The Cullis Connector grew an OIDC login path (``cullis-connector login``)
that mints a user-bound session token on top of the agent identity the
device already enrolled with. Subsequent MCP calls carry the token in
``X-Cullis-Session-Token`` + ``X-Cullis-On-Behalf-Of-User``; the proxy
verifies the binding, looks the principal_id up in ``user_sessions``,
and stamps the per-request contextvar that ``audit_log.on_behalf_of_user_id``
reads from.

Two schema changes:

1. ``user_sessions`` table. Opaque random session tokens (not JWT) so
   logout / forced revocation is a single UPDATE — no Redis blacklist
   needed for the common path. The agent cert thumbprint is denormalised
   into the row so session-verification can refuse a token that is
   replayed by a different Connector device.

2. ``audit_log.on_behalf_of_user_id`` nullable + indexed. Mirrors the
   PR #731 dpop_jkt column: auxiliary correlation metadata, NOT part
   of the hash chain (``compute_audit_row_hash`` invariant untouched).
   Forensic query "every action user X authorised an agent to take"
   stays flat as the log grows.

Also adds ``local_user_principals.sso_subject`` + ``idp_issuer`` so
the dashboard Users tab can render the SSO identity that originally
provisioned the principal without joining ``user_sessions``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0034_user_sessions_obo"
down_revision: Union[str, Sequence[str], None] = "0033_audit_dpop_jkt"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_SESSIONS = "user_sessions"
_USERS = "local_user_principals"
_AUDIT = "audit_log"


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return column in {c["name"] for c in insp.get_columns(table)}


def _has_index(table: str, index: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return index in {i["name"] for i in insp.get_indexes(table)}


def upgrade() -> None:
    # 1. user_sessions ------------------------------------------------------
    if not _has_table(_SESSIONS):
        op.create_table(
            _SESSIONS,
            sa.Column("session_id",           sa.Text(),  primary_key=True),
            sa.Column("principal_id",         sa.Text(),  nullable=False),
            sa.Column("agent_cert_thumbprint", sa.Text(), nullable=False),
            sa.Column("sso_subject",          sa.Text(),  nullable=False),
            sa.Column("idp_issuer",           sa.Text(),  nullable=False),
            sa.Column("display_name",         sa.Text(),  nullable=True),
            sa.Column("created_at",           sa.Text(),  nullable=False),
            sa.Column("expires_at",           sa.Text(),  nullable=False),
            # NULL = active. Set on logout / admin revoke.
            sa.Column("revoked_at",           sa.Text(),  nullable=True),
        )
        op.create_index(
            "idx_user_sessions_principal_id", _SESSIONS, ["principal_id"],
        )
        op.create_index(
            "idx_user_sessions_thumbprint", _SESSIONS, ["agent_cert_thumbprint"],
        )

    # 2. audit_log.on_behalf_of_user_id ------------------------------------
    if not _has_column(_AUDIT, "on_behalf_of_user_id"):
        with op.batch_alter_table(_AUDIT) as batch_op:
            # principal_id is the ``<org>::user::<name>`` short form;
            # 255 is generous against typical SSO subject lengths.
            batch_op.add_column(
                sa.Column(
                    "on_behalf_of_user_id", sa.String(length=255), nullable=True,
                ),
            )

    if not _has_index(_AUDIT, "idx_audit_log_on_behalf_of_user"):
        op.create_index(
            "idx_audit_log_on_behalf_of_user",
            _AUDIT,
            ["on_behalf_of_user_id"],
        )

    # 3. local_user_principals.sso_subject + idp_issuer --------------------
    if not _has_column(_USERS, "sso_subject"):
        with op.batch_alter_table(_USERS) as batch_op:
            batch_op.add_column(
                sa.Column("sso_subject", sa.Text(), nullable=True),
            )

    if not _has_column(_USERS, "idp_issuer"):
        with op.batch_alter_table(_USERS) as batch_op:
            batch_op.add_column(
                sa.Column("idp_issuer", sa.Text(), nullable=True),
            )


def downgrade() -> None:
    if _has_column(_USERS, "idp_issuer"):
        with op.batch_alter_table(_USERS) as batch_op:
            batch_op.drop_column("idp_issuer")
    if _has_column(_USERS, "sso_subject"):
        with op.batch_alter_table(_USERS) as batch_op:
            batch_op.drop_column("sso_subject")

    if _has_index(_AUDIT, "idx_audit_log_on_behalf_of_user"):
        op.drop_index("idx_audit_log_on_behalf_of_user", table_name=_AUDIT)
    if _has_column(_AUDIT, "on_behalf_of_user_id"):
        with op.batch_alter_table(_AUDIT) as batch_op:
            batch_op.drop_column("on_behalf_of_user_id")

    if _has_table(_SESSIONS):
        if _has_index(_SESSIONS, "idx_user_sessions_thumbprint"):
            op.drop_index("idx_user_sessions_thumbprint", _SESSIONS)
        if _has_index(_SESSIONS, "idx_user_sessions_principal_id"):
            op.drop_index("idx_user_sessions_principal_id", _SESSIONS)
        op.drop_table(_SESSIONS)
