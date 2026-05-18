"""ADR-033 Phase 2: WebAuthn-bound user session tokens for Frontdesk shared mode.

Revision ID: 0039_webauthn_credentials
Revises: 0038_pki_key_store
Create Date: 2026-05-18 14:00:00.000000

Phase 1 (PR #786) added an audit warning when a Connector-issued user
session token is accepted without a cryptographic assertion from the
user. The Connector still signs the binding on behalf of the user, so
a compromised Connector can mint sessions for any local principal.

Phase 2 closes this gap by binding session emission to a WebAuthn
assertion produced by the user's authenticator (passkey, YubiKey,
Touch ID, Windows Hello). The Mastio verifies the assertion against
the credential public key registered by the user during enrollment;
without a valid assertion the session emission path either warns
(transitional) or hard-fails (target steady state).

Schema additions:

1. ``user_webauthn_credentials`` (new table) — one row per registered
   authenticator, keyed by ``credential_id``. ``credential_public_key``
   is the COSE-encoded public key returned by py_webauthn after
   registration. ``sign_count`` is the monotonic counter the
   authenticator increments on each use — a non-strictly-increasing
   value on a later assertion is a signal of credential cloning and
   the verification path raises. ``aaguid`` and ``transports`` are
   informational (used by the dashboard to render authenticator type
   and to constrain ``allowCredentials`` at authentication time).

2. ``user_sessions.user_signed_assertion`` (TEXT NULL) — JSON
   serialisation of the AssertionResponse (clientDataJSON +
   authenticatorData + signature, base64url-encoded). Persisted so the
   audit trail can prove the user-side proof was carried, not just
   trusted at emission time. NULL during the Phase 1 → Phase 2
   transition; required when MCP_PROXY_WEBAUTHN_ENFORCEMENT="required".

3. ``user_sessions.user_credential_id`` (BLOB NULL, FK
   ``user_webauthn_credentials.credential_id``) — denormalised pointer
   to the credential that signed the assertion. Indexed so the
   "show me all sessions tied to this passkey" lookup the dashboard
   surfaces stays cheap when a user revokes a credential.

All additions are nullable; the migration is safe on populated tables.
Existing sessions stay unaffected — the new columns are NULL on legacy
rows and the warn path remains the default until an operator flips
the enforcement flag.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0039_webauthn_credentials"
down_revision: Union[str, Sequence[str], None] = "0038_pki_key_store"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_CREDENTIALS = "user_webauthn_credentials"
_SESSIONS = "user_sessions"


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return name in set(insp.get_table_names())


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if table not in set(insp.get_table_names()):
        return False
    return column in {c["name"] for c in insp.get_columns(table)}


def _has_index(table: str, name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if table not in set(insp.get_table_names()):
        return False
    return name in {ix["name"] for ix in insp.get_indexes(table)}


def upgrade() -> None:
    if not _has_table(_CREDENTIALS):
        op.create_table(
            _CREDENTIALS,
            sa.Column("credential_id", sa.LargeBinary(), primary_key=True),
            sa.Column("principal_id", sa.String(length=255), nullable=False),
            sa.Column("credential_public_key", sa.LargeBinary(), nullable=False),
            sa.Column("sign_count", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("aaguid", sa.LargeBinary(), nullable=True),
            sa.Column("transports", sa.Text(), nullable=True),
            sa.Column("name", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.String(length=64), nullable=False),
            sa.Column("last_used_at", sa.String(length=64), nullable=True),
        )

    if not _has_index(_CREDENTIALS, "ix_user_webauthn_credentials_principal_id"):
        op.create_index(
            "ix_user_webauthn_credentials_principal_id",
            _CREDENTIALS,
            ["principal_id"],
            unique=False,
        )

    if not _has_column(_SESSIONS, "user_signed_assertion"):
        with op.batch_alter_table(_SESSIONS) as batch_op:
            batch_op.add_column(
                sa.Column("user_signed_assertion", sa.Text(), nullable=True),
            )

    if not _has_column(_SESSIONS, "user_credential_id"):
        with op.batch_alter_table(_SESSIONS) as batch_op:
            batch_op.add_column(
                sa.Column("user_credential_id", sa.LargeBinary(), nullable=True),
            )

    if not _has_index(_SESSIONS, "ix_user_sessions_user_credential_id"):
        op.create_index(
            "ix_user_sessions_user_credential_id",
            _SESSIONS,
            ["user_credential_id"],
            unique=False,
        )


def downgrade() -> None:
    if _has_index(_SESSIONS, "ix_user_sessions_user_credential_id"):
        op.drop_index("ix_user_sessions_user_credential_id", table_name=_SESSIONS)

    if _has_column(_SESSIONS, "user_credential_id"):
        with op.batch_alter_table(_SESSIONS) as batch_op:
            batch_op.drop_column("user_credential_id")

    if _has_column(_SESSIONS, "user_signed_assertion"):
        with op.batch_alter_table(_SESSIONS) as batch_op:
            batch_op.drop_column("user_signed_assertion")

    if _has_index(_CREDENTIALS, "ix_user_webauthn_credentials_principal_id"):
        op.drop_index(
            "ix_user_webauthn_credentials_principal_id",
            table_name=_CREDENTIALS,
        )

    if _has_table(_CREDENTIALS):
        op.drop_table(_CREDENTIALS)
