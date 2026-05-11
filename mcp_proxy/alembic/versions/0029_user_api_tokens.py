"""User API tokens for cross-channel Bearer auth (ADR-027 Phase 1).

Revision ID: 0029_user_api_tokens
Revises: 0028_revert_user_password
Create Date: 2026-05-11 12:00:00.000000

Adds the ``user_api_tokens`` table backing ADR-027 ``culk_*`` Bearer
tokens. Each row maps a long-lived API key to a user principal so any
OpenAI-compat client (LibreChat, Cursor, Cherry Studio, AnythingLLM,
curl) can authenticate at ``/v1/*`` without going through DPoP cert
provisioning.

Schema:

  id                      TEXT PRIMARY KEY      ulid string
  principal_id            TEXT NOT NULL         FK -> local_user_principals.principal_id
  label                   TEXT NOT NULL         operator-supplied display name
  token_hash              TEXT NOT NULL         bcrypt(culk_*) cost 12
  token_last4             TEXT NOT NULL         last 4 chars of the plaintext, indexed
  scope_providers_json    TEXT NOT NULL         JSON array, [] = no restriction
  scope_paths_json        TEXT NOT NULL         JSON array, ["/v1/*"] default
  created_at              TEXT NOT NULL         ISO-8601 UTC
  created_by              TEXT NOT NULL         minter principal_id (admin or self)
  last_used_at            TEXT NULL             ISO-8601 UTC, set on each auth
  last_used_ip            TEXT NULL             client IP at last successful auth
  expires_at              TEXT NULL             NULL = never expire
  revoked_at              TEXT NULL             NULL = active
  revoked_by              TEXT NULL             principal_id that revoked

Indexes:

  idx_user_api_tokens_principal  ON (principal_id) — list-by-user
  idx_user_api_tokens_last4      ON (token_last4)  — auth resolver prefix probe

The auth resolver hashes incoming Bearer values and compares against
``token_hash`` only on rows matching the ``token_last4`` prefix, so the
bcrypt check cost is amortised: ~65k possible suffix buckets × a
handful of active tokens per bucket means ≪1 bcrypt op per request on
the median workload.

No PII outside ``label`` (operator chooses) and ``last_used_ip`` (audit
need). Tokens themselves are never persisted in plaintext — only the
mint endpoint returns the cleartext once at creation time.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0029_user_api_tokens"
down_revision: Union[str, Sequence[str], None] = "0028_revert_user_password"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "user_api_tokens"
_IDX_PRINCIPAL = "idx_user_api_tokens_principal"
_IDX_LAST4 = "idx_user_api_tokens_last4"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE in set(inspector.get_table_names()):
        return

    op.create_table(
        _TABLE,
        sa.Column("id",                   sa.Text(), primary_key=True),
        sa.Column("principal_id",         sa.Text(), nullable=False),
        sa.Column("label",                sa.Text(), nullable=False),
        sa.Column("token_hash",           sa.Text(), nullable=False),
        sa.Column("token_last4",          sa.Text(), nullable=False),
        sa.Column(
            "scope_providers_json", sa.Text(),
            nullable=False, server_default="[]",
        ),
        sa.Column(
            "scope_paths_json", sa.Text(),
            nullable=False, server_default='["/v1/*"]',
        ),
        sa.Column("created_at",   sa.Text(), nullable=False),
        sa.Column("created_by",   sa.Text(), nullable=False),
        sa.Column("last_used_at", sa.Text(), nullable=True),
        sa.Column("last_used_ip", sa.Text(), nullable=True),
        sa.Column("expires_at",   sa.Text(), nullable=True),
        sa.Column("revoked_at",   sa.Text(), nullable=True),
        sa.Column("revoked_by",   sa.Text(), nullable=True),
    )
    op.create_index(_IDX_PRINCIPAL, _TABLE, ["principal_id"])
    op.create_index(_IDX_LAST4,     _TABLE, ["token_last4"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE not in set(inspector.get_table_names()):
        return
    op.drop_index(_IDX_LAST4, table_name=_TABLE)
    op.drop_index(_IDX_PRINCIPAL, table_name=_TABLE)
    op.drop_table(_TABLE)
