"""Multi-provider AI credentials, dashboard-managed.

Revision ID: 0027_ai_provider_creds
Revises: 0026_user_password
Create Date: 2026-05-10 23:30:00.000000

Lifts the embedded AI gateway off the single ``ANTHROPIC_API_KEY``
environment variable so an org admin can add Gemini, OpenAI, Bedrock,
Vertex, or a local Ollama base URL from the Mastio dashboard at runtime.

Schema:
  provider          TEXT PRIMARY KEY  — anthropic, openai, gemini, bedrock,
                                         vertex, ollama. The catalog in
                                         ``mcp_proxy.egress.provider_catalog``
                                         enumerates the supported keys.
  creds_json        TEXT NOT NULL     — JSON dict of provider-specific fields
                                         (api_key, aws_access_key_id, ...).
                                         Stored alongside ``proxy_config``
                                         entries like ``org_ca_key``; the
                                         Mastio process is the trust
                                         boundary, not this column.
  enabled           BOOLEAN NOT NULL  — operator can pause a provider
                                         without losing the credentials.
  updated_at        TEXT NOT NULL     — ISO-8601 UTC.
  updated_by        TEXT              — principal_id of the admin who set
                                         the row, NULL when the row was
                                         seeded from environment for
                                         backward compat.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0027_ai_provider_creds"
down_revision: Union[str, Sequence[str], None] = "0026_user_password"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "ai_provider_credentials"


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE in set(inspector.get_table_names()):
        return

    op.create_table(
        _TABLE,
        sa.Column("provider", sa.Text(), primary_key=True),
        sa.Column("creds_json", sa.Text(), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(),
            nullable=False, server_default=sa.true(),
        ),
        sa.Column("updated_at", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE in set(inspector.get_table_names()):
        op.drop_table(_TABLE)
