"""Encrypt ai_provider_credentials.creds_json at rest (Wave B B1).

Revision ID: 0032_ai_creds_at_rest_enc
Revises: 0031_audit_append_only_v2
Create Date: 2026-05-11 22:30:00.000000

Audit ref: imp/audits/2026-05-11-track-4-secrets-supply-chain.md H-01
+ imp/audits/2026-05-11-track-6-ai-frontdesk.md M-3.

Pre-fix the AI provider credentials lived as plaintext JSON in
``ai_provider_credentials.creds_json``. Anyone with read access to
the SQLite file or a Postgres backup recovered every upstream LLM API
key (Anthropic, OpenAI, AWS Bedrock, GCP service-account JSON, Gemini,
Vertex) in cleartext.

This migration walks every existing row, parses the JSON to confirm
it is plaintext (already-enveloped rows are skipped — no double-wrap),
and rewrites it through ``mcp_proxy.tools.secret_encrypt.encrypt_at_rest``
so the column carries the ``enc:v1:<token>`` envelope. The KMS-derived
master key is bootstrapped on first read; on a cold-install Mastio the
helper mints + persists a per-deploy random into ``proxy_config``
(env override available via ``MCP_PROXY_SECRET_ENCRYPTION_KEY_B64``).

Schema-only change: no DDL. The migration is a one-shot data rewrite.
Rolls back safely (``decrypt_at_rest`` reads the envelope back to
plaintext). Idempotent: a second forward run no-ops on rows that
already start with ``enc:v1:``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0032_ai_creds_at_rest_enc"
down_revision: Union[str, Sequence[str], None] = "0031_audit_append_only_v2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "ai_provider_credentials"
_PREFIX = "enc:v1:"


def _migrate_rows(direction: str) -> None:
    """Walk every row and upgrade / downgrade the envelope.

    direction = "encrypt" → wrap plaintext in enc:v1:<token>
    direction = "decrypt" → unwrap enc:v1: back to plaintext
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _TABLE not in set(inspector.get_table_names()):
        return

    rows = bind.execute(
        sa.text(f"SELECT provider, creds_json FROM {_TABLE}"),
    ).fetchall()

    if not rows:
        return

    # Late import — alembic's offline-mode renderer can run without
    # the application package on the path; the data step requires it.
    import asyncio
    from mcp_proxy.tools.secret_encrypt import (
        decrypt_at_rest,
        encrypt_at_rest,
    )

    async def _transform(value: str | None) -> str | None:
        if value is None or value == "":
            return value
        if direction == "encrypt":
            if value.startswith(_PREFIX):
                return value  # already enveloped, idempotent
            return await encrypt_at_rest(value)
        # downgrade
        if not value.startswith(_PREFIX):
            return value  # already plaintext
        return await decrypt_at_rest(value)

    loop = asyncio.new_event_loop()
    try:
        for provider, blob in rows:
            new_blob = loop.run_until_complete(_transform(blob))
            if new_blob != blob:
                bind.execute(
                    sa.text(
                        f"UPDATE {_TABLE} SET creds_json = :c "
                        f" WHERE provider = :p"
                    ),
                    {"c": new_blob, "p": provider},
                )
    finally:
        loop.close()


def upgrade() -> None:
    _migrate_rows("encrypt")


def downgrade() -> None:
    _migrate_rows("decrypt")
