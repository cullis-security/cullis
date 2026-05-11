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

This migration walks every existing row, parses the envelope to
confirm it is plaintext (already-enveloped rows are skipped — no
double-wrap), and rewrites the column with the ``enc:v1:<token>``
Fernet envelope. Reads at runtime go through
``mcp_proxy.tools.secret_encrypt.decrypt_at_rest`` which already
transparently handles legacy plaintext rows during rollout.

Implementation note (Bug #8 fix-forward, 2026-05-11 sera): the
original revision called the async ``encrypt_at_rest`` helper via
``loop.run_until_complete(...)``. Inside alembic's
``connection.run_sync(do_run_migrations)`` bridge the new event loop
deadlocks against the outer ``asyncio.run`` driving the migration —
the coroutine is created but never awaited (RuntimeWarning), the
container exits with code 3, docker compose retries forever, and
the customer-path Mastio bundle becomes unbootable
(``project_dogfood_2026_05_11_vps_demo`` Bug #8, issue #626).

This rewrite stays inside the alembic sync execution context the
whole way:

  - master key resolution reads ``MCP_PROXY_SECRET_ENCRYPTION_KEY_B64``
    env first (operator override, common in production), falling back
    to a sync ``SELECT value FROM proxy_config WHERE key = ...`` via
    ``bind.execute``. Cold install mints + persists a fresh
    ``secrets.token_bytes(32)`` into proxy_config the same way the
    runtime helper does, just through the alembic bind.
  - encryption/decryption use ``Fernet`` directly (synchronous).
  - No ``asyncio``, no nested event loop, no coroutine creation.

The runtime path (``mcp_proxy.tools.secret_encrypt``) is unchanged
and remains async — only the one-shot migration goes sync. Forward
and reverse are still idempotent on already-correct rows.
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# NOTE: ``cryptography`` is imported lazily inside ``_migrate_rows`` (and
# only on the encrypt/decrypt branch, after the empty-rows early-exit) so
# the module file parses in environments that have alembic but not the
# full proxy runtime deps. Specifically ``demo_network/proxy-init`` is a
# slim seed container that runs ``command.upgrade(cfg, "head")`` against
# a fresh SQLite to pre-populate ``proxy_config``: there are zero rows in
# ``ai_provider_credentials`` to migrate there, and we don't want to add
# ``cryptography`` to its requirements just so this file can be parsed.


revision: str = "0032_ai_creds_at_rest_enc"
down_revision: Union[str, Sequence[str], None] = "0031_audit_append_only_v2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLE = "ai_provider_credentials"
_PROXY_CONFIG_TABLE = "proxy_config"
_PREFIX = "enc:v1:"
_PROXY_CONFIG_KEY = "secret_encryption_key_b64"

_log = logging.getLogger("alembic.runtime.migration")


# ── master key resolution (sync) ─────────────────────────────────────────


def _bytes_to_fernet_key(raw: bytes) -> bytes:
    """Same conversion contract as ``mcp_proxy.tools.secret_encrypt``:
    accept either 32 raw bytes or the urlsafe-base64 form, normalise
    to the form Fernet expects."""
    if len(raw) == 32:
        return base64.urlsafe_b64encode(raw)
    if len(raw) == 44:
        decoded = base64.urlsafe_b64decode(raw)
        if len(decoded) != 32:
            raise ValueError(
                "secret_encryption_key_b64 decodes to non-32-byte material",
            )
        return raw
    raise ValueError(
        f"secret_encryption_key_b64 unexpected length {len(raw)}; "
        "expected 32 raw bytes or 44 urlsafe-base64 chars",
    )


def _resolve_master_key(bind) -> bytes:
    """Sync mirror of ``_load_or_create_master_key`` for migration use.

    Precedence matches the runtime helper:
      1. ``MCP_PROXY_SECRET_ENCRYPTION_KEY_B64`` env.
      2. ``proxy_config`` row.
      3. Mint + persist on cold install.
    """
    env_val = os.environ.get("MCP_PROXY_SECRET_ENCRYPTION_KEY_B64", "").strip()
    if env_val:
        try:
            raw = base64.urlsafe_b64decode(env_val)
        except Exception as exc:
            raise RuntimeError(
                "MCP_PROXY_SECRET_ENCRYPTION_KEY_B64 is not valid "
                "urlsafe-base64",
            ) from exc
        return _bytes_to_fernet_key(raw)

    row = bind.execute(
        sa.text(
            f"SELECT value FROM {_PROXY_CONFIG_TABLE} WHERE key = :k"
        ),
        {"k": _PROXY_CONFIG_KEY},
    ).fetchone()

    if row is not None and row[0]:
        try:
            raw = base64.urlsafe_b64decode(row[0])
        except Exception as exc:
            raise RuntimeError(
                f"{_PROXY_CONFIG_KEY} in proxy_config is not valid "
                "urlsafe-base64",
            ) from exc
        return _bytes_to_fernet_key(raw)

    # Cold install — mint + persist. Same insert-or-update shape used
    # by ``mcp_proxy.db.set_config`` so the runtime helper picks the
    # value up on next boot.
    raw = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(raw).decode()
    _log.info(
        "secret_encryption_key minted by migration 0032 and persisted "
        "to proxy_config. Override via MCP_PROXY_SECRET_ENCRYPTION_KEY_B64."
    )
    # Portable upsert: DELETE-then-INSERT inside the migration's
    # transaction. Works on SQLite + Postgres without dialect branches.
    bind.execute(
        sa.text(
            f"DELETE FROM {_PROXY_CONFIG_TABLE} WHERE key = :k"
        ),
        {"k": _PROXY_CONFIG_KEY},
    )
    bind.execute(
        sa.text(
            f"INSERT INTO {_PROXY_CONFIG_TABLE} (key, value) "
            f"VALUES (:k, :v)"
        ),
        {"k": _PROXY_CONFIG_KEY, "v": encoded},
    )
    return _bytes_to_fernet_key(raw)


# ── row walker ───────────────────────────────────────────────────────────


def _migrate_rows(direction: str) -> None:
    """Walk every row and upgrade / downgrade the envelope, synchronously.

    direction = "encrypt" → wrap plaintext in enc:v1:<token>
    direction = "decrypt" → unwrap enc:v1: back to plaintext

    Idempotent: encrypt skips ``enc:v1:`` rows, decrypt skips plain rows.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())
    if _TABLE not in table_names:
        return
    if _PROXY_CONFIG_TABLE not in table_names:
        # Should never happen — proxy_config is part of the 0001
        # initial snapshot — but bail rather than crash the bundle if
        # an exotic legacy DB somehow lacks it.
        _log.warning(
            "0032: %s table missing, skipping data migration",
            _PROXY_CONFIG_TABLE,
        )
        return

    rows = bind.execute(
        sa.text(f"SELECT provider, creds_json FROM {_TABLE}"),
    ).fetchall()
    if not rows:
        return

    # Lazy import — see module-level note. demo_network/proxy-init parses
    # this file but never reaches this branch (its DB has no rows), so it
    # must not need ``cryptography`` installed.
    from cryptography.fernet import Fernet, InvalidToken

    key = _resolve_master_key(bind)
    fernet = Fernet(key)

    for provider, blob in rows:
        if blob is None or blob == "":
            continue
        if direction == "encrypt":
            if blob.startswith(_PREFIX):
                continue  # already enveloped
            token = fernet.encrypt(blob.encode("utf-8")).decode("utf-8")
            new_blob = _PREFIX + token
        else:
            if not blob.startswith(_PREFIX):
                continue  # already plaintext
            try:
                new_blob = fernet.decrypt(
                    blob[len(_PREFIX):].encode("utf-8"),
                ).decode("utf-8")
            except InvalidToken as exc:
                raise RuntimeError(
                    f"0032 downgrade: row provider={provider!r} cannot "
                    "be decrypted with the current master key — likely "
                    "the key was rotated since upgrade ran"
                ) from exc
        bind.execute(
            sa.text(
                f"UPDATE {_TABLE} SET creds_json = :c "
                f" WHERE provider = :p"
            ),
            {"c": new_blob, "p": provider},
        )


def upgrade() -> None:
    _migrate_rows("encrypt")


def downgrade() -> None:
    _migrate_rows("decrypt")
