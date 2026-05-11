"""Wave B PR4 — B1 AI provider creds at-rest encryption.

Audit ref: imp/audits/2026-05-11-track-4-secrets-supply-chain.md H-01.

Pre-fix the AI provider credentials lived as plaintext JSON in
``ai_provider_credentials.creds_json``. Anyone with read access to
the SQLite file or a Postgres backup recovered every upstream LLM
API key in cleartext.

Post-fix:
- Writes go through ``encrypt_at_rest`` → row stores ``enc:v1:<token>``
- Reads go through ``decrypt_at_rest`` → caller sees the original JSON
- Master key resolution: env > proxy_config row > random on cold install
- Migration 0032 walks existing plaintext rows and upgrades them to v1
"""
from __future__ import annotations

import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

import pytest
import pytest_asyncio
from sqlalchemy import text

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.tools.secret_encrypt import (
    _PREFIX,
    _reset_master_key_for_tests,
    decrypt_at_rest,
    encrypt_at_rest,
)

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def fresh_db(tmp_path, monkeypatch):
    db_file = tmp_path / "ai-creds.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.delenv("MCP_PROXY_SECRET_ENCRYPTION_KEY_B64", raising=False)
    _reset_master_key_for_tests()
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        _reset_master_key_for_tests()


# ─── encrypt_at_rest / decrypt_at_rest round-trip ───


async def test_encrypt_at_rest_round_trip(fresh_db):
    plaintext = '{"api_key":"sk-ant-api03-DEADBEEF"}'
    blob = await encrypt_at_rest(plaintext)
    assert blob.startswith(_PREFIX)
    # The cleartext key must NOT appear in the envelope.
    assert "sk-ant-api03-DEADBEEF" not in blob
    decrypted = await decrypt_at_rest(blob)
    assert decrypted == plaintext


async def test_encrypt_at_rest_passthrough_on_empty(fresh_db):
    assert await encrypt_at_rest("") == ""
    assert await encrypt_at_rest(None) is None


async def test_decrypt_at_rest_passthrough_on_legacy_plaintext(fresh_db):
    """Migration-pending rows that still carry plaintext JSON must
    be readable. The decrypt helper returns them as-is so the rest of
    the code keeps working while 0032 rolls out."""
    legacy = '{"api_key":"sk-legacy-plaintext"}'
    assert await decrypt_at_rest(legacy) == legacy


async def test_decrypt_at_rest_raises_on_wrong_key(monkeypatch, fresh_db):
    """Operator rotated MCP_PROXY_SECRET_ENCRYPTION_KEY_B64 without
    re-encrypting rows. The helper must fail loudly — falling back to
    treating ciphertext as plaintext would be a worse failure mode."""
    blob = await encrypt_at_rest('{"api_key":"x"}')
    # Rotate the key; clear the cache.
    import base64
    import secrets
    new_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    monkeypatch.setenv("MCP_PROXY_SECRET_ENCRYPTION_KEY_B64", new_key)
    _reset_master_key_for_tests()
    with pytest.raises(RuntimeError, match="cannot decrypt"):
        await decrypt_at_rest(blob)


async def test_master_key_persisted_to_proxy_config(fresh_db):
    # Cold install: helper auto-mints + persists to proxy_config.
    await encrypt_at_rest("seed")
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT value FROM proxy_config "
                " WHERE key = 'secret_encryption_key_b64'"
            )
        )).first()
    assert row is not None
    assert len(row[0]) >= 40  # base64 of 32 bytes


async def test_env_override_takes_precedence(monkeypatch, fresh_db):
    import base64
    import secrets
    raw = secrets.token_bytes(32)
    encoded = base64.urlsafe_b64encode(raw).decode()
    monkeypatch.setenv("MCP_PROXY_SECRET_ENCRYPTION_KEY_B64", encoded)
    _reset_master_key_for_tests()
    blob = await encrypt_at_rest("payload")
    # Verify the env value, not a freshly-minted random, was used:
    # decrypt with the same env → success.
    assert await decrypt_at_rest(blob) == "payload"
    # And the proxy_config row was NOT seeded (env path skips it).
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT value FROM proxy_config "
                " WHERE key = 'secret_encryption_key_b64'"
            )
        )).first()
    assert row is None


# ─── upsert_ai_provider_creds + get round-trip ───


async def test_upsert_then_get_round_trips_creds(fresh_db):
    from mcp_proxy.db import (
        get_ai_provider_creds,
        upsert_ai_provider_creds,
    )
    await upsert_ai_provider_creds(
        provider="anthropic",
        creds={"api_key": "sk-ant-api03-DEADBEEF"},
        enabled=True,
        updated_by="admin",
    )
    fetched = await get_ai_provider_creds("anthropic")
    assert fetched is not None
    assert fetched["creds"] == {"api_key": "sk-ant-api03-DEADBEEF"}
    assert fetched["enabled"] is True
    # Verify the row on disk is enveloped, not plaintext.
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT creds_json FROM ai_provider_credentials "
                " WHERE provider = 'anthropic'"
            )
        )).first()
    assert row[0].startswith(_PREFIX)
    assert "sk-ant-api03-DEADBEEF" not in row[0]


async def test_list_decrypts_every_row(fresh_db):
    from mcp_proxy.db import (
        list_ai_provider_creds,
        upsert_ai_provider_creds,
    )
    await upsert_ai_provider_creds(
        "anthropic", {"api_key": "sk-ant"}, updated_by="admin",
    )
    await upsert_ai_provider_creds(
        "openai", {"api_key": "sk-openai"}, updated_by="admin",
    )
    rows = await list_ai_provider_creds()
    by_provider = {r["provider"]: r["creds"] for r in rows}
    assert by_provider["anthropic"] == {"api_key": "sk-ant"}
    assert by_provider["openai"] == {"api_key": "sk-openai"}


async def test_legacy_plaintext_row_still_readable(fresh_db):
    """A row written before B1 (plaintext JSON) must still be readable
    via get_ai_provider_creds. The 0032 migration upgrades it on the
    next deploy; until then the runtime is forward-compatible."""
    from datetime import datetime, timezone
    legacy_payload = '{"api_key":"sk-legacy-plain"}'
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO ai_provider_credentials "
                "(provider, creds_json, enabled, updated_at, updated_by) "
                "VALUES ('legacyprov', :c, 1, :ts, 'admin')"
            ),
            {"c": legacy_payload, "ts": datetime.now(timezone.utc).isoformat()},
        )
    from mcp_proxy.db import get_ai_provider_creds
    fetched = await get_ai_provider_creds("legacyprov")
    assert fetched["creds"] == {"api_key": "sk-legacy-plain"}


# ── Migration 0032 with rows present (Bug #8 regression) ────────────────


def test_migration_0032_upgrades_rows_with_plaintext_payload(tmp_path):
    """Bug #8 regression: pre-fix 0032 called the async ``encrypt_at_rest``
    helper via ``loop.run_until_complete(...)`` inside alembic's
    ``connection.run_sync(do_run_migrations)`` bridge. The new event loop
    deadlocked against the outer ``asyncio.run`` driving the migration,
    the coroutine was created but never awaited, the container exited
    with code 3 the very first time ``ai_provider_credentials`` was
    non-empty, and the Mastio bundle went into restart loop.

    All existing 0032 tests run against a FRESH DB (no rows in
    ``ai_provider_credentials``) so the buggy branch was never reached
    — this is the gap the dogfood surfaced.

    This test seeds two plaintext rows at revision 0031, runs alembic
    upgrade head, and asserts both rows now carry the ``enc:v1:`` prefix.
    A fresh master key is minted by the migration into ``proxy_config``
    on cold-install; the test round-trips through that key to confirm
    the ciphertext decrypts back to the original payload.
    """
    import asyncio
    import sqlite3
    from alembic import command
    from alembic.config import Config as AlembicConfig

    from mcp_proxy.db import _alembic_config  # type: ignore[attr-defined]
    from mcp_proxy.tools.secret_encrypt import _PREFIX as RUNTIME_PREFIX

    db_file = tmp_path / "migration-0032.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    sync_url = f"sqlite:///{db_file}"

    # 1. Upgrade to 0031 only (before the encryption migration).
    cfg: AlembicConfig = _alembic_config(url)
    command.upgrade(cfg, "0031_audit_append_only_v2")

    # 2. Seed plaintext rows directly in the table.
    seed_payloads = {
        "anthropic": '{"api_key":"sk-ant-plaintext"}',
        "openai":    '{"api_key":"sk-openai-plaintext"}',
    }
    from datetime import datetime, timezone
    with sqlite3.connect(str(db_file)) as conn:
        for provider, payload in seed_payloads.items():
            conn.execute(
                "INSERT INTO ai_provider_credentials "
                "(provider, creds_json, enabled, updated_at, updated_by) "
                "VALUES (?, ?, 1, ?, 'test')",
                (provider, payload, datetime.now(timezone.utc).isoformat()),
            )
        conn.commit()

    # 3. Apply 0032. Pre-fix this raises RuntimeWarning and the bind
    #    transaction never persists; post-fix it walks the rows sync.
    command.upgrade(cfg, "head")

    # 4. Confirm rows are now enveloped + decryptable with the persisted
    #    master key.
    with sqlite3.connect(str(db_file)) as conn:
        rows = dict(
            conn.execute(
                "SELECT provider, creds_json FROM ai_provider_credentials"
            ).fetchall(),
        )
        master_row = conn.execute(
            "SELECT value FROM proxy_config WHERE key = 'secret_encryption_key_b64'",
        ).fetchone()

    assert master_row is not None, "migration must persist a fresh master key"
    encoded_key = master_row[0]
    import base64
    raw_key = base64.urlsafe_b64decode(encoded_key)
    assert len(raw_key) == 32, "master key must be 32 raw bytes"

    from cryptography.fernet import Fernet
    fernet = Fernet(base64.urlsafe_b64encode(raw_key))
    for provider, original in seed_payloads.items():
        stored = rows[provider]
        assert stored.startswith(RUNTIME_PREFIX), (
            f"row {provider} not enveloped: {stored[:32]}"
        )
        decrypted = fernet.decrypt(stored[len(RUNTIME_PREFIX):].encode()).decode()
        assert decrypted == original, f"round-trip mismatch for {provider}"


def test_migration_0032_idempotent_on_already_encrypted_rows(tmp_path):
    """Running upgrade twice (or after a partial deploy that already
    enveloped some rows) must not double-wrap."""
    import sqlite3
    import base64
    from alembic import command
    from cryptography.fernet import Fernet

    from mcp_proxy.db import _alembic_config  # type: ignore[attr-defined]
    from mcp_proxy.tools.secret_encrypt import _PREFIX as RUNTIME_PREFIX

    db_file = tmp_path / "migration-0032-idem.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    cfg = _alembic_config(url)
    command.upgrade(cfg, "0031_audit_append_only_v2")

    # Seed one row already enveloped with a known key + one plaintext.
    raw_key = b"\x42" * 32
    encoded_key = base64.urlsafe_b64encode(raw_key).decode()
    fernet = Fernet(base64.urlsafe_b64encode(raw_key))
    pre_encrypted = RUNTIME_PREFIX + fernet.encrypt(
        b'{"api_key":"sk-already-wrapped"}',
    ).decode()
    from datetime import datetime, timezone
    with sqlite3.connect(str(db_file)) as conn:
        # Pin the master key in proxy_config so the migration uses it
        # (not a random one). Both rows must round-trip with this key.
        conn.execute(
            "INSERT INTO proxy_config (key, value) VALUES (?, ?)",
            ("secret_encryption_key_b64", encoded_key),
        )
        conn.execute(
            "INSERT INTO ai_provider_credentials "
            "(provider, creds_json, enabled, updated_at, updated_by) "
            "VALUES ('prewrapped', ?, 1, ?, 'test')",
            (pre_encrypted, datetime.now(timezone.utc).isoformat()),
        )
        conn.execute(
            "INSERT INTO ai_provider_credentials "
            "(provider, creds_json, enabled, updated_at, updated_by) "
            "VALUES ('plainnew', ?, 1, ?, 'test')",
            ('{"api_key":"sk-plain"}', datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    command.upgrade(cfg, "head")

    with sqlite3.connect(str(db_file)) as conn:
        rows = dict(
            conn.execute(
                "SELECT provider, creds_json FROM ai_provider_credentials"
            ).fetchall(),
        )

    # The pre-wrapped row stays exactly as we left it (no double-wrap,
    # no rewrap with a fresh nonce).
    assert rows["prewrapped"] == pre_encrypted
    # The plain row gets wrapped exactly once.
    assert rows["plainnew"].startswith(RUNTIME_PREFIX)
    inner = rows["plainnew"][len(RUNTIME_PREFIX):]
    assert not inner.startswith(RUNTIME_PREFIX), "double-wrapped!"


def test_migration_0032_downgrade_reverses_envelope(tmp_path):
    """Downgrade unwraps enc:v1: back to plaintext for rollback paths.
    Idempotent on rows that were already plain."""
    import sqlite3
    import base64
    from alembic import command
    from cryptography.fernet import Fernet

    from mcp_proxy.db import _alembic_config  # type: ignore[attr-defined]
    from mcp_proxy.tools.secret_encrypt import _PREFIX as RUNTIME_PREFIX

    db_file = tmp_path / "migration-0032-down.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    cfg = _alembic_config(url)
    command.upgrade(cfg, "0031_audit_append_only_v2")

    raw_key = b"\x37" * 32
    encoded_key = base64.urlsafe_b64encode(raw_key).decode()
    fernet = Fernet(base64.urlsafe_b64encode(raw_key))
    original_payload = '{"api_key":"sk-roundtrip"}'
    wrapped = RUNTIME_PREFIX + fernet.encrypt(
        original_payload.encode(),
    ).decode()
    from datetime import datetime, timezone
    with sqlite3.connect(str(db_file)) as conn:
        conn.execute(
            "INSERT INTO proxy_config (key, value) VALUES (?, ?)",
            ("secret_encryption_key_b64", encoded_key),
        )
        conn.execute(
            "INSERT INTO ai_provider_credentials "
            "(provider, creds_json, enabled, updated_at, updated_by) "
            "VALUES ('wrapped', ?, 1, ?, 'test')",
            (wrapped, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    command.upgrade(cfg, "head")
    command.downgrade(cfg, "0031_audit_append_only_v2")

    with sqlite3.connect(str(db_file)) as conn:
        stored = conn.execute(
            "SELECT creds_json FROM ai_provider_credentials WHERE provider = 'wrapped'",
        ).fetchone()[0]
    assert stored == original_payload
