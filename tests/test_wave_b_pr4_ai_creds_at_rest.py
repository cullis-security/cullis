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
    import base64, secrets
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
    import base64, secrets
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
