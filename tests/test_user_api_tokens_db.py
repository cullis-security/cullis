"""DB helpers for ``user_api_tokens`` (ADR-027 Phase 1).

Covers the migration (0029_user_api_tokens) end-to-end:
  - Table + indices created by Alembic
  - mint returns cleartext token only at creation
  - verify resolves cleartext to row dict (without hash)
  - verify rejects unknown / malformed / revoked / expired tokens
  - revoke is idempotent (second revoke returns False)
  - list filters revoked rows by default
  - touch updates last_used_at + last_used_ip best-effort

Uses an isolated SQLite file per test so the Alembic chain runs for
real, matching the pattern in ``test_pending_updates_db.py``.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import inspect

from mcp_proxy.db import (
    dispose_db,
    get_db,
    get_user_api_token,
    init_db,
    list_user_api_tokens,
    mint_user_api_token,
    revoke_user_api_token,
    touch_user_api_token,
    verify_user_api_token,
)

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def fresh_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()


async def _table_exists(table: str) -> bool:
    async with get_db() as conn:
        names = await conn.run_sync(
            lambda sync_conn: set(inspect(sync_conn).get_table_names())
        )
    return table in names


async def _index_names(table: str) -> set[str]:
    async with get_db() as conn:
        indices = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_indexes(table)
        )
    return {idx["name"] for idx in indices}


# ── migration ─────────────────────────────────────────────────────────


async def test_migration_creates_table_and_indices(fresh_db):
    assert await _table_exists("user_api_tokens"), "table missing after init_db"
    idx_names = await _index_names("user_api_tokens")
    assert "idx_user_api_tokens_principal" in idx_names
    assert "idx_user_api_tokens_last4" in idx_names


# ── mint ──────────────────────────────────────────────────────────────


async def test_mint_returns_cleartext_only_once(fresh_db):
    minted = await mint_user_api_token(
        principal_id="acme::user::alice",
        label="Cursor laptop",
        created_by="acme::admin",
    )
    assert minted["token"].startswith("culk_")
    assert len(minted["token"]) == 57  # culk_ + 52 base32 chars
    assert minted["token_last4"] == minted["token"][-4:]
    assert minted["principal_id"] == "acme::user::alice"
    assert minted["label"] == "Cursor laptop"
    assert minted["created_by"] == "acme::admin"
    assert minted["scope_providers"] == []
    assert minted["scope_paths"] == ["/v1/*"]
    assert minted["expires_at"] is None
    assert minted["revoked_at"] is None

    # get_user_api_token never returns cleartext
    fetched = await get_user_api_token(minted["id"])
    assert fetched is not None
    assert "token" not in fetched
    assert "token_hash" not in fetched
    assert fetched["token_last4"] == minted["token_last4"]


async def test_mint_requires_principal_label_creator(fresh_db):
    with pytest.raises(ValueError):
        await mint_user_api_token(
            principal_id="",
            label="x",
            created_by="admin",
        )
    with pytest.raises(ValueError):
        await mint_user_api_token(
            principal_id="acme::user::alice",
            label="   ",
            created_by="admin",
        )
    with pytest.raises(ValueError):
        await mint_user_api_token(
            principal_id="acme::user::alice",
            label="x",
            created_by="",
        )


async def test_mint_persists_scope_fields(fresh_db):
    minted = await mint_user_api_token(
        principal_id="acme::user::bob",
        label="LibreChat staging",
        created_by="acme::admin",
        scope_providers=["anthropic", "openai"],
        scope_paths=["/v1/chat/completions", "/v1/models"],
    )
    fetched = await get_user_api_token(minted["id"])
    assert fetched["scope_providers"] == ["anthropic", "openai"]
    assert fetched["scope_paths"] == ["/v1/chat/completions", "/v1/models"]


async def test_mint_two_tokens_for_same_user_are_independent(fresh_db):
    a = await mint_user_api_token(
        principal_id="acme::user::carol",
        label="laptop",
        created_by="acme::admin",
    )
    b = await mint_user_api_token(
        principal_id="acme::user::carol",
        label="desktop",
        created_by="acme::admin",
    )
    assert a["id"] != b["id"]
    assert a["token"] != b["token"]
    assert a["token_last4"] != b["token_last4"] or True  # collision possible
    rows = await list_user_api_tokens("acme::user::carol")
    assert {r["id"] for r in rows} == {a["id"], b["id"]}


# ── verify ────────────────────────────────────────────────────────────


async def test_verify_accepts_valid_token(fresh_db):
    minted = await mint_user_api_token(
        principal_id="acme::user::dave",
        label="test",
        created_by="acme::admin",
    )
    resolved = await verify_user_api_token(minted["token"])
    assert resolved is not None
    assert resolved["id"] == minted["id"]
    assert resolved["principal_id"] == "acme::user::dave"
    assert "token_hash" not in resolved
    assert "token" not in resolved


async def test_verify_rejects_unknown_token(fresh_db):
    fake = "culk_" + "a" * 52
    assert await verify_user_api_token(fake) is None


async def test_verify_rejects_malformed_token(fresh_db):
    assert await verify_user_api_token("") is None
    assert await verify_user_api_token("nope") is None
    assert await verify_user_api_token("sk-ant-xxx") is None
    assert await verify_user_api_token("culk_short") is None
    assert await verify_user_api_token("culk_" + "a" * 99) is None


async def test_verify_rejects_revoked_token(fresh_db):
    minted = await mint_user_api_token(
        principal_id="acme::user::erin",
        label="test",
        created_by="acme::admin",
    )
    assert await verify_user_api_token(minted["token"]) is not None
    revoked = await revoke_user_api_token(minted["id"], revoked_by="acme::admin")
    assert revoked is True
    assert await verify_user_api_token(minted["token"]) is None


async def test_verify_rejects_expired_token(fresh_db):
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    minted = await mint_user_api_token(
        principal_id="acme::user::frank",
        label="test",
        created_by="acme::admin",
        expires_at=past,
    )
    assert await verify_user_api_token(minted["token"]) is None


async def test_verify_accepts_future_expiry(fresh_db):
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    minted = await mint_user_api_token(
        principal_id="acme::user::grace",
        label="test",
        created_by="acme::admin",
        expires_at=future,
    )
    resolved = await verify_user_api_token(minted["token"])
    assert resolved is not None
    assert resolved["expires_at"] == future


# ── revoke ────────────────────────────────────────────────────────────


async def test_revoke_is_idempotent(fresh_db):
    minted = await mint_user_api_token(
        principal_id="acme::user::heidi",
        label="test",
        created_by="acme::admin",
    )
    assert await revoke_user_api_token(minted["id"], revoked_by="acme::admin") is True
    assert await revoke_user_api_token(minted["id"], revoked_by="acme::admin") is False


async def test_revoke_unknown_id_returns_false(fresh_db):
    assert await revoke_user_api_token("nonexistent-id", revoked_by="acme::admin") is False


# ── list ──────────────────────────────────────────────────────────────


async def test_list_filters_revoked_by_default(fresh_db):
    a = await mint_user_api_token(
        principal_id="acme::user::ivan",
        label="active",
        created_by="acme::admin",
    )
    b = await mint_user_api_token(
        principal_id="acme::user::ivan",
        label="revoked",
        created_by="acme::admin",
    )
    await revoke_user_api_token(b["id"], revoked_by="acme::admin")
    rows = await list_user_api_tokens("acme::user::ivan")
    assert [r["id"] for r in rows] == [a["id"]]


async def test_list_include_revoked(fresh_db):
    a = await mint_user_api_token(
        principal_id="acme::user::jane",
        label="active",
        created_by="acme::admin",
    )
    b = await mint_user_api_token(
        principal_id="acme::user::jane",
        label="revoked",
        created_by="acme::admin",
    )
    await revoke_user_api_token(b["id"], revoked_by="acme::admin")
    rows = await list_user_api_tokens("acme::user::jane", include_revoked=True)
    assert {r["id"] for r in rows} == {a["id"], b["id"]}


async def test_list_all_users_when_principal_none(fresh_db):
    await mint_user_api_token(
        principal_id="acme::user::ken",
        label="t1",
        created_by="acme::admin",
    )
    await mint_user_api_token(
        principal_id="acme::user::leo",
        label="t2",
        created_by="acme::admin",
    )
    rows = await list_user_api_tokens(None)
    assert len(rows) == 2
    assert {r["principal_id"] for r in rows} == {"acme::user::ken", "acme::user::leo"}


# ── touch ─────────────────────────────────────────────────────────────


async def test_touch_updates_last_used(fresh_db):
    minted = await mint_user_api_token(
        principal_id="acme::user::mia",
        label="test",
        created_by="acme::admin",
    )
    pre = await get_user_api_token(minted["id"])
    assert pre["last_used_at"] is None
    assert pre["last_used_ip"] is None

    await touch_user_api_token(minted["id"], client_ip="10.0.0.42")
    post = await get_user_api_token(minted["id"])
    assert post["last_used_at"] is not None
    assert post["last_used_ip"] == "10.0.0.42"


async def test_touch_unknown_id_does_not_raise(fresh_db):
    # Best-effort: must not raise even when id doesn't exist
    await touch_user_api_token("nonexistent-id", client_ip="10.0.0.99")
