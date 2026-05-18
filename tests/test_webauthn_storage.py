"""ADR-033 Phase 2 — credential persistence helpers in
:mod:`mcp_proxy.auth.webauthn.storage`.

Exercises the SQL surface (``save_credential`` / ``load_credentials_for_principal``
/ ``load_credential_records_for_verification`` / ``update_sign_count`` /
``delete_credential``) plus the in-memory challenge store. The
third-party ``webauthn`` library is not touched.
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

from mcp_proxy.auth.webauthn import storage as wa_storage
from mcp_proxy.db import dispose_db, init_db


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "webauthn_storage.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


async def test_save_and_load_credential_roundtrip(proxy_db):
    await wa_storage.save_credential(
        principal_id="acme::user::alice",
        credential_id=b"\xaa" * 16,
        credential_public_key=b"\xbb" * 64,
        sign_count=0,
        aaguid=b"\xcc" * 16,
        transports=["usb", "nfc"],
        name="YubiKey 5C",
    )
    rows = await wa_storage.load_credentials_for_principal("acme::user::alice")
    assert len(rows) == 1
    row = rows[0]
    assert row.credential_id == b"\xaa" * 16
    assert row.transports == ["usb", "nfc"]
    assert row.name == "YubiKey 5C"
    assert row.last_used_at is None


async def test_load_credentials_returns_empty_for_unknown_principal(proxy_db):
    rows = await wa_storage.load_credentials_for_principal("acme::user::bob")
    assert rows == []


async def test_load_credential_records_returns_public_key(proxy_db):
    await wa_storage.save_credential(
        principal_id="acme::user::carol",
        credential_id=b"\xdd" * 16,
        credential_public_key=b"\xee" * 64,
        sign_count=7,
        aaguid=None,
        transports=None,
        name=None,
    )
    records = await wa_storage.load_credential_records_for_verification(
        "acme::user::carol",
    )
    assert len(records) == 1
    record = records[0]
    assert record.credential_id == b"\xdd" * 16
    assert record.credential_public_key == b"\xee" * 64
    assert record.sign_count == 7


async def test_update_sign_count_stamps_last_used(proxy_db):
    cid = b"\x10" * 16
    await wa_storage.save_credential(
        principal_id="acme::user::dora",
        credential_id=cid,
        credential_public_key=b"\x20" * 64,
        sign_count=0,
        aaguid=None,
        transports=None,
        name="Touch ID",
    )
    await wa_storage.update_sign_count(credential_id=cid, new_sign_count=42)
    rows = await wa_storage.load_credentials_for_principal("acme::user::dora")
    assert rows[0].sign_count == 42
    assert rows[0].last_used_at is not None


async def test_delete_credential_returns_true_on_hit(proxy_db):
    cid = b"\x30" * 16
    await wa_storage.save_credential(
        principal_id="acme::user::eve",
        credential_id=cid,
        credential_public_key=b"\x40" * 64,
        sign_count=0,
        aaguid=None,
        transports=None,
        name=None,
    )
    deleted = await wa_storage.delete_credential(
        principal_id="acme::user::eve", credential_id=cid,
    )
    assert deleted is True
    rows = await wa_storage.load_credentials_for_principal("acme::user::eve")
    assert rows == []


async def test_delete_credential_refuses_cross_principal(proxy_db):
    cid = b"\x50" * 16
    await wa_storage.save_credential(
        principal_id="acme::user::frank",
        credential_id=cid,
        credential_public_key=b"\x60" * 64,
        sign_count=0,
        aaguid=None,
        transports=None,
        name=None,
    )
    # Different principal — the WHERE clause must refuse the delete.
    deleted = await wa_storage.delete_credential(
        principal_id="acme::user::imposter", credential_id=cid,
    )
    assert deleted is False
    # Row still present for frank.
    rows = await wa_storage.load_credentials_for_principal("acme::user::frank")
    assert len(rows) == 1


async def test_in_memory_challenge_store_roundtrip():
    store = wa_storage.InMemoryChallengeStore()
    await store.put(
        principal_id="acme::user::alice", ceremony="register",
        value="challenge-xyz", ttl=60,
    )
    out = await store.take(principal_id="acme::user::alice", ceremony="register")
    assert out == "challenge-xyz"
    # Single-use: a second take must return None.
    again = await store.take(
        principal_id="acme::user::alice", ceremony="register",
    )
    assert again is None


async def test_in_memory_challenge_store_separates_ceremonies():
    store = wa_storage.InMemoryChallengeStore()
    await store.put(
        principal_id="acme::user::alice", ceremony="register",
        value="reg-challenge", ttl=60,
    )
    await store.put(
        principal_id="acme::user::alice", ceremony="authenticate",
        value="auth-challenge", ttl=60,
    )
    assert await store.take(
        principal_id="acme::user::alice", ceremony="register",
    ) == "reg-challenge"
    assert await store.take(
        principal_id="acme::user::alice", ceremony="authenticate",
    ) == "auth-challenge"
