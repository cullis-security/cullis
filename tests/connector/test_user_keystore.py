"""Tests for :class:`UserKeyStore` (cullis_connector.ambassador.shared.keystore).

Covers:
  - get_or_create persists on first call, hits cache on second
  - same principal_id round-trips to the same PEM bytes
  - different principal_ids land on different files
  - chmod 0600 on the persisted PEM
  - invalidate() removes the file
  - empty / non-string principal_id rejected
  - concurrent get_or_create for the same principal returns the same PEM
"""
from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cullis_connector.ambassador.shared.keystore import (
    UserKeyStore,
    keystore_dir_for,
)


@pytest.mark.asyncio
async def test_get_or_create_persists_and_returns_same_pem(tmp_path: Path):
    store = UserKeyStore(tmp_path)
    pem1 = await store.get_or_create("acme.test/acme/user/mario")
    pem2 = await store.get_or_create("acme.test/acme/user/mario")
    assert pem1 == pem2
    assert "BEGIN PRIVATE KEY" in pem1
    priv = serialization.load_pem_private_key(pem1.encode(), password=None)
    assert isinstance(priv, ec.EllipticCurvePrivateKey)


@pytest.mark.asyncio
async def test_different_principals_get_different_keys(tmp_path: Path):
    store = UserKeyStore(tmp_path)
    a = await store.get_or_create("acme.test/acme/user/mario")
    b = await store.get_or_create("acme.test/acme/user/alice")
    assert a != b
    # Two files on disk now.
    files = list(tmp_path.glob("*.key.pem"))
    assert len(files) == 2


@pytest.mark.asyncio
async def test_persistence_survives_new_instance(tmp_path: Path):
    """The whole point of the fix: a fresh UserKeyStore instance over
    the same base_dir returns the same key as the previous instance.

    This is the exact scenario that breaks today — container restart =
    fresh process = fresh in-memory cache, and without the keystore the
    Mastio TOFU pin rejects the next CSR."""
    store1 = UserKeyStore(tmp_path)
    pem1 = await store1.get_or_create("acme.test/acme/user/mario")
    store2 = UserKeyStore(tmp_path)
    pem2 = await store2.get_or_create("acme.test/acme/user/mario")
    assert pem1 == pem2


@pytest.mark.asyncio
async def test_chmod_0600_on_persisted_key(tmp_path: Path):
    if os.name != "posix":
        pytest.skip("POSIX-only permission check")
    store = UserKeyStore(tmp_path)
    await store.get_or_create("acme.test/acme/user/mario")
    files = list(tmp_path.glob("*.key.pem"))
    assert len(files) == 1
    mode = files[0].stat().st_mode
    # No group/other read/write/execute bits.
    assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0
    # Owner can read+write.
    assert mode & stat.S_IRUSR
    assert mode & stat.S_IWUSR


@pytest.mark.asyncio
async def test_invalidate_removes_file(tmp_path: Path):
    store = UserKeyStore(tmp_path)
    await store.get_or_create("acme.test/acme/user/mario")
    assert len(list(tmp_path.glob("*.key.pem"))) == 1
    removed = await store.invalidate("acme.test/acme/user/mario")
    assert removed is True
    assert len(list(tmp_path.glob("*.key.pem"))) == 0
    # Invalidating again returns False.
    again = await store.invalidate("acme.test/acme/user/mario")
    assert again is False


@pytest.mark.asyncio
async def test_invalidate_then_recreate_yields_fresh_key(tmp_path: Path):
    store = UserKeyStore(tmp_path)
    pem1 = await store.get_or_create("acme.test/acme/user/mario")
    await store.invalidate("acme.test/acme/user/mario")
    pem2 = await store.get_or_create("acme.test/acme/user/mario")
    assert pem1 != pem2


@pytest.mark.asyncio
async def test_empty_principal_id_rejected(tmp_path: Path):
    store = UserKeyStore(tmp_path)
    with pytest.raises(ValueError):
        await store.get_or_create("")
    with pytest.raises(ValueError):
        await store.get_or_create("   ")


@pytest.mark.asyncio
async def test_concurrent_get_or_create_returns_same_pem(tmp_path: Path):
    """The lock must serialise create-then-read so two coroutines hitting
    a cold cache for the same principal don't end up with different keys
    persisted (the second write would clobber the first)."""
    store = UserKeyStore(tmp_path)
    results = await asyncio.gather(
        *[store.get_or_create("acme.test/acme/user/mario") for _ in range(20)],
    )
    assert all(r == results[0] for r in results)
    # Exactly one file persisted.
    assert len(list(tmp_path.glob("*.key.pem"))) == 1


def test_keystore_dir_for_returns_user_keys_subdir(tmp_path: Path):
    assert keystore_dir_for(tmp_path) == tmp_path / "user_keys"
