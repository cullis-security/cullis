"""Tests for the Connector atomic-write helper + secret-write call sites (F-B-401).

The pre-2026-05-20 idiom ``Path.write_text(...) + chmod(0o600)`` left a
microsecond window during which the file was readable by other UIDs on
the box. The fix routes all secret writes through
``cullis_connector._atomic_write.write_with_mode``, which uses
``tempfile.mkstemp`` (creates 0600 by default) + ``os.fchmod`` +
``os.replace``.

We test two things:

  1. The helper itself: file lands with the requested mode, content is
     correct, no race-window file ever appears with permissive mode,
     atomic replace works (existing file is overwritten with the new
     content).
  2. The migrated call sites (auth.py _write_new_local_token,
     identity/store.py _write_atomic, shared/keystore.py, shared/wire.py
     _ensure_cookie_secret) deliver files at mode 0600 first try.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest


# ── Helper unit tests ─────────────────────────────────────────────


def test_write_with_mode_creates_file_with_requested_mode(tmp_path):
    """The helper must lay the file down at the requested mode on the
    first stat. No transient permissive-mode file ever shows up."""
    from cullis_connector._atomic_write import write_with_mode

    target = tmp_path / "secret.bin"
    write_with_mode(target, data=b"hello", mode=0o600)

    assert target.read_bytes() == b"hello"
    # 0600 only — no group or other bit.
    perm = stat.S_IMODE(target.stat().st_mode)
    assert perm == 0o600, f"expected 0o600, got {oct(perm)}"


def test_write_text_with_mode_encodes_utf8(tmp_path):
    from cullis_connector._atomic_write import write_text_with_mode

    target = tmp_path / "secret.txt"
    write_text_with_mode(target, text="cafè\n", mode=0o600)

    assert target.read_text(encoding="utf-8") == "cafè\n"
    perm = stat.S_IMODE(target.stat().st_mode)
    assert perm == 0o600


def test_write_with_mode_overwrites_existing_atomically(tmp_path):
    from cullis_connector._atomic_write import write_with_mode

    target = tmp_path / "secret.bin"
    target.write_bytes(b"old-content")
    target.chmod(0o644)  # pretend it was created loose by an old version

    write_with_mode(target, data=b"new-content", mode=0o600)

    assert target.read_bytes() == b"new-content"
    perm = stat.S_IMODE(target.stat().st_mode)
    assert perm == 0o600


def test_write_with_mode_cleans_up_temp_on_failure(tmp_path, monkeypatch):
    """If os.replace fails, the temp file must not linger in the
    destination directory — otherwise the next caller sees an extra
    .tmp file with secret content even on the failure path."""
    from cullis_connector import _atomic_write

    target = tmp_path / "secret.bin"

    def _boom(*_args, **_kwargs):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", _boom)

    with pytest.raises(OSError, match="simulated"):
        _atomic_write.write_with_mode(target, data=b"hello", mode=0o600)

    # No leftover .tmp file in the parent directory.
    leftover = [p for p in tmp_path.iterdir() if p.name.startswith("secret.bin.")]
    assert leftover == [], f"temp file leaked on failure path: {leftover}"


def test_write_with_mode_creates_parent_directory(tmp_path):
    from cullis_connector._atomic_write import write_with_mode

    target = tmp_path / "nested" / "deep" / "secret.bin"
    write_with_mode(target, data=b"x", mode=0o600)
    assert target.is_file()
    perm = stat.S_IMODE(target.stat().st_mode)
    assert perm == 0o600


# ── Call site regression: local Bearer token ──────────────────────


def test_local_token_file_lands_0600(tmp_path):
    """The Bearer minted by ``_write_new_local_token`` must hit disk
    at mode 0600 on first stat — never readable by other UIDs."""
    from cullis_connector.ambassador.auth import (
        LOCAL_TOKEN_FILENAME,
        rotate_local_token,
    )

    token = rotate_local_token(tmp_path)
    assert len(token) == 64  # 32 bytes hex
    token_path = tmp_path / LOCAL_TOKEN_FILENAME
    assert token_path.is_file()
    perm = stat.S_IMODE(token_path.stat().st_mode)
    assert perm == 0o600, f"local Bearer file mode {oct(perm)} — should be 0o600"


# ── Call site regression: identity store keys ─────────────────────


def test_identity_store_write_atomic_uses_helper(tmp_path):
    """``_write_atomic`` is the entry point for agent.key + dpop.jwk +
    metadata. After F-B-401 it delegates to the helper."""
    from cullis_connector.identity import store

    target = tmp_path / "agent.key"
    store._write_atomic(target, b"---PRIVATE KEY---", mode=0o600)
    assert target.read_bytes() == b"---PRIVATE KEY---"
    perm = stat.S_IMODE(target.stat().st_mode)
    assert perm == 0o600


def test_ensure_private_key_permissions_warns_on_loose_mode(tmp_path, caplog):
    """Loose-perm detection now logs WARNING (audit F-B-401) rather
    than silently chmodding. The file still gets fixed — leaving it
    world-readable would be worse — but ops sees the drift signal."""
    if os.name != "posix":
        pytest.skip("posix-only path")
    from cullis_connector.identity import store

    target = tmp_path / "agent.key"
    target.write_bytes(b"---PRIVATE KEY---")
    target.chmod(0o644)  # simulate a backup-restore with loose perms

    import logging
    captured: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    logger = logging.getLogger("cullis_connector.identity.store")
    h = _Capture()
    h.setLevel(logging.WARNING)
    logger.addHandler(h)
    try:
        store._ensure_private_key_permissions(target)
    finally:
        logger.removeHandler(h)

    # File was tightened.
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    # The drift was reported.
    assert any("F-B-401" in m for m in captured), (
        f"expected F-B-401 warning, got {captured!r}"
    )


# ── Call site regression: shared keystore (Frontdesk per-user) ────


def test_shared_keystore_persists_user_key_0600(tmp_path):
    """``shared.keystore.UserKeyStore.get_or_create`` writes the
    per-user EC private key at 0600. The first-time-provision path is
    the one F-B-401 fixed."""
    import asyncio

    from cullis_connector.ambassador.shared.keystore import UserKeyStore

    ks = UserKeyStore(base_dir=tmp_path)
    pem = asyncio.run(ks.get_or_create("acme/user/alice"))
    assert "BEGIN" in pem and "PRIVATE KEY" in pem

    # Find the file (UserKeyStore hashes the principal_id for the filename)
    keys = [p for p in tmp_path.iterdir() if p.is_file() and not p.name.endswith(".tmp")]
    assert len(keys) == 1, f"expected exactly one key file, got {keys}"
    perm = stat.S_IMODE(keys[0].stat().st_mode)
    assert perm == 0o600


# ── Call site regression: shared cookie secret ───────────────────


def test_shared_cookie_secret_lands_0600(tmp_path):
    """``bootstrap_cookie_secret`` mints the HMAC key for every Frontdesk
    shared-mode session cookie. Must land 0600."""
    from cullis_connector.ambassador.shared import wire

    secret = wire.bootstrap_cookie_secret(tmp_path)
    assert len(secret) == wire.SECRET_LEN_BYTES

    secret_path = tmp_path / wire.COOKIE_SECRET_FILENAME
    assert secret_path.is_file()
    perm = stat.S_IMODE(secret_path.stat().st_mode)
    assert perm == 0o600
