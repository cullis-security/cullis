"""Tests for cullis_connector.identity.users / users_db — ADR-025 Phase 1.

Covers the DB layer in isolation: bcrypt verify, must_change_password
toggling, list filters, delete + reset-password semantics, and the
0600 permission enforcement on the SQLite file.
"""
from __future__ import annotations

import os
import stat

import pytest
from sqlalchemy.exc import IntegrityError

from cullis_connector.identity.users import (
    create_user,
    delete_user,
    get_user_by_name,
    list_users,
    mark_password_changed,
    reset_password,
    set_password_hash,
    verify_password,
)
from cullis_connector.identity.users_db import (
    USERS_DB_FILENAME,
    dispose_users_engines,
    get_users_session,
    init_users_db,
)


pytestmark = pytest.mark.asyncio


@pytest.fixture
def config_dir(tmp_path):
    d = tmp_path / "connector"
    d.mkdir(parents=True, exist_ok=True)
    yield d


@pytest.fixture(autouse=True)
async def _cleanup_engines():
    """Each test gets a fresh engine cache so per-tmp_path DBs don't leak."""
    yield
    await dispose_users_engines()


# ── happy path ──────────────────────────────────────────────────────────


async def test_create_user_happy_path(config_dir):
    async with get_users_session(config_dir) as session:
        user = await create_user(
            session,
            name="mario",
            password="temp123!secure",
            must_change=True,
            display_name="Mario Rossi",
        )
    assert user.user_name == "mario"
    assert user.display_name == "Mario Rossi"
    assert user.must_change_password is True
    assert user.disabled is False
    assert user.password_changed_at is None
    assert user.created_at  # ISO timestamp


async def test_get_user_by_name_returns_none_for_missing(config_dir):
    async with get_users_session(config_dir) as session:
        result = await get_user_by_name(session, "nobody")
    assert result is None


async def test_create_user_then_get(config_dir):
    async with get_users_session(config_dir) as session:
        await create_user(
            session, name="alice", password="superlong-pwd",
        )
    async with get_users_session(config_dir) as session:
        fetched = await get_user_by_name(session, "alice")
    assert fetched is not None
    assert fetched.user_name == "alice"


# ── duplicates ──────────────────────────────────────────────────────────


async def test_duplicate_user_raises_integrity_error(config_dir):
    async with get_users_session(config_dir) as session:
        await create_user(session, name="dup", password="password1")

    with pytest.raises(IntegrityError):
        async with get_users_session(config_dir) as session:
            await create_user(session, name="dup", password="password2")


# ── bcrypt verify ──────────────────────────────────────────────────────


async def test_verify_password_pass_and_fail(config_dir):
    async with get_users_session(config_dir) as session:
        await create_user(
            session, name="bob", password="correct-horse-battery",
        )

    async with get_users_session(config_dir) as session:
        assert await verify_password(
            session, "bob", "correct-horse-battery",
        ) is True
        assert await verify_password(
            session, "bob", "wrong-password",
        ) is False
        assert await verify_password(
            session, "bob", "",
        ) is False


async def test_verify_password_unknown_user_returns_false(config_dir):
    # Sanity: never expose existence via timing — verify_password
    # short-circuits to False before bcrypt runs.
    async with get_users_session(config_dir) as session:
        assert await verify_password(session, "ghost", "anything-here") is False


# ── must_change_password flag ──────────────────────────────────────────


async def test_mark_password_changed_clears_flag(config_dir):
    async with get_users_session(config_dir) as session:
        await create_user(
            session, name="charlie", password="initial-pwd",
            must_change=True,
        )

    async with get_users_session(config_dir) as session:
        ok = await mark_password_changed(session, "charlie")
    assert ok is True

    async with get_users_session(config_dir) as session:
        u = await get_user_by_name(session, "charlie")
    assert u is not None
    assert u.must_change_password is False
    assert u.password_changed_at is not None


# ── list filters ───────────────────────────────────────────────────────


async def test_list_users_filter_by_q_and_disabled(config_dir):
    async with get_users_session(config_dir) as session:
        await create_user(
            session, name="aaa", password="password1",
            display_name="Mario Rossi",
        )
        await create_user(
            session, name="bbb", password="password2",
            display_name="Lucia Bianchi",
        )
        await create_user(
            session, name="ccc", password="password3",
        )

    # Substring match on display_name (case-insensitive).
    async with get_users_session(config_dir) as session:
        rows = await list_users(session, q="mario")
    assert {u.user_name for u in rows} == {"aaa"}

    async with get_users_session(config_dir) as session:
        rows = await list_users(session, q="MARIO")
    assert {u.user_name for u in rows} == {"aaa"}

    async with get_users_session(config_dir) as session:
        rows = await list_users(session, q="bb")  # matches user_name
    assert {u.user_name for u in rows} == {"bbb"}

    # disabled filter — none disabled in fixture, both filters work.
    async with get_users_session(config_dir) as session:
        rows = await list_users(session, disabled=False)
    assert len(rows) == 3
    async with get_users_session(config_dir) as session:
        rows = await list_users(session, disabled=True)
    assert rows == []


# ── delete ─────────────────────────────────────────────────────────────


async def test_delete_user_removes_row(config_dir):
    async with get_users_session(config_dir) as session:
        await create_user(session, name="todel", password="goodpassword")

    async with get_users_session(config_dir) as session:
        ok = await delete_user(session, "todel")
    assert ok is True

    async with get_users_session(config_dir) as session:
        assert await get_user_by_name(session, "todel") is None


async def test_delete_user_returns_false_if_missing(config_dir):
    async with get_users_session(config_dir) as session:
        ok = await delete_user(session, "ghost")
    assert ok is False


# ── reset password ─────────────────────────────────────────────────────


async def test_reset_password_sets_must_change_true(config_dir):
    async with get_users_session(config_dir) as session:
        await create_user(
            session, name="resetme", password="old-password",
            must_change=False,  # already changed once
        )

    async with get_users_session(config_dir) as session:
        ok = await reset_password(session, "resetme", "new-temp-pwd")
    assert ok is True

    async with get_users_session(config_dir) as session:
        u = await get_user_by_name(session, "resetme")
        # New password verifies; old does not.
        assert await verify_password(session, "resetme", "new-temp-pwd") is True
        assert await verify_password(session, "resetme", "old-password") is False
    assert u is not None
    assert u.must_change_password is True


async def test_set_password_hash_keeps_or_clears_must_change(config_dir):
    async with get_users_session(config_dir) as session:
        await create_user(session, name="user1", password="initial1234")

    async with get_users_session(config_dir) as session:
        ok = await set_password_hash(
            session, "user1", "user-chosen-pw", must_change=False,
        )
    assert ok is True

    async with get_users_session(config_dir) as session:
        u = await get_user_by_name(session, "user1")
    assert u is not None
    assert u.must_change_password is False


# ── validation ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_name",
    ["", " ", "with space", "exclam!", "a" * 65, "slash/in/name", "qu'ote"],
)
async def test_create_user_rejects_bad_username(config_dir, bad_name):
    async with get_users_session(config_dir) as session:
        with pytest.raises(ValueError):
            await create_user(session, name=bad_name, password="password1")


@pytest.mark.parametrize("bad_pw", ["", "short", "       ", "  \t\n  "])
async def test_create_user_rejects_bad_password(config_dir, bad_pw):
    async with get_users_session(config_dir) as session:
        with pytest.raises(ValueError):
            await create_user(session, name="okuser", password=bad_pw)


# ── perms ──────────────────────────────────────────────────────────────


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only chmod check")
async def test_users_db_file_is_chmod_0600(config_dir):
    await init_users_db(config_dir)
    db_path = config_dir / USERS_DB_FILENAME
    assert db_path.exists()
    mode = stat.S_IMODE(db_path.stat().st_mode)
    # Owner-only read/write — no group, no world bits.
    assert mode == 0o600, (
        f"users.db permissions are {oct(mode)} — expected 0o600. "
        "bcrypt hashes must not be group/world readable."
    )
