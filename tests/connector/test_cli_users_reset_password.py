"""CLI tests for ``cullis-connector users reset-password`` — P3 MAJOR-1.

Covers the four customer-facing branches:

* explicit ``--new-password`` succeeds and rewrites the bcrypt hash;
* generated path prints "Temporary password:" plus a URL-safe token;
* missing user → exit 1 + "not found" on stderr;
* ``must_change_password`` is forced back to 1 after a successful reset.

Reuses the existing ``users.db`` engine cache invalidation pattern
(``dispose_users_engines``) so each test sees a clean SQLite file at
its own ``tmp_path``.
"""
from __future__ import annotations

import asyncio

import pytest

from cullis_connector.cli import main as cli_main
from cullis_connector.identity import get_users_session
from cullis_connector.identity.users import (
    LocalUser,
    create_user,
    verify_password,
)
from cullis_connector.identity.users_db import dispose_users_engines
from sqlalchemy import select


@pytest.fixture(autouse=True)
async def _cleanup_engines():
    yield
    await dispose_users_engines()


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Isolated config_dir for this test, exported via CLI flag."""
    cd = tmp_path / "connector"
    cd.mkdir(parents=True, exist_ok=True)
    # Avoid the CLI picking up the dev profile under ~/.cullis.
    monkeypatch.delenv("CULLIS_CONNECTOR_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CULLIS_PROFILE", raising=False)
    return cd


def _seed_user(config_dir, name: str, password: str = "initialpass") -> None:
    async def _run():
        async with get_users_session(config_dir) as session:
            await create_user(
                session, name=name, password=password, must_change=False,
            )
        await dispose_users_engines()

    asyncio.run(_run())


def _load_row(config_dir, name: str) -> LocalUser | None:
    async def _run():
        async with get_users_session(config_dir) as session:
            result = await session.execute(
                select(LocalUser).where(LocalUser.user_name == name)
            )
            row = result.scalar_one_or_none()
            # Detach so the row survives session teardown for assertions
            if row is not None:
                session.expunge(row)
            return row

    return asyncio.run(_run())


def test_users_reset_password_with_explicit_pwd(config_dir, capsys):
    _seed_user(config_dir, "alice", password="initialpass")

    exit_code = cli_main(
        [
            "users", "reset-password", "alice",
            "--new-password", "newstrongpw",
            "--config-dir", str(config_dir),
        ]
    )
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "Password reset for user 'alice'" in captured.out
    # Explicit-password path must NOT echo the password back.
    assert "newstrongpw" not in captured.out
    assert "User must change password at next login." in captured.out

    async def _check():
        async with get_users_session(config_dir) as session:
            assert await verify_password(session, "alice", "newstrongpw") is True
            # Old password is rejected.
            assert await verify_password(session, "alice", "initialpass") is False

    asyncio.run(_check())


def test_users_reset_password_generated(config_dir, capsys):
    _seed_user(config_dir, "bob", password="initialpass")

    exit_code = cli_main(
        [
            "users", "reset-password", "bob",
            "--config-dir", str(config_dir),
        ]
    )
    assert exit_code == 0

    out = capsys.readouterr().out
    assert "Temporary password:" in out
    # Extract the temp password and assert it works against the DB.
    line = next(
        ln for ln in out.splitlines() if ln.startswith("Temporary password:")
    )
    temp_pwd = line.split("Temporary password:", 1)[1].strip()
    # secrets.token_urlsafe(12) produces 16 ASCII chars.
    assert len(temp_pwd) >= 12
    assert temp_pwd.isascii()

    async def _check():
        async with get_users_session(config_dir) as session:
            assert await verify_password(session, "bob", temp_pwd) is True

    asyncio.run(_check())


def test_users_reset_password_user_not_found(config_dir, capsys):
    # users.db will be created empty on first session open
    exit_code = cli_main(
        [
            "users", "reset-password", "nosuchuser",
            "--new-password", "newstrongpw",
            "--config-dir", str(config_dir),
        ]
    )
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "not found" in err
    assert "nosuchuser" in err


def test_users_reset_password_forces_must_change(config_dir):
    _seed_user(config_dir, "carol", password="initialpass")
    # Sanity: seeded user has must_change=False (must_change_password=0)
    seeded = _load_row(config_dir, "carol")
    assert seeded is not None
    assert seeded.must_change_password == 0

    exit_code = cli_main(
        [
            "users", "reset-password", "carol",
            "--new-password", "newstrongpw",
            "--config-dir", str(config_dir),
        ]
    )
    assert exit_code == 0

    after = _load_row(config_dir, "carol")
    assert after is not None
    assert after.must_change_password == 1
