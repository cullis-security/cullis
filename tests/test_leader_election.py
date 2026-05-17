"""Cross-worker leader election (Cluster A, Wave 2b).

Pin SQLite flock + NoopLeader + the factory dispatch. Postgres
``pg_try_advisory_lock`` path is exercised in `test_postgres_bindings`
when a Postgres URL is in the env — these tests stay sqlite + noop so
they run on every shard without external infra.
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

from mcp_proxy.lifespan.leader_election import (
    NoopLeader,
    PostgresAdvisoryLeader,
    SQLiteFlockLeader,
    get_leader,
)


# ── factory dispatch ─────────────────────────────────────────────────


def test_factory_picks_postgres_for_postgres_url():
    leader = get_leader(
        "task_pg",
        db_url="postgresql+asyncpg://u:p@h/d",
    )
    assert isinstance(leader, PostgresAdvisoryLeader)
    assert leader.task_name == "task_pg"


def test_factory_picks_sqlite_for_sqlite_file_url(tmp_path):
    db = tmp_path / "x.sqlite"
    leader = get_leader(
        "task_sqlite",
        db_url=f"sqlite+aiosqlite:///{db}",
    )
    assert isinstance(leader, SQLiteFlockLeader)


def test_factory_returns_noop_for_in_memory_sqlite():
    leader = get_leader(
        "task_mem",
        db_url="sqlite+aiosqlite:///:memory:",
    )
    assert isinstance(leader, NoopLeader)


def test_factory_returns_noop_for_missing_url():
    leader = get_leader("task_none", db_url="")
    assert isinstance(leader, NoopLeader)


def test_factory_returns_noop_for_unknown_scheme():
    leader = get_leader("task_weird", db_url="mysql://h/d")
    assert isinstance(leader, NoopLeader)


# ── postgres key derivation ──────────────────────────────────────────


def test_postgres_keys_are_deterministic_and_distinct():
    """Two task names produce two distinct int64-safe keys."""
    k1 = PostgresAdvisoryLeader._key_for("task_a")
    k2 = PostgresAdvisoryLeader._key_for("task_b")
    k1b = PostgresAdvisoryLeader._key_for("task_a")
    assert k1 == k1b
    assert k1 != k2
    # Both keys fit in int64-positive range (Postgres advisory_lock
    # accepts bigint = int64 signed).
    assert 0 <= k1 < (1 << 63)
    assert 0 <= k2 < (1 << 63)


# ── noop leader ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_noop_leader_always_wins():
    leader = NoopLeader("task_noop")
    assert await leader.acquire() is True
    assert leader.held is True
    await leader.release()
    assert leader.held is False


@pytest.mark.asyncio
async def test_noop_leader_acquire_is_idempotent():
    leader = NoopLeader("task_noop_idem")
    assert await leader.acquire() is True
    assert await leader.acquire() is True
    await leader.release()


# ── sqlite flock leader ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sqlite_flock_first_caller_wins(tmp_path):
    db = tmp_path / "lock-test.sqlite"
    leader = SQLiteFlockLeader("task_one", db)
    assert await leader.acquire() is True
    assert leader.held is True
    await leader.release()
    assert leader.held is False


@pytest.mark.asyncio
async def test_sqlite_flock_concurrent_only_one_wins(tmp_path):
    """Two SQLiteFlockLeader instances on the same lockfile: only one
    wins. The other gets False (LOCK_NB). After the winner releases,
    the loser CAN now acquire — verifies LOCK_UN releases the inode
    lock properly."""
    db = tmp_path / "race-test.sqlite"

    a = SQLiteFlockLeader("task_race", db)
    b = SQLiteFlockLeader("task_race", db)

    got_a = await a.acquire()
    got_b = await b.acquire()

    assert got_a is True
    assert got_b is False
    assert a.held is True
    assert b.held is False

    await a.release()
    assert a.held is False

    got_b_after = await b.acquire()
    assert got_b_after is True
    await b.release()


@pytest.mark.asyncio
async def test_sqlite_flock_writes_pid_for_ops_visibility(tmp_path):
    db = tmp_path / "pid-test.sqlite"
    leader = SQLiteFlockLeader("task_pid", db)
    assert await leader.acquire() is True

    lock_file = db.with_name(f"{db.name}.task_pid.lock")
    assert lock_file.exists()
    content = lock_file.read_text().strip()
    assert content == str(os.getpid())

    await leader.release()


@pytest.mark.asyncio
async def test_sqlite_flock_release_when_not_held_is_noop(tmp_path):
    db = tmp_path / "release-noop.sqlite"
    leader = SQLiteFlockLeader("task_unheld", db)
    # Never acquired — release must not raise.
    await leader.release()
    assert leader.held is False


@pytest.mark.asyncio
async def test_sqlite_flock_lockfile_path_uses_task_name(tmp_path):
    db = tmp_path / "naming.sqlite"
    a = SQLiteFlockLeader("task_a", db)
    b = SQLiteFlockLeader("task_b", db)

    # Different task names share the same DB but get distinct
    # lockfiles, so they don't contend.
    assert await a.acquire() is True
    assert await b.acquire() is True

    await a.release()
    await b.release()


# ── separation between tasks ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_two_different_tasks_can_both_acquire(tmp_path):
    """task_x and task_y on the same DB don't block each other."""
    db = tmp_path / "two-tasks.sqlite"
    x = get_leader("task_x", db_url=f"sqlite+aiosqlite:///{db}")
    y = get_leader("task_y", db_url=f"sqlite+aiosqlite:///{db}")

    assert await x.acquire() is True
    assert await y.acquire() is True

    await x.release()
    await y.release()
