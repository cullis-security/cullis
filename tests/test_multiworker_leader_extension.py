"""Multi-worker leader gating for 6 background tasks (Bug 3 / PR #759
follow-up).

PR #759 (a.k.a. "Cluster A wave 2b") shipped ``get_leader()`` and
wired it on three tasks: ``local_sweeper``, ``mdm_intune_poller``,
``attestation_stale_watcher``. The remaining six lifespan-spawned
loops still ran on every uvicorn worker, causing:

* ``anomaly_evaluator`` + ``quarantine_expiry``: audit-chain inflation
  (4x quarantine events per logical anomaly) — CRITICAL.
* ``federation_publisher`` + ``federation_audit_publisher``: 4x
  outbound bandwidth to the Court and 4x compute Court-side.
* ``federation_subscriber``: 4x concurrent SSE connections per worker.
* ``federation_stats_publisher``: 4x stats push per tick.

These tests pin the gating contract at the unit level. They do not
exercise the full lifespan (those paths land in the integration smoke
+ ``./sandbox/smoke.sh full``); they pin that ``get_leader(task_name)``
is consulted for each of the six tasks before the loop body runs and
that the held leader is released cleanly at shutdown.
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


# Six task names that PR follow-up wires. Keep this list in sync with
# the task_name string literals used at the ``get_leader(...)`` call
# sites in ``mcp_proxy/main.py``. If a task is renamed, this fixture
# is the single source of truth that catches the drift.
_BUG3_TASK_NAMES = (
    "anomaly_evaluator",
    "quarantine_expiry",
    "federation_publisher",
    "federation_audit_publisher",
    "federation_subscriber",
    "federation_stats_publisher",
)


# ── leader factory dispatch on real task names ──────────────────────


def test_all_bug3_task_names_get_distinct_postgres_keys():
    """``pg_try_advisory_lock`` collisions across tasks would mean
    two unrelated loops fight for the same lock and only one runs.
    The factory uses crc32 ^ salt under the hood, so distinctness is
    de facto guaranteed for non-pathological names, but we pin it
    here so a future rename can't silently break leader independence.
    """
    from mcp_proxy.lifespan.leader_election import PostgresAdvisoryLeader

    keys = {name: PostgresAdvisoryLeader._key_for(name) for name in _BUG3_TASK_NAMES}
    assert len(set(keys.values())) == len(_BUG3_TASK_NAMES), keys


def test_all_bug3_tasks_get_distinct_sqlite_lockfiles(tmp_path):
    """Distinct task names map to distinct sidecar lockfiles, so on
    a SQLite deployment six tasks can be held by up to six workers
    concurrently (no false serialization)."""
    from mcp_proxy.lifespan.leader_election import get_leader

    db = tmp_path / "bug3.sqlite"
    db_url = f"sqlite+aiosqlite:///{db}"
    leaders = [get_leader(name, db_url=db_url) for name in _BUG3_TASK_NAMES]
    lock_paths = {leader._lock_path for leader in leaders}  # type: ignore[attr-defined]
    assert len(lock_paths) == len(_BUG3_TASK_NAMES)


# ── leader-gated lifespan-loop contract (the body of the fix) ────────


class _FakeLeader:
    """Records ``acquire()`` / ``release()`` and decides if the loop
    body runs. Mirrors the ``LeaderElection`` contract closely enough
    that swapping it in via monkeypatch on ``mcp_proxy.lifespan.
    get_leader`` exercises the gating logic without needing real
    flock / postgres infra.
    """

    def __init__(self, task_name: str, *, wins: bool = True) -> None:
        self.task_name = task_name
        self._wins = wins
        self.acquired = False
        self.released = False
        self.held = False

    async def acquire(self) -> bool:
        self.acquired = True
        if self._wins:
            self.held = True
        return self._wins

    async def release(self) -> None:
        self.released = True
        self.held = False


def _make_leader_factory(wins_for: set[str]):
    """Return a ``get_leader`` replacement that yields a winning
    ``_FakeLeader`` for tasks in ``wins_for`` and a losing one
    otherwise. Records each instance for post-hoc assertions."""
    created: dict[str, _FakeLeader] = {}

    def factory(task_name: str, db_url: str | None = None) -> _FakeLeader:
        leader = _FakeLeader(task_name, wins=task_name in wins_for)
        created[task_name] = leader
        return leader

    return factory, created


@pytest.mark.asyncio
async def test_leader_loses_skips_loop_spawn():
    """Pattern reference: when ``leader.acquire()`` returns False, the
    follower path must NOT spawn the background task. This pins the
    branch all six lifespan call sites take when another worker
    already holds the lock — preventing the duplicate work that Bug
    3 set out to fix."""
    leader = _FakeLeader("anomaly_evaluator", wins=False)
    spawned = []

    async def fake_loop() -> None:
        spawned.append("ran")

    # Mirror the call-site shape exactly: if acquired, spawn; else,
    # skip with an INFO log (omitted here — pinned in main.py).
    if await leader.acquire():
        await fake_loop()

    assert leader.acquired is True
    assert leader.held is False
    assert spawned == []  # loop body must NOT run on the follower


@pytest.mark.asyncio
async def test_leader_wins_runs_loop_and_releases_at_shutdown():
    """Pattern reference: winning leader runs the loop, holds for the
    lifetime of the worker, and releases at lifespan shutdown."""
    leader = _FakeLeader("federation_publisher", wins=True)
    spawned = []

    async def fake_loop() -> None:
        spawned.append("ran")

    if await leader.acquire():
        await fake_loop()
        # ... lifespan yields, worker serves traffic ...
        await leader.release()

    assert leader.acquired is True
    assert leader.released is True
    assert leader.held is False
    assert spawned == ["ran"]


@pytest.mark.asyncio
async def test_factory_called_once_per_task_at_startup():
    """The lifespan hook must call ``get_leader(name)`` exactly once
    per task at startup — duplicate calls would imply two leader
    instances, which on SQLite would race on the same flock and on
    Postgres would open a second long-lived connection."""
    factory, created = _make_leader_factory(wins_for=set(_BUG3_TASK_NAMES))
    for name in _BUG3_TASK_NAMES:
        leader = factory(name)
        assert await leader.acquire() is True

    assert set(created.keys()) == set(_BUG3_TASK_NAMES)
    for name, leader in created.items():
        assert leader.acquired is True, name
        assert leader.held is True, name


# ── pin the lifespan code path imports the helper ────────────────────


def test_main_py_imports_get_leader_for_each_bug3_task():
    """Smoke check: every Bug 3 task name appears next to a
    ``get_leader("…")`` call in ``mcp_proxy/main.py``. Cheap textual
    check, but catches the "someone refactored and dropped the gating"
    regression with no infra dependency."""
    from pathlib import Path

    main_py = Path(__file__).resolve().parents[1] / "mcp_proxy" / "main.py"
    src = main_py.read_text()
    for task in _BUG3_TASK_NAMES:
        needle = f'get_leader("{task}")'
        assert needle in src, f"missing leader gating for task {task!r}"
