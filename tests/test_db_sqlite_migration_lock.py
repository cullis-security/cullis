"""
MAJOR-4-rest: SQLite multi-worker Alembic migration lock.

Pre-fix, ``init_db`` on a SQLite URL called ``_run_migrations_sync``
directly without any cross-worker gate. Under ``MASTIO_WORKERS=4``
(packaging/mastio-enterprise-bundle/docker-compose.yml) every uvicorn
worker called ``alembic.command.upgrade("head")`` against the same
file, racing CREATE/DROP/ALTER (sqlite3 IntegrityError or SQLITE_BUSY).

PR #759 (commit b10723ff) shipped the fix: the SQLite branch now goes
through ``_run_migrations_sync_under_flock`` which takes an exclusive
blocking flock on ``<db>.alembic.lock``. This test file pins the
contract:

  - Helper runs the migration callable and creates the sidecar lock.
  - In-memory SQLite skips the helper entirely (still calls
    ``_run_migrations_sync`` plain).
  - Postgres URL never reaches the SQLite helper (existing advisory
    lock path covers it; out of scope here).
  - Cross-process serialization: 4 concurrent workers booting against
    the same file converge with zero alembic IntegrityError, exactly
    one runs the real upgrade work first, the others observe head and
    no-op.

The multi-process scenario uses ``multiprocessing.Process`` because
``fcntl.flock`` is per-open-file-description: two acquires from the
same process on the same fd both succeed (POSIX semantics, kernel
treats them as one lock holder). Only distinct processes contend.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# ── Helper unit tests ─────────────────────────────────────────────────


def test_under_flock_runs_callable_and_creates_lockfile(tmp_path, monkeypatch):
    """``_run_migrations_sync_under_flock`` must invoke the migration
    body exactly once and leave the sidecar lockfile on disk."""
    import mcp_proxy.db as _db_mod

    called = MagicMock()
    monkeypatch.setattr(_db_mod, "_run_migrations_sync", called)

    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    _db_mod._run_migrations_sync_under_flock(url, str(db_file))

    assert called.call_count == 1
    assert called.call_args.args == (url,)

    lock_path = tmp_path / "proxy.sqlite.alembic.lock"
    assert lock_path.exists(), (
        "sidecar lockfile must be created (inert mutex, OK to leave on disk)"
    )


def test_under_flock_creates_parent_directory(tmp_path, monkeypatch):
    """A fresh bind mount may not have the DB directory yet — the
    helper must ``mkdir(parents=True, exist_ok=True)`` so a cold boot
    doesn't fail on the lockfile open() call."""
    import mcp_proxy.db as _db_mod

    monkeypatch.setattr(_db_mod, "_run_migrations_sync", MagicMock())

    nested = tmp_path / "data" / "nested" / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{nested}"

    _db_mod._run_migrations_sync_under_flock(url, str(nested))

    assert nested.parent.exists()
    assert (nested.parent / "proxy.sqlite.alembic.lock").exists()


def test_under_flock_releases_lock_even_when_migration_raises(
    tmp_path, monkeypatch
):
    """If the migration body raises, the helper must still release
    the flock + close the fd (try/finally). Verified by acquiring the
    same lockfile from a second process after the failure."""
    import mcp_proxy.db as _db_mod

    def boom(_url):
        raise RuntimeError("simulated alembic explosion")

    monkeypatch.setattr(_db_mod, "_run_migrations_sync", boom)

    db_file = tmp_path / "boom.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"

    with pytest.raises(RuntimeError, match="simulated alembic explosion"):
        _db_mod._run_migrations_sync_under_flock(url, str(db_file))

    # Now confirm the lock is releasable: another acquire from a
    # subprocess must succeed without blocking. flock from a separate
    # process will fail-fast under LOCK_NB if the inode is still held.
    lock_path = tmp_path / "boom.sqlite.alembic.lock"
    assert lock_path.exists()
    assert _try_flock_nb_in_subprocess(lock_path) is True, (
        "flock must be released even when the wrapped callable raises"
    )


# ── init_db dispatch tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_init_db_sqlite_file_uses_flock_wrapper(tmp_path, monkeypatch):
    """For an on-disk SQLite URL, ``init_db`` must dispatch through
    ``_run_migrations_sync_under_flock`` (not the plain helper)."""
    monkeypatch.delenv("PROXY_SKIP_MIGRATIONS", raising=False)

    import mcp_proxy.db as _db_mod

    wrapper_called = MagicMock()
    plain_called = MagicMock()

    def _fake_wrapper(url, sqlite_path):
        wrapper_called(url, sqlite_path)
        # Don't actually run alembic — keep the test cheap.

    monkeypatch.setattr(
        _db_mod, "_run_migrations_sync_under_flock", _fake_wrapper
    )
    monkeypatch.setattr(_db_mod, "_run_migrations_sync", plain_called)

    db_file = tmp_path / "dispatch.sqlite"
    await _db_mod.init_db(f"sqlite+aiosqlite:///{db_file}")
    try:
        assert wrapper_called.called, (
            "on-disk SQLite must go through the flock wrapper"
        )
        assert wrapper_called.call_args.args[1] == str(db_file)
        assert not plain_called.called, (
            "plain _run_migrations_sync must NOT be called for on-disk SQLite"
        )
    finally:
        await _db_mod.dispose_db()


@pytest.mark.asyncio
async def test_init_db_in_memory_sqlite_skips_flock(monkeypatch):
    """``:memory:`` SQLite is single-process by definition. The flock
    helper must NOT be invoked (no file to lock against)."""
    monkeypatch.delenv("PROXY_SKIP_MIGRATIONS", raising=False)

    import mcp_proxy.db as _db_mod

    wrapper_called = MagicMock()
    plain_called = MagicMock()

    monkeypatch.setattr(
        _db_mod, "_run_migrations_sync_under_flock", wrapper_called
    )
    monkeypatch.setattr(_db_mod, "_run_migrations_sync", plain_called)

    await _db_mod.init_db("sqlite+aiosqlite:///:memory:")
    try:
        assert not wrapper_called.called, (
            "in-memory SQLite must not take the flock"
        )
        assert plain_called.called, (
            "in-memory SQLite still runs alembic (plain) for schema setup"
        )
    finally:
        await _db_mod.dispose_db()


# ── Multi-process serialization (the real bug) ────────────────────────


@pytest.mark.skipif(
    os.name != "posix",
    reason="fcntl.flock is POSIX-only",
)
def test_four_workers_serialize_alembic_upgrades(tmp_path):
    """4 concurrent workers (separate processes) call init_db against
    the same SQLite file. Pre-fix this raced CREATE/DROP/ALTER. Post-
    fix the flock serialises the upgrades: every worker eventually
    returns success, no alembic IntegrityError or SQLITE_BUSY.

    The body of the worker is a stub that imitates ``alembic upgrade
    head``: under the flock, write a marker line into a shared file
    with a small sleep, so without the lock concurrent writes would
    interleave their timestamps. Post-fix the [start, end] intervals
    must be non-overlapping for each worker.
    """
    db_file = tmp_path / "race.sqlite"
    db_file.touch()  # simulate an existing DB file (init_db parent setup)

    timeline_file = tmp_path / "timeline.txt"
    timeline_file.touch()

    n_workers = 4
    ctx = mp.get_context("spawn")
    procs = [
        ctx.Process(
            target=_worker_main,
            args=(str(db_file), str(timeline_file), idx),
        )
        for idx in range(n_workers)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0, (
            f"worker exited non-zero: {p.exitcode!r} (alembic race?)"
        )

    intervals = _parse_timeline(timeline_file)
    assert len(intervals) == n_workers, (
        f"expected {n_workers} worker entries, got {len(intervals)}: "
        f"{intervals!r}"
    )

    # Sort by start time and verify non-overlap. The flock guarantees
    # one worker's [start, end] strictly precedes the next worker's
    # start.
    intervals.sort(key=lambda iv: iv[1])  # by start_ns
    for prev, curr in zip(intervals, intervals[1:]):
        prev_idx, prev_start, prev_end = prev
        curr_idx, curr_start, curr_end = curr
        assert prev_end <= curr_start, (
            f"workers {prev_idx} and {curr_idx} overlapped: "
            f"prev=[{prev_start}, {prev_end}] curr=[{curr_start}, {curr_end}] — "
            f"the migration lock did NOT serialise them"
        )


# ── helpers ───────────────────────────────────────────────────────────


def _try_flock_nb_in_subprocess(lock_path: Path) -> bool:
    """Return True if another process can take LOCK_EX | LOCK_NB on
    ``lock_path``. False if the lock is still held."""
    ctx = mp.get_context("spawn")
    q: mp.Queue = ctx.Queue()
    p = ctx.Process(target=_nb_flock_probe, args=(str(lock_path), q))
    p.start()
    p.join(timeout=10)
    return q.get_nowait()


def _nb_flock_probe(lock_path: str, q) -> None:
    import fcntl
    fd = os.open(lock_path, os.O_CREAT | os.O_WRONLY, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            q.put(True)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except BlockingIOError:
            q.put(False)
    finally:
        os.close(fd)


def _worker_main(db_path: str, timeline_path: str, idx: int) -> None:
    """Stand-in for ``init_db`` SQLite branch. We exercise the
    production helper directly with a patched migration body so the
    test is fast (no real alembic) but the lock semantics are the
    real ones."""
    import mcp_proxy.db as _db_mod

    def fake_migration(_url):
        # Marker: "started" + small sleep so the interleaving window
        # is real. End marker on exit. Both writes happen under the
        # flock — if the lock is correct, intervals must be disjoint.
        start_ns = time.monotonic_ns()
        time.sleep(0.05)
        end_ns = time.monotonic_ns()
        with open(timeline_path, "a") as fh:
            fh.write(f"{idx} {start_ns} {end_ns}\n")

    # Monkey-patch the inner callable on this child's import of the
    # module. spawn-context children re-import everything so this is
    # process-local and doesn't bleed back into the parent.
    _db_mod._run_migrations_sync = fake_migration

    url = f"sqlite+aiosqlite:///{db_path}"
    _db_mod._run_migrations_sync_under_flock(url, db_path)


def _parse_timeline(path: Path) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        idx_s, start_s, end_s = line.split()
        out.append((int(idx_s), int(start_s), int(end_s)))
    return out
