"""P1.4 — cert_thumbprint indices on ``agents`` and ``user_principals``.

Both lookups (cert rotation, revocation check, TOFU pin verification)
hit the column directly and have always done a full table scan. The
indices are declared two places:

* SQLAlchemy ``__table_args__`` so ``Base.metadata.create_all`` paths
  (notably the test fixtures and the dev-mode bootstrap) get them.
* Alembic ``t0o1p2q3r4s5_idx_thumbprint`` so production deploys that
  go through the migration chain get them.

This test asserts both code paths end up with the same index name on
the same column.
"""
from __future__ import annotations

import os
import subprocess
import sys
import sysconfig
import tempfile

import pytest
from sqlalchemy import inspect


# ── Path A: ORM create_all (what test fixtures use) ────────────────


@pytest.mark.asyncio
async def test_orm_create_all_emits_thumbprint_index():
    """The model-level Index entries must show up after create_all so
    test fixtures that never run Alembic still cover queries that
    rely on the index plan."""
    from tests.conftest import test_engine

    async with test_engine.begin() as conn:
        agents_idx = await conn.run_sync(
            lambda sc: {i["name"] for i in inspect(sc).get_indexes("agents")},
        )
        principals_idx = await conn.run_sync(
            lambda sc: {
                i["name"] for i in inspect(sc).get_indexes("user_principals")
            },
        )
    assert "idx_agents_cert_thumbprint" in agents_idx, agents_idx
    assert (
        "idx_user_principals_cert_thumbprint" in principals_idx
    ), principals_idx


# ── Path B: Alembic chain (what prod deploys use) ──────────────────


@pytest.mark.skipif(
    os.environ.get("CI_SKIP_ALEMBIC_SUBPROCESS") == "1",
    reason="alembic subprocess test disabled by env",
)
def test_alembic_upgrade_creates_thumbprint_indices():
    """Run the full Alembic chain end-to-end on a fresh sqlite file and
    verify both indices exist after ``upgrade head`` and disappear
    after ``downgrade -1``. Catches typos in the migration file
    (revision id, down_revision, index name) that the ORM path would
    silently mask."""
    import sqlite3

    db_path = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    db_path.close()
    url = f"sqlite+aiosqlite:///{db_path.name}"

    env = dict(os.environ)
    env["ADMIN_SECRET"] = "alembic-subprocess-test"
    env["DATABASE_URL"] = url

    cwd = _repo_root()
    cmd = _alembic_cmd()
    r = subprocess.run(
        cmd + ["upgrade", "head"],
        capture_output=True, text=True, env=env, cwd=cwd,
    )
    assert r.returncode == 0, (
        f"alembic upgrade head failed: stderr={r.stderr[-1500:]}"
    )

    con = sqlite3.connect(db_path.name)
    try:
        rows = con.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND name LIKE '%cert_thumbprint%'"
        ).fetchall()
        names = {r[0] for r in rows}
        assert "idx_agents_cert_thumbprint" in names, names
        assert "idx_user_principals_cert_thumbprint" in names, names
    finally:
        con.close()

    # PR #3 audit 2026-05-20: downgrade to the revision BEFORE the
    # thumbprint-index migration (t0o1p2q3r4s5_idx_thumb). Using a
    # named revision rather than ``-1`` keeps the test stable as more
    # migrations land on top.
    r = subprocess.run(
        cmd + ["downgrade", "s9n0o1p2q3r4_replica"],
        capture_output=True, text=True, env=env, cwd=cwd,
    )
    assert r.returncode == 0, (
        f"alembic downgrade failed: stderr={r.stderr[-1500:]}"
    )

    con = sqlite3.connect(db_path.name)
    try:
        rows = con.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND name LIKE '%cert_thumbprint%'"
        ).fetchall()
        assert not rows, rows
    finally:
        con.close()


def _repo_root() -> str:
    """Find the repo root by walking up from this file until alembic.ini
    sits next to us. Robust against being invoked from any cwd."""
    import pathlib
    here = pathlib.Path(__file__).resolve().parent
    for candidate in [here, *here.parents]:
        if (candidate / "alembic.ini").exists():
            return str(candidate)
    raise RuntimeError("alembic.ini not found from tests/ upwards")


def _alembic_cmd() -> list[str]:
    """Resolve the alembic invocation in the active environment.

    ``sysconfig`` points at the interpreter's own scripts directory
    (more portable than hard-coding ``.venv/bin/alembic`` or trusting
    ``$PATH``). When the entry-point is missing we fall back to
    ``python -m alembic``, which is always reachable as long as the
    package is installed.
    """
    scripts = sysconfig.get_path("scripts")
    cand = os.path.join(scripts, "alembic")
    if os.path.exists(cand):
        return [cand]
    return [sys.executable, "-m", "alembic"]
