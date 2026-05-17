"""P3 MAJOR-A — packaging/mastio-bundle/deploy.sh refuses to start when
the operator points ``MCP_PROXY_DATABASE_URL`` at Postgres but a
non-empty ``./data/mcp_proxy.db`` is still on disk.

Failure mode this pins (192.168.122.170 dogfood, 2026-05-17): an
operator boots Mastio with the SQLite default, agents enroll against
the Org CA persisted in ``mcp_proxy.db``. The operator then edits
``proxy.env`` to point at Postgres and restarts. The Mastio lifespan
finds an empty Postgres → ``generate_org_ca(derive_org_id=True)`` (the
intended standalone bootstrap, ADR-006) mints a fresh CA. Every
previously enrolled Connector now fails TLS verify on
``/v1/principals/csr``. There is no automatic SQLite → Postgres
migration in the bundle, so the only safe behaviour is to refuse to
start and force the operator to pick a path explicitly.

These tests drive ``deploy.sh`` directly in a tmp bundle dir with a
PATH that has fake ``docker`` / ``ss`` binaries — the orphan check
runs before any docker call, so the fake binaries are never invoked
in the negative path. ``CULLIS_DEPLOY_EXIT_AFTER_CHECKS=1`` short-
circuits the script after the pre-flight checks for the positive
paths so we don't need to mock the full pull/up flow.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess
import textwrap

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BUNDLE_SRC = REPO_ROOT / "packaging" / "mastio-bundle"
COMMON_HELPERS = REPO_ROOT / "packaging" / "_common-deploy-helpers.sh"


def _stage_bundle(tmp_path: pathlib.Path) -> pathlib.Path:
    """Mirror the bundle layout into ``tmp_path`` so ``deploy.sh`` sees
    a real ``_common-deploy-helpers.sh`` next to its parent dir.

    The source uses ``source "$SCRIPT_DIR/../_common-deploy-helpers.sh"``
    so we reproduce the same parent/child layout the release tarball
    has after extraction (``cullis-mastio-bundle/`` lives inside
    ``packaging/``).
    """
    pkg = tmp_path / "packaging"
    bundle = pkg / "mastio-bundle"
    bundle.mkdir(parents=True)
    shutil.copy2(BUNDLE_SRC / "deploy.sh", bundle / "deploy.sh")
    shutil.copy2(BUNDLE_SRC / "docker-compose.yml", bundle / "docker-compose.yml")
    shutil.copy2(BUNDLE_SRC / "proxy.env.example", bundle / "proxy.env.example")
    shutil.copy2(COMMON_HELPERS, pkg / "_common-deploy-helpers.sh")
    (bundle / "deploy.sh").chmod(0o755)
    return bundle


def _stub_path(tmp_path: pathlib.Path) -> str:
    """A PATH stub directory shadowing ``docker`` and ``ss`` so the
    script can survive even if it reaches the post-check steps. The
    orphan guard exits BEFORE these are consulted in the failure cases;
    the success cases use ``CULLIS_DEPLOY_EXIT_AFTER_CHECKS=1`` to bail
    out before any docker call regardless.
    """
    stub = tmp_path / "stubpath"
    stub.mkdir()
    for name in ("docker", "ss", "curl"):
        p = stub / name
        p.write_text("#!/usr/bin/env bash\nexit 0\n")
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    # Compose v2 lookup: ``docker compose version`` must succeed.
    # The simple stub above returns 0 for any subcommand, so this works.
    real_path = os.environ.get("PATH", "")
    return f"{stub}:{real_path}"


def _write_proxy_env(bundle: pathlib.Path, **kv: str) -> None:
    lines = [f"{k}={v}" for k, v in kv.items()]
    (bundle / "proxy.env").write_text("\n".join(lines) + "\n")


def _seed_sqlite(bundle: pathlib.Path, size_bytes: int = 4096) -> pathlib.Path:
    data = bundle / "data"
    data.mkdir(exist_ok=True)
    db = data / "mcp_proxy.db"
    db.write_bytes(b"SQLite format 3\x00" + b"\x00" * (size_bytes - 16))
    return db


def _run_deploy(
    bundle: pathlib.Path,
    *extra_args: str,
    env_overrides: dict | None = None,
    exit_after_checks: bool = True,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PATH"] = _stub_path(bundle.parent.parent)
    if exit_after_checks:
        env["CULLIS_DEPLOY_EXIT_AFTER_CHECKS"] = "1"
    # Force MODE=development so the prod validation block does not
    # short-circuit the run on dev-default secrets. The MAJOR-A check
    # is independent of MODE.
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["bash", str(bundle / "deploy.sh"), *extra_args],
        cwd=str(bundle),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


# ── deploy.sh syntax + flag plumbing ──────────────────────────────────────


def test_deploy_sh_is_syntactically_valid():
    """``bash -n`` must accept the script — guards against a stray edit
    breaking the parser before any test exercises the runtime logic."""
    result = subprocess.run(
        ["bash", "-n", str(BUNDLE_SRC / "deploy.sh")],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_accept_data_loss_flag_is_advertised_in_help():
    """``--help`` must mention the override so a stuck operator can find
    the escape hatch without grepping the source."""
    result = subprocess.run(
        ["bash", str(BUNDLE_SRC / "deploy.sh"), "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "--accept-data-loss" in result.stdout
    # The help text should warn about Connector invalidation explicitly
    # so the operator understands the blast radius before passing the
    # flag.
    assert "Connector" in result.stdout or "re-enroll" in result.stdout


# ── MAJOR-A — orphan SQLite + Postgres URL ────────────────────────────────


def test_orphan_sqlite_with_postgres_url_refuses_to_start(tmp_path):
    """Test 1 — ./data/mcp_proxy.db non-empty AND
    MCP_PROXY_DATABASE_URL=postgresql+... → deploy.sh exits 1 with a
    clear, recoverable error."""
    bundle = _stage_bundle(tmp_path)
    _seed_sqlite(bundle)
    _write_proxy_env(
        bundle,
        MCP_PROXY_DATABASE_URL="postgresql+asyncpg://u:p@db:5432/cullis",
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )
    result = _run_deploy(bundle)
    combined = result.stdout + result.stderr
    assert result.returncode == 1, (
        f"expected exit 1 (refuse-to-start), got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    # The error message must mention the orphan file path AND the
    # Postgres URL so the operator immediately knows what to act on.
    assert "Orphan SQLite database" in combined
    assert "data/mcp_proxy.db" in combined
    assert "Postgres" in combined or "postgresql" in combined
    # All three recovery paths must be enumerated.
    assert "Roll back" in combined or "rollback" in combined.lower()
    assert "--accept-data-loss" in combined


def test_no_sqlite_file_with_postgres_url_proceeds(tmp_path):
    """Test 2 — ./data/mcp_proxy.db does not exist AND
    MCP_PROXY_DATABASE_URL=postgresql+... → deploy.sh proceeds past
    the guard (fresh Postgres bring-up, no enrolled agents to lose)."""
    bundle = _stage_bundle(tmp_path)
    # Intentionally do NOT seed ./data/mcp_proxy.db.
    _write_proxy_env(
        bundle,
        MCP_PROXY_DATABASE_URL="postgresql+asyncpg://u:p@db:5432/cullis",
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )
    result = _run_deploy(bundle)
    assert result.returncode == 0, (
        f"expected exit 0 (proceed), got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "Orphan SQLite database" not in (result.stdout + result.stderr)


def test_sqlite_default_url_proceeds_even_with_db_file(tmp_path):
    """Test 3 — ./data/mcp_proxy.db non-empty AND MCP_PROXY_DATABASE_URL
    unset (compose default = SQLite) → deploy.sh proceeds. This is the
    normal happy path on every restart of an already-initialized
    Mastio."""
    bundle = _stage_bundle(tmp_path)
    _seed_sqlite(bundle)
    _write_proxy_env(
        bundle,
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )
    result = _run_deploy(bundle)
    assert result.returncode == 0, (
        f"expected exit 0 (proceed, default SQLite), got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "Orphan SQLite database" not in (result.stdout + result.stderr)


def test_orphan_sqlite_with_postgres_url_and_accept_data_loss_proceeds(tmp_path):
    """Test 4 — ./data/mcp_proxy.db non-empty AND
    MCP_PROXY_DATABASE_URL=postgresql+... AND --accept-data-loss →
    deploy.sh proceeds with a loud warn (operator opted in to losing
    every enrolled Connector)."""
    bundle = _stage_bundle(tmp_path)
    _seed_sqlite(bundle)
    _write_proxy_env(
        bundle,
        MCP_PROXY_DATABASE_URL="postgresql+asyncpg://u:p@db:5432/cullis",
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )
    result = _run_deploy(bundle, "--accept-data-loss")
    combined = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"expected exit 0 (proceed with override), got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    # Warn must mention the override AND the impact so the audit trail
    # makes it obvious the operator opted in.
    assert "--accept-data-loss" in combined
    assert "Connector" in combined or "TLS verification" in combined


def test_orphan_sqlite_with_short_postgres_url_scheme(tmp_path):
    """Defensive — the short ``postgres://`` scheme (no driver suffix)
    must trip the guard too. SQLAlchemy and lifecycle code accept both
    spellings so a guard that only matches ``postgresql+`` would be
    bypassed by a copy-paste from a libpq-style connection string."""
    bundle = _stage_bundle(tmp_path)
    _seed_sqlite(bundle)
    _write_proxy_env(
        bundle,
        MCP_PROXY_DATABASE_URL="postgres://u:p@db:5432/cullis",
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )
    result = _run_deploy(bundle)
    assert result.returncode == 1, (
        f"expected exit 1 on short postgres:// scheme, got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "Orphan SQLite database" in (result.stdout + result.stderr)


# ── docs / customer-facing strings ────────────────────────────────────────


def test_readme_documents_database_backend_section():
    """README must surface the Postgres-swap gotcha at the section level
    so a customer reading the bundle docs end-to-end cannot miss it."""
    readme = (BUNDLE_SRC / "README.md").read_text()
    assert "Database backend" in readme
    assert "MCP_PROXY_DATABASE_URL" in readme
    assert "--accept-data-loss" in readme


def test_proxy_env_example_documents_database_url():
    """proxy.env.example must mention the variable + the swap-is-not-a-
    migration warning. Operators copy this file as the starting point;
    burying the gotcha in README alone misses the cohort that edits
    proxy.env without reading further docs."""
    example = (BUNDLE_SRC / "proxy.env.example").read_text()
    assert "MCP_PROXY_DATABASE_URL" in example
    assert "migration" in example.lower() or "--accept-data-loss" in example
