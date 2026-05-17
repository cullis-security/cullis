"""P3 MINOR-E — ``packaging/mastio-bundle/deploy.sh --accept-data-loss``
garbage-collects the orphan SQLite file after bypassing the MAJOR-A
guard.

Failure mode this pins (192.168.122.170 dogfood, 2026-05-17): the
operator swapped ``MCP_PROXY_DATABASE_URL`` from SQLite to Postgres,
hit the PR #769 refuse-to-start guard, ran ``./deploy.sh --accept-
data-loss`` to acknowledge the Connector invalidation, and the orphan
``./data/mcp_proxy.db`` (281 MB) was left on disk. The file no longer
served any purpose — every Connector enrolled against its Org CA was
already broken — but it confused later ``du -sh ./data`` audits and
wasted disk space.

These tests drive ``deploy.sh --accept-data-loss`` end-to-end with a
fake ``docker`` shim that translates the busybox-root ``rm -f`` into
host-side ``rm`` calls (mirror of the pattern in
``test_bundle_down_volumes.py``) so we can assert on the post-flag
filesystem state.

Allowlist invariant: only ``mcp_proxy.db``, ``mcp_proxy.db-wal``, and
``mcp_proxy.db-shm`` are removed. Anything else in ``./data/`` (operator
notes, a hypothetical future ``connector_data.db``, random binaries)
must survive. The helper refuses to glob, refuses to recurse.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG_ROOT = REPO_ROOT / "packaging"
COMMON_HELPERS = PKG_ROOT / "_common-deploy-helpers.sh"
BUNDLE_SRC = PKG_ROOT / "mastio-bundle"


# ── docker shim that honours ``rm -f`` busybox calls ──────────────────────


def _docker_shim_with_rm(stub_dir: pathlib.Path, log_path: pathlib.Path) -> None:
    """Fake ``docker`` that records every invocation and, for
    ``docker run --rm --user 0:0 -v <host>:/data busybox:stable sh -c
    "rm -f /data/<name> ..."`` calls, translates the rm into a
    host-side rm on the bound dir.

    Returns 0 for any other subcommand (``docker compose version``,
    ``docker compose down``, etc.) so the rest of deploy.sh runs.
    """
    docker = stub_dir / "docker"
    docker.write_text(
        f"""#!/usr/bin/env bash
echo "$@" >> {log_path}
if [[ "$1" == "run" ]]; then
    host=""
    cmd=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v)
                # First /data mount wins; the helper only mounts one.
                if [[ -z "$host" && "$2" == *:/data ]]; then
                    host="${{2%%:/data}}"
                fi
                shift 2
                ;;
            busybox:stable)
                shift
                if [[ "$1" == "sh" && "$2" == "-c" ]]; then
                    cmd="$3"
                fi
                break
                ;;
            *) shift ;;
        esac
    done
    # Translate ``rm -f /data/<a> /data/<b>`` into host-side rm.
    if [[ -n "$host" && "$cmd" == rm\\ -f* ]]; then
        for tok in $cmd; do
            case "$tok" in
                /data/*) rm -f "${{host}}/${{tok#/data/}}" ;;
            esac
        done
    fi
    exit 0
fi
exit 0
"""
    )
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _passthrough(stub_dir: pathlib.Path, name: str) -> None:
    p = stub_dir / name
    p.write_text("#!/usr/bin/env bash\nexit 0\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _build_path(tmp_path: pathlib.Path) -> tuple[str, pathlib.Path]:
    stub = tmp_path / "stubpath"
    stub.mkdir()
    log = tmp_path / "docker.log"
    log.write_text("")
    _docker_shim_with_rm(stub, log)
    for n in ("ss", "curl", "wget"):
        _passthrough(stub, n)
    real = os.environ.get("PATH", "")
    return f"{stub}:{real}", log


# ── bundle staging ────────────────────────────────────────────────────────


def _stage_bundle(tmp_path: pathlib.Path) -> pathlib.Path:
    """Customer-tarball layout: ``deploy.sh`` and ``_common-deploy-
    helpers.sh`` as siblings inside the bundle dir, no ``packaging/``
    parent. Mirror of ``_stage_mastio_customer_layout`` in
    ``test_bundle_down_volumes.py`` so the helper-source resolution
    is exercised the way the shipped tarball does it."""
    bundle = tmp_path / "cullis-mastio-bundle"
    bundle.mkdir(parents=True)
    shutil.copy2(BUNDLE_SRC / "deploy.sh", bundle / "deploy.sh")
    shutil.copy2(BUNDLE_SRC / "docker-compose.yml", bundle / "docker-compose.yml")
    shutil.copy2(COMMON_HELPERS, bundle / "_common-deploy-helpers.sh")
    (bundle / "deploy.sh").chmod(0o755)
    return bundle


def _seed_sqlite_files(bundle: pathlib.Path, db_size: int = 100 * 1024) -> dict:
    """Seed the three SQLite artefacts the wipe should touch."""
    data = bundle / "data"
    data.mkdir(exist_ok=True)
    db = data / "mcp_proxy.db"
    db.write_bytes(b"SQLite format 3\x00" + b"\x00" * (db_size - 16))
    wal = data / "mcp_proxy.db-wal"
    wal.write_bytes(b"\x00" * (12 * 1024))
    shm = data / "mcp_proxy.db-shm"
    shm.write_bytes(b"\x00" * 32_768)
    return {"db": db, "wal": wal, "shm": shm}


def _write_proxy_env(bundle: pathlib.Path, **kv: str) -> None:
    lines = [f"{k}={v}" for k, v in kv.items()]
    (bundle / "proxy.env").write_text("\n".join(lines) + "\n")


def _run_deploy(
    bundle: pathlib.Path,
    *args: str,
    env_overrides: dict | None = None,
    exit_after_checks: bool = True,
) -> subprocess.CompletedProcess:
    path_val, _ = _build_path(bundle.parent)
    env = os.environ.copy()
    env["PATH"] = path_val
    if exit_after_checks:
        env["CULLIS_DEPLOY_EXIT_AFTER_CHECKS"] = "1"
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["bash", str(bundle / "deploy.sh"), *args],
        cwd=str(bundle),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


# ── happy path ────────────────────────────────────────────────────────────


def test_accept_data_loss_wipes_orphan_sqlite_db(tmp_path):
    """Postgres URL + orphan ``mcp_proxy.db`` + ``--accept-data-loss``
    must remove the DB file from ``./data/``."""
    bundle = _stage_bundle(tmp_path)
    seeded = _seed_sqlite_files(bundle)
    _write_proxy_env(
        bundle,
        MCP_PROXY_DATABASE_URL="postgresql+asyncpg://u:p@db:5432/cullis",
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )

    result = _run_deploy(bundle, "--accept-data-loss")
    combined = result.stdout + result.stderr

    assert result.returncode == 0, (
        f"expected exit 0, got {result.returncode}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    # All three SQLite artefacts must be gone post-wipe.
    assert not seeded["db"].exists(), "mcp_proxy.db must be wiped"
    assert not seeded["wal"].exists(), "mcp_proxy.db-wal must be wiped"
    assert not seeded["shm"].exists(), "mcp_proxy.db-shm must be wiped"
    # The data/ dir itself survives as a placeholder.
    assert (bundle / "data").is_dir()
    # Log line announces the wipe with the file inventory so the audit
    # trail is human-readable (``Wiping orphan SQLite files: data/...``).
    assert "Wiping orphan SQLite files" in combined
    assert "mcp_proxy.db" in combined


def test_accept_data_loss_idempotent_when_files_already_missing(tmp_path):
    """Rerunning ``--accept-data-loss`` after a successful wipe must be
    a no-op, not an error. Same contract as ``--down -v`` on an
    already-clean stack."""
    bundle = _stage_bundle(tmp_path)
    # Postgres URL set, BUT no orphan SQLite on disk. The MAJOR-A guard
    # short-circuits via ``[[ -f $sqlite_path ]] || return 0`` BEFORE
    # checking ACCEPT_DATA_LOSS, so the wipe helper is never invoked.
    # That's still the right behaviour — the result is the same end-
    # state (no orphan files) without bothering docker.
    (bundle / "data").mkdir()
    _write_proxy_env(
        bundle,
        MCP_PROXY_DATABASE_URL="postgresql+asyncpg://u:p@db:5432/cullis",
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )

    result = _run_deploy(bundle, "--accept-data-loss")
    assert result.returncode == 0, (result.stdout, result.stderr)
    # No file to delete, no false-positive "Wiping" banner.
    assert "Orphan SQLite database" not in (result.stdout + result.stderr)


def test_accept_data_loss_idempotent_via_direct_helper_call(tmp_path):
    """Drive ``_wipe_orphan_sqlite`` directly twice — the second call
    on an already-clean data dir must succeed silently. Closes the
    ``[[ -f $sqlite_path ]] || return 0`` short-circuit gap above where
    the helper itself is never re-entered."""
    bundle = _stage_bundle(tmp_path)
    seeded = _seed_sqlite_files(bundle)
    path_val, _ = _build_path(bundle.parent)
    env = os.environ.copy()
    env["PATH"] = path_val
    script = f"""
set -eo pipefail
SCRIPT_DIR="{bundle}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{bundle}/_common-deploy-helpers.sh"
echo "--- first call ---"
_wipe_orphan_sqlite "{bundle}/data"
echo "--- second call ---"
_wipe_orphan_sqlite "{bundle}/data"
"""
    result = subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True,
        text=True, timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    # First call wiped the files; second call must see "already clean".
    assert not seeded["db"].exists()
    assert not seeded["wal"].exists()
    assert not seeded["shm"].exists()
    assert "Wiping orphan SQLite files" in result.stdout
    assert "already clean" in result.stdout


# ── allowlist invariant ───────────────────────────────────────────────────


def test_wipe_helper_preserves_non_allowlisted_files(tmp_path):
    """A future ``connector_data.db`` from the Connector bundle, an
    operator's ``random.bin`` dropped for forensics, or a stray
    ``mcp_proxy.db.bak`` snapshot must survive the wipe. Allowlist is
    by exact filename only — no glob, no prefix match."""
    bundle = _stage_bundle(tmp_path)
    seeded = _seed_sqlite_files(bundle)
    data = bundle / "data"
    # Bystanders the wipe must NEVER touch.
    bystanders = {
        "connector_data.db": b"connector state",
        "random.bin": b"\xde\xad\xbe\xef",
        "mcp_proxy.db.bak": b"operator backup",
        "notes.txt": b"keep me",
    }
    for name, content in bystanders.items():
        (data / name).write_bytes(content)
    # A nested dir with content — wipe must not recurse.
    (data / "subdir").mkdir()
    (data / "subdir" / "deep.bin").write_bytes(b"deep")

    path_val, _ = _build_path(bundle.parent)
    env = os.environ.copy()
    env["PATH"] = path_val
    script = f"""
set -eo pipefail
SCRIPT_DIR="{bundle}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{bundle}/_common-deploy-helpers.sh"
_wipe_orphan_sqlite "{bundle}/data"
"""
    result = subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True,
        text=True, timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    # Allowlisted files gone.
    assert not seeded["db"].exists()
    assert not seeded["wal"].exists()
    assert not seeded["shm"].exists()
    # Bystanders survive byte-for-byte.
    for name, content in bystanders.items():
        path = data / name
        assert path.exists(), f"{name} must survive the wipe"
        assert path.read_bytes() == content, f"{name} contents must be untouched"
    # Nested dir survives untouched too (no recursion).
    assert (data / "subdir" / "deep.bin").read_bytes() == b"deep"


def test_wipe_helper_busybox_invocation_uses_user_zero(tmp_path):
    """Bind dirs are chmod 10001:10001 after init-permissions; the
    invoking host uid can't ``rm -f`` 0600 files. The helper MUST
    therefore pass ``--user 0:0`` so busybox runs as root inside the
    container. Pin via docker argv assertion, same posture as the
    test in ``test_bundle_down_volumes.py``."""
    bundle = _stage_bundle(tmp_path)
    _seed_sqlite_files(bundle)
    path_val, log = _build_path(bundle.parent)
    env = os.environ.copy()
    env["PATH"] = path_val
    script = f"""
set -eo pipefail
SCRIPT_DIR="{bundle}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{bundle}/_common-deploy-helpers.sh"
_wipe_orphan_sqlite "{bundle}/data"
"""
    result = subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True,
        text=True, timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    docker_log = log.read_text()
    rm_invocations = [
        line for line in docker_log.splitlines()
        if "busybox" in line and "rm" in line and line.startswith("run ")
    ]
    assert rm_invocations, (
        "expected at least one busybox rm invocation, got: "
        f"{docker_log!r}"
    )
    for inv in rm_invocations:
        assert "--user 0:0" in inv, (
            "wipe invocation missing --user 0:0 (busybox-root "
            f"invariant violated): {inv!r}"
        )


# ── scope: SQLite normal mode is unaffected ───────────────────────────────


def test_sqlite_default_url_with_accept_data_loss_does_not_wipe(tmp_path):
    """When MCP_PROXY_DATABASE_URL is unset (compose default = SQLite),
    the MAJOR-A guard does not fire, so ``--accept-data-loss`` is a
    no-op for the wipe. The flag exists solely to acknowledge the
    Postgres-swap data loss; on a normal SQLite restart the file
    must survive."""
    bundle = _stage_bundle(tmp_path)
    seeded = _seed_sqlite_files(bundle)
    _write_proxy_env(
        bundle,
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )

    result = _run_deploy(bundle, "--accept-data-loss")
    assert result.returncode == 0, (result.stdout, result.stderr)
    # SQLite still active → DB must be intact.
    assert seeded["db"].exists(), (
        "mcp_proxy.db must NOT be wiped on a normal SQLite restart "
        "even when --accept-data-loss is passed"
    )
    assert seeded["wal"].exists()
    assert seeded["shm"].exists()
    # No wipe banner.
    assert "Wiping orphan SQLite" not in (result.stdout + result.stderr)


def test_partial_orphan_only_wipes_present_files(tmp_path):
    """If only ``mcp_proxy.db`` exists (no WAL / SHM, e.g. a clean
    shutdown), the wipe must still proceed and remove just the DB
    rather than erroring on the missing sidecars."""
    bundle = _stage_bundle(tmp_path)
    data = bundle / "data"
    data.mkdir()
    db = data / "mcp_proxy.db"
    db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 4080)
    # NO -wal, NO -shm.
    _write_proxy_env(
        bundle,
        MCP_PROXY_DATABASE_URL="postgresql+asyncpg://u:p@db:5432/cullis",
        MCP_PROXY_PROXY_PUBLIC_URL="https://host.docker.internal:9443",
        MCP_PROXY_NGINX_SAN="host.docker.internal,localhost",
    )

    result = _run_deploy(bundle, "--accept-data-loss")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not db.exists()
    combined = result.stdout + result.stderr
    assert "Wiping orphan SQLite files" in combined
    # Inventory should mention the DB but not phantom WAL/SHM entries.
    assert "mcp_proxy.db-wal" not in combined
    assert "mcp_proxy.db-shm" not in combined


# ── help text + README messaging ──────────────────────────────────────────


def test_help_text_mentions_orphan_gc(tmp_path):
    """``--help`` must explain the GC side-effect so a customer reading
    the flag for the first time knows the file will be removed (and
    can back it up beforehand if they want a forensic copy)."""
    result = subprocess.run(
        ["bash", str(BUNDLE_SRC / "deploy.sh"), "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    out = result.stdout
    assert "--accept-data-loss" in out
    # The help must say the orphan files are GC'd, not "left for forensics".
    assert "garbage-collect" in out.lower() or "removed" in out.lower() \
        or "wipe" in out.lower()
    # Backup hint so operators know to ``cp -a`` before the wipe.
    assert "back" in out.lower()


def test_readme_describes_orphan_gc_behaviour():
    """README's ``Database backend`` section must reflect that
    ``--accept-data-loss`` now wipes the orphan SQLite files, so a
    customer reading the docs end-to-end finds the new behaviour
    without grepping the script."""
    readme = (BUNDLE_SRC / "README.md").read_text()
    assert "Database backend" in readme
    assert "--accept-data-loss" in readme
    # The README messaging must say the file is wiped / removed / GC'd
    # rather than the old "left on disk for forensics" line.
    assert (
        "garbage-collect" in readme.lower()
        or "wiped" in readme.lower()
        or "removed" in readme.lower()
    )
    assert "Back up" in readme or "back up" in readme.lower()
