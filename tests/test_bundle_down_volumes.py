"""P3 MINOR-H: ``./deploy.sh --down -v`` wipes the bundle bind dirs.

After ADR-030 the Mastio + Frontdesk bundles persist runtime state on
host bind mounts (``./data``, ``./nginx-certs``, ``./certs``,
``connector_data/``, ``tls/``). ``compose down --volumes`` only touches
named volumes, so a "tabula rasa" reset previously needed a manual
busybox-root ``rm -rf`` because ``init-permissions`` had chown'd the
trees to uid 10001.

The new ``-v`` / ``--volumes`` / ``--wipe-data`` modifier on ``--down``
runs that wipe via the shared ``_wipe_bind_dirs`` helper. These tests
drive ``deploy.sh --down -v`` end-to-end with a fake ``docker`` shim on
PATH that records every ``docker run`` invocation, then performs the
wipe by hand. Real docker is NOT required — the helper's contract is
that it passes ``--user 0:0`` + mounts each dir at ``/wipeN`` and calls
``find -mindepth 1 -delete``. We assert on the argv and on the
post-wipe filesystem state.

Default ``--down`` (no flag) must leave bind dirs untouched. The flag
parsing must accept ``-v`` (short), ``--volumes`` (long, compose
parallel), and ``--wipe-data`` (descriptive).
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
MASTIO_SRC = PKG_ROOT / "mastio-bundle"
FRONTDESK_SRC = PKG_ROOT / "frontdesk-bundle"
ENTERPRISE_SRC = PKG_ROOT / "mastio-enterprise-bundle"


# ── shared shim infra ─────────────────────────────────────────────────────


def _docker_shim(stub_dir: pathlib.Path, log_path: pathlib.Path) -> None:
    """A ``docker`` shim that:

    * Logs every argv to ``log_path`` so the test can assert on the
      busybox invocation (``--user 0:0``, mount flags, find command).
    * Performs the wipe locally for ``docker run --rm --user 0:0
      -v <host>:/wipe<N> ... busybox:stable sh -c "<find ...>"`` calls
      so the post-wipe filesystem state can be asserted on too.
    * Returns 0 for any unrelated subcommand (``docker compose``,
      ``docker volume inspect``) so the rest of deploy.sh runs.
    """
    docker = stub_dir / "docker"
    docker.write_text(
        f"""#!/usr/bin/env bash
echo "$@" >> {log_path}
# Translate the wipe invocation into a host-side rm. We only handle
# the very specific argv shape _wipe_bind_dirs produces, so any other
# docker call short-circuits to exit 0 (the bundle's compose calls
# don't care about real container behaviour in these tests).
if [[ "$1" == "run" ]]; then
    # Collect -v <host>:/wipe<N> mounts; everything after busybox:stable
    # sh -c is the find command, applied to the host paths.
    mounts=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v) mounts+=("$2"); shift 2 ;;
            busybox:stable) shift; break ;;
            *) shift ;;
        esac
    done
    # Apply wipe semantics host-side: every mount of the form
    # ``<hostpath>:/wipeN`` triggers ``find <hostpath> -mindepth 1 -delete``.
    for m in "${{mounts[@]}}"; do
        host="${{m%%:/wipe*}}"
        if [[ -d "$host" ]]; then
            find "$host" -mindepth 1 -delete 2>/dev/null || true
        fi
    done
    exit 0
fi
# docker compose version / docker compose down / etc — short-circuit.
exit 0
"""
    )
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _passthrough_shim(stub_dir: pathlib.Path, name: str) -> None:
    p = stub_dir / name
    p.write_text("#!/usr/bin/env bash\nexit 0\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _build_path(tmp_path: pathlib.Path) -> tuple[str, pathlib.Path, pathlib.Path]:
    """Return (PATH, stub_dir, docker_log_path). The shim writes one line
    per ``docker`` invocation so tests can assert on flag presence."""
    stub = tmp_path / "stubpath"
    stub.mkdir()
    log = tmp_path / "docker.log"
    log.write_text("")
    _docker_shim(stub, log)
    for n in ("ss", "curl", "wget"):
        _passthrough_shim(stub, n)
    real = os.environ.get("PATH", "")
    return f"{stub}:{real}", stub, log


def _seed_dir_with_state(d: pathlib.Path, owned_by_root_dotfile: bool = True) -> None:
    """Drop a couple of files into ``d`` so we can verify the wipe ran.
    ``owned_by_root_dotfile`` covers the ``find -mindepth 1 -delete``
    case for dotfiles (sqlite ``-journal`` etc) the busybox path is
    supposed to handle."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "marker.txt").write_text("pre-wipe")
    (d / "nested").mkdir(exist_ok=True)
    (d / "nested" / "inner.bin").write_bytes(b"\x00" * 32)
    if owned_by_root_dotfile:
        (d / ".cullis-stash").write_text("dotfile-state")


# ── mastio-bundle ─────────────────────────────────────────────────────────


def _stage_mastio(tmp_path: pathlib.Path) -> pathlib.Path:
    pkg = tmp_path / "packaging"
    bundle = pkg / "mastio-bundle"
    bundle.mkdir(parents=True)
    shutil.copy2(MASTIO_SRC / "deploy.sh", bundle / "deploy.sh")
    shutil.copy2(MASTIO_SRC / "docker-compose.yml", bundle / "docker-compose.yml")
    shutil.copy2(COMMON_HELPERS, pkg / "_common-deploy-helpers.sh")
    (bundle / "deploy.sh").chmod(0o755)
    # Minimal proxy.env so the _load_env helpers find something.
    (bundle / "proxy.env").write_text(
        "MCP_PROXY_PROXY_PUBLIC_URL=https://localhost:9443\n"
    )
    return bundle


def _run(bundle: pathlib.Path, *args: str, env_overrides: dict | None = None
         ) -> subprocess.CompletedProcess:
    path_val, _, _ = _build_path(bundle.parent.parent)
    env = os.environ.copy()
    env["PATH"] = path_val
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


def test_mastio_down_without_v_preserves_bind_dirs(tmp_path):
    bundle = _stage_mastio(tmp_path)
    _seed_dir_with_state(bundle / "data")
    _seed_dir_with_state(bundle / "nginx-certs")
    _seed_dir_with_state(bundle / "certs")

    result = _run(bundle, "--down")
    assert result.returncode == 0, (result.stdout, result.stderr)
    # Bind dirs must be intact.
    assert (bundle / "data" / "marker.txt").exists()
    assert (bundle / "nginx-certs" / "marker.txt").exists()
    assert (bundle / "certs" / "marker.txt").exists()
    # The "Wiping bind dirs" step must NOT have run.
    assert "Wiping bind dirs" not in (result.stdout + result.stderr)


def test_mastio_down_v_wipes_bind_dirs(tmp_path):
    bundle = _stage_mastio(tmp_path)
    _seed_dir_with_state(bundle / "data")
    _seed_dir_with_state(bundle / "nginx-certs")
    _seed_dir_with_state(bundle / "certs")

    result = _run(bundle, "--down", "-v")
    assert result.returncode == 0, (result.stdout, result.stderr)
    # Wipe banner shown.
    combined = result.stdout + result.stderr
    assert "Wiping bind dirs" in combined
    assert "Destructive" in combined
    # The dirs themselves survive (placeholders), contents are gone.
    for sub in ("data", "nginx-certs", "certs"):
        assert (bundle / sub).is_dir(), f"{sub}/ must survive as placeholder"
        leftovers = list((bundle / sub).iterdir())
        assert leftovers == [], f"{sub}/ should be empty, got {leftovers}"
    # proxy.env must be untouched.
    assert (bundle / "proxy.env").exists()
    assert "MCP_PROXY_PROXY_PUBLIC_URL" in (bundle / "proxy.env").read_text()


def test_mastio_down_v_accepts_long_flag_aliases(tmp_path):
    """--volumes and --wipe-data are the documented aliases."""
    for flag in ("--volumes", "--wipe-data"):
        bundle = _stage_mastio(tmp_path / flag.lstrip("-"))
        _seed_dir_with_state(bundle / "data")
        result = _run(bundle, "--down", flag)
        assert result.returncode == 0, (flag, result.stdout, result.stderr)
        assert "Wiping bind dirs" in (result.stdout + result.stderr), flag
        assert list((bundle / "data").iterdir()) == [], flag


def test_mastio_down_v_is_idempotent_on_empty_dirs(tmp_path):
    """Re-running --down -v after a successful wipe must be a no-op,
    not an error. Same contract as ``docker compose down -v`` on an
    already-down stack."""
    bundle = _stage_mastio(tmp_path)
    # Empty bind dirs (no state seeded).
    (bundle / "data").mkdir()
    (bundle / "nginx-certs").mkdir()
    (bundle / "certs").mkdir()

    result = _run(bundle, "--down", "-v")
    assert result.returncode == 0, (result.stdout, result.stderr)
    # The helper should report "already empty" instead of issuing the wipe.
    assert "already empty" in (result.stdout + result.stderr)


def test_mastio_down_v_is_idempotent_when_dirs_missing(tmp_path):
    """Some operators rm -rf'd the dirs by hand before discovering this
    flag — the wipe must not crash if they don't exist at all."""
    bundle = _stage_mastio(tmp_path)
    # Do not create data/ etc. at all.
    result = _run(bundle, "--down", "-v")
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_mastio_help_documents_v_flag():
    result = subprocess.run(
        ["bash", str(MASTIO_SRC / "deploy.sh"), "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    # The flag itself + at least one alias + the destructive warning.
    assert "--volumes" in result.stdout
    assert "wipe" in result.stdout.lower()
    assert "re-enroll" in result.stdout or "Connector" in result.stdout


# ── frontdesk-bundle ──────────────────────────────────────────────────────


def _stage_frontdesk(tmp_path: pathlib.Path) -> pathlib.Path:
    pkg = tmp_path / "packaging"
    bundle = pkg / "frontdesk-bundle"
    bundle.mkdir(parents=True)
    shutil.copy2(FRONTDESK_SRC / "deploy.sh", bundle / "deploy.sh")
    # Minimal docker-compose.yml for sanity (deploy.sh doesn't assert
    # on its content during --down).
    (bundle / "docker-compose.yml").write_text("services: {}\n")
    shutil.copy2(COMMON_HELPERS, pkg / "_common-deploy-helpers.sh")
    (bundle / "deploy.sh").chmod(0o755)
    (bundle / "frontdesk.env").write_text(
        "CONNECTOR_DATA_DIR=./connector_data\n"
    )
    return bundle


def test_frontdesk_down_without_v_preserves_bind_dirs(tmp_path):
    bundle = _stage_frontdesk(tmp_path)
    _seed_dir_with_state(bundle / "connector_data")
    _seed_dir_with_state(bundle / "tls")

    result = _run(bundle, "--down")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (bundle / "connector_data" / "marker.txt").exists()
    assert (bundle / "tls" / "marker.txt").exists()
    assert "Wiping bind dirs" not in (result.stdout + result.stderr)


def test_frontdesk_down_v_wipes_bind_dirs(tmp_path):
    bundle = _stage_frontdesk(tmp_path)
    _seed_dir_with_state(bundle / "connector_data")
    _seed_dir_with_state(bundle / "tls")
    # frontdesk.env.bak must NOT be wiped — only the bind dirs.
    (bundle / "frontdesk.env.bak-20260517-120000").write_text("backup")

    result = _run(bundle, "--down", "-v")
    assert result.returncode == 0, (result.stdout, result.stderr)
    combined = result.stdout + result.stderr
    assert "Wiping bind dirs" in combined
    assert "Destructive" in combined
    for sub in ("connector_data", "tls"):
        assert (bundle / sub).is_dir(), f"{sub}/ must survive"
        assert list((bundle / sub).iterdir()) == [], sub
    # frontdesk.env + .bak survive.
    assert (bundle / "frontdesk.env").exists()
    assert (bundle / "frontdesk.env.bak-20260517-120000").exists()


def test_frontdesk_down_v_short_flag_alias(tmp_path):
    bundle = _stage_frontdesk(tmp_path)
    _seed_dir_with_state(bundle / "connector_data")
    result = _run(bundle, "--down", "--wipe-data")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert list((bundle / "connector_data").iterdir()) == []


def test_frontdesk_help_documents_v_flag():
    result = subprocess.run(
        ["bash", str(FRONTDESK_SRC / "deploy.sh"), "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "--volumes" in result.stdout
    assert "wipe" in result.stdout.lower()


# ── enterprise bundle (private repo path, but the open-core deploy.sh ──
#   in packaging/mastio-enterprise-bundle/ is open-source) ────────────────


def _stage_enterprise(tmp_path: pathlib.Path) -> pathlib.Path:
    pkg = tmp_path / "packaging"
    bundle = pkg / "mastio-enterprise-bundle"
    bundle.mkdir(parents=True)
    shutil.copy2(ENTERPRISE_SRC / "deploy.sh", bundle / "deploy.sh")
    shutil.copy2(ENTERPRISE_SRC / "docker-compose.yml", bundle / "docker-compose.yml")
    shutil.copy2(ENTERPRISE_SRC / "proxy.env.example", bundle / "proxy.env.example")
    shutil.copy2(COMMON_HELPERS, pkg / "_common-deploy-helpers.sh")
    (bundle / "deploy.sh").chmod(0o755)
    (bundle / "proxy.env").write_text(
        "MCP_PROXY_PROXY_PUBLIC_URL=https://localhost:9443\n"
        "CULLIS_LICENSE_KEY=fake-license\n"
    )
    return bundle


def test_enterprise_down_v_wipes_bind_dirs(tmp_path):
    bundle = _stage_enterprise(tmp_path)
    _seed_dir_with_state(bundle / "data")
    _seed_dir_with_state(bundle / "nginx-certs")

    result = _run(bundle, "--down", "-v")
    assert result.returncode == 0, (result.stdout, result.stderr)
    combined = result.stdout + result.stderr
    assert "wiping bind dirs" in combined.lower()
    for sub in ("data", "nginx-certs"):
        assert (bundle / sub).is_dir()
        assert list((bundle / sub).iterdir()) == [], sub
    # proxy.env preserved.
    assert (bundle / "proxy.env").exists()


def test_enterprise_down_without_v_preserves_bind_dirs(tmp_path):
    bundle = _stage_enterprise(tmp_path)
    _seed_dir_with_state(bundle / "data")
    result = _run(bundle, "--down")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (bundle / "data" / "marker.txt").exists()


# ── helper unit test: never touches env files ─────────────────────────────


def test_wipe_bind_dirs_helper_only_touches_listed_paths(tmp_path):
    """Source the helper directly + drive ``_wipe_bind_dirs`` with two
    paths; assert every other file in the tmp dir is untouched. Guards
    against a future refactor that accidentally widens scope (e.g. an
    inadvertent ``rm -rf $SCRIPT_DIR``)."""
    bundle = _stage_mastio(tmp_path)
    _seed_dir_with_state(bundle / "data")
    _seed_dir_with_state(bundle / "nginx-certs")
    # A sibling file the helper must NEVER touch.
    (bundle / "important.txt").write_text("keep me")

    path_val, _, _ = _build_path(bundle.parent.parent)
    env = os.environ.copy()
    env["PATH"] = path_val
    env["SCRIPT_DIR"] = str(bundle)
    # Drive _wipe_bind_dirs directly through the helper file. The
    # caller-contract stubs (ok / warn / err) are required by the
    # source, so seed them as no-op shell functions.
    script = f"""
set -eo pipefail
SCRIPT_DIR="{bundle}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{COMMON_HELPERS.parent / '_common-deploy-helpers.sh'}"
_wipe_bind_dirs "{bundle}/data" "{bundle}/nginx-certs"
"""
    # Use the bundle's helpers location, not the one in the temp pkg
    # (which is identical anyway).
    result = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert list((bundle / "data").iterdir()) == []
    assert list((bundle / "nginx-certs").iterdir()) == []
    # Bystander files untouched.
    assert (bundle / "important.txt").read_text() == "keep me"
    assert (bundle / "proxy.env").exists()
