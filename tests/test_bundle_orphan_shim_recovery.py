"""P3 MINOR-I: bundle deploy.sh sweeps orphan container shims pre-up.

Failure mode observed during the 2026-05-17 tabula-rasa dogfood:

    1. Operator runs ``docker compose ... up`` with a bind-mounted config
       file whose dst path does not exist inside the image. Docker auto-
       creates dst as a DIRECTORY (default for missing bind-mount
       targets), container starts, service crashes parsing the dir.
    2. Operator fixes the upstream issue and retries ``compose up``.
       Docker sees a residual stopped container from the previous
       attempt. The recreate sees src=file vs dst=dir and fails with
       ``not a directory: mount src=..., dst=...``.
    3. Every subsequent retry hits the same error. Only fix is
       ``docker rm -f <project>-<service>-1``.

The fix lives in the shared ``_common-deploy-helpers.sh`` as
``_cleanup_orphan_shims`` + ``_hint_on_bind_mount_failure``. Each of
the three bundle deploy.sh wires the sweep BEFORE every primary
``compose up``, scoped to ``COMPOSE_PROJECT_NAME`` so sibling stacks
on the same host are never touched.

These tests drive the helper through a fake ``docker`` shim that
records every invocation, then assert:

* ``_cleanup_orphan_shims`` calls ``docker rm -f`` on stale shim ids
  matching the project label.
* The filter argv is anchored on ``com.docker.compose.project=$project``
  (no cross-bundle reach).
* No ``docker rm`` is issued when no stale shims are present.
* Missing docker / unsupported filter / empty project = no-op.
* The hint fires only on non-zero exit code, mentioning the project
  name and the recovery command.
* Each of the three bundle deploy.sh sources the helper at top-level
  (so the wired sweep call resolves) and the helper is name-stable.

Mirrors ``tests/test_bundle_down_volumes.py`` (#773) fake docker shim
pattern.
"""

from __future__ import annotations

import os
import pathlib
import stat
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG_ROOT = REPO_ROOT / "packaging"
COMMON_HELPERS = PKG_ROOT / "_common-deploy-helpers.sh"
MASTIO_SRC = PKG_ROOT / "mastio-bundle"
FRONTDESK_SRC = PKG_ROOT / "frontdesk-bundle"
ENTERPRISE_SRC = PKG_ROOT / "mastio-enterprise-bundle"


# ── docker shim ─────────────────────────────────────────────────────────────


def _docker_shim_with_stale(
    stub_dir: pathlib.Path,
    log_path: pathlib.Path,
    stale_ids: list[str],
) -> None:
    """A ``docker`` shim that:

    * Logs every argv (one line per invocation) to ``log_path``.
    * For ``docker ps -aq --filter label=com.docker.compose.project=<p>
      --filter status=created --filter status=exited``, emits the
      configured ``stale_ids`` as newline-separated stdout.
    * For ``docker rm -f <ids...>``, returns 0 and logs.
    * Any other docker subcommand returns 0 (the bundle's compose
      calls don't matter for unit tests).
    """
    docker = stub_dir / "docker"
    docker.write_text(
        f"""#!/usr/bin/env bash
echo "$@" >> {log_path}
if [[ "$1" == "ps" ]]; then
    # Only emit the stale ids when the caller asked for the
    # project-scoped + status=created/exited filter. Otherwise stay
    # silent so unrelated ``docker ps`` calls inside the bundle do
    # not pollute the sweep argv.
    saw_project_filter=0
    saw_created=0
    saw_exited=0
    for a in "$@"; do
        case "$a" in
            label=com.docker.compose.project=*) saw_project_filter=1 ;;
            status=created) saw_created=1 ;;
            status=exited) saw_exited=1 ;;
        esac
    done
    if [[ $saw_project_filter -eq 1 && $saw_created -eq 1 && $saw_exited -eq 1 ]]; then
        printf '%s\\n' {' '.join(repr(i) for i in stale_ids)}
    fi
    exit 0
fi
exit 0
"""
    )
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _passthrough_shim(stub_dir: pathlib.Path, name: str) -> None:
    p = stub_dir / name
    p.write_text("#!/usr/bin/env bash\nexit 0\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _build_path(
    tmp_path: pathlib.Path, stale_ids: list[str] | None = None
) -> tuple[str, pathlib.Path, pathlib.Path]:
    stub = tmp_path / "stubpath"
    stub.mkdir()
    log = tmp_path / "docker.log"
    log.write_text("")
    _docker_shim_with_stale(stub, log, stale_ids or [])
    for n in ("ss", "curl", "wget"):
        _passthrough_shim(stub, n)
    real = os.environ.get("PATH", "")
    return f"{stub}:{real}", stub, log


def _run_helper(
    tmp_path: pathlib.Path,
    helper_script: str,
    stale_ids: list[str] | None = None,
) -> subprocess.CompletedProcess:
    """Source ``_common-deploy-helpers.sh`` + execute ``helper_script``
    via bash, with the fake docker shim on PATH. Returns the completed
    process (stdout/stderr/returncode all captured)."""
    path_val, _, _ = _build_path(tmp_path, stale_ids=stale_ids)
    env = os.environ.copy()
    env["PATH"] = path_val
    # Caller-contract stubs (ok / warn / err / die / step) are required
    # by the helper. Seed them as no-op functions that echo so we can
    # assert on the warn message.
    script = f"""
set -eo pipefail
SCRIPT_DIR="{tmp_path}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{COMMON_HELPERS}"
{helper_script}
"""
    return subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


# ── _cleanup_orphan_shims ───────────────────────────────────────────────────


def test_cleanup_orphan_shims_calls_rm_f_on_stale(tmp_path):
    """When the docker filter returns stale container ids, the helper
    must invoke ``docker rm -f`` with those ids and emit the warn."""
    stale = ["abc123def456", "deadbeef0000"]
    path_val, _, log = _build_path(tmp_path, stale_ids=stale)
    env = os.environ.copy()
    env["PATH"] = path_val
    script = f"""
set -eo pipefail
SCRIPT_DIR="{tmp_path}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{COMMON_HELPERS}"
_cleanup_orphan_shims "cullis-mastio"
"""
    result = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    docker_log = log.read_text()
    # Filter argv must contain the project label + both status filters.
    assert "label=com.docker.compose.project=cullis-mastio" in docker_log
    assert "status=created" in docker_log
    assert "status=exited" in docker_log
    # rm -f must have been called with the stale ids.
    rm_lines = [
        line for line in docker_log.splitlines()
        if line.startswith("rm -f")
    ]
    assert rm_lines, f"expected at least one ``docker rm -f`` call, got: {docker_log!r}"
    rm_argv = " ".join(rm_lines)
    for sid in stale:
        assert sid in rm_argv, f"stale id {sid!r} not in rm argv: {rm_argv!r}"
    # User-facing warn must have fired.
    assert "orphan container shim" in result.stdout.lower()


def test_cleanup_orphan_shims_noop_when_no_stale(tmp_path):
    """No stale containers → no ``docker rm`` call, no warn."""
    path_val, _, log = _build_path(tmp_path, stale_ids=[])
    env = os.environ.copy()
    env["PATH"] = path_val
    script = f"""
set -eo pipefail
SCRIPT_DIR="{tmp_path}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{COMMON_HELPERS}"
_cleanup_orphan_shims "cullis-mastio"
"""
    result = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    docker_log = log.read_text()
    # The ``docker ps`` filter call is fine, but no ``docker rm``.
    rm_lines = [
        line for line in docker_log.splitlines()
        if line.startswith("rm ")
    ]
    assert rm_lines == [], f"expected no rm calls when nothing stale, got: {rm_lines!r}"
    # Warn must NOT have fired.
    assert "orphan container shim" not in result.stdout.lower()


def test_cleanup_orphan_shims_empty_project_is_noop(tmp_path):
    """An empty project name is treated as "nothing to sweep" rather
    than blasting every container on the host (defence against a
    future caller that forgets to export COMPOSE_PROJECT_NAME)."""
    path_val, _, log = _build_path(tmp_path, stale_ids=["abc"])
    env = os.environ.copy()
    env["PATH"] = path_val
    script = f"""
set -eo pipefail
SCRIPT_DIR="{tmp_path}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{COMMON_HELPERS}"
_cleanup_orphan_shims ""
"""
    result = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    docker_log = log.read_text()
    # No docker call at all — the early-return on empty project must
    # short-circuit BEFORE invoking ``docker ps``.
    assert docker_log == "", (
        "empty project must not invoke docker at all, got:\n"
        f"{docker_log!r}"
    )


def test_cleanup_orphan_shims_no_docker_available_is_noop(tmp_path):
    """``command -v docker`` failing must return 0 (no-op) — the
    deploy.sh runs with ``set -e`` and an unguarded exit would abort
    the whole bring-up on hosts without docker installed (e.g. a
    dry-run from a CI lint job)."""
    # Build a PATH with NO docker binary on it. Find the minimal
    # system dirs that provide bash + find + grep so the script can
    # actually run, then strip out anything providing docker.
    real_path = os.environ.get("PATH", "")
    filtered_dirs = [
        d for d in real_path.split(os.pathsep)
        if d and not (pathlib.Path(d) / "docker").exists()
    ]
    stub = tmp_path / "stubpath_no_docker"
    stub.mkdir()
    for n in ("ss", "curl", "wget"):
        _passthrough_shim(stub, n)
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(stub), *filtered_dirs])
    # Sanity check: docker must truly not resolve on this PATH.
    which = subprocess.run(
        ["bash", "-c", "command -v docker"],
        env=env, capture_output=True, text=True, timeout=10,
    )
    assert which.returncode != 0, (
        f"test setup error: docker still resolves on filtered PATH: "
        f"{which.stdout!r}"
    )
    script = f"""
set -eo pipefail
SCRIPT_DIR="{tmp_path}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{COMMON_HELPERS}"
_cleanup_orphan_shims "cullis-mastio"
echo "after-cleanup-ok"
"""
    result = subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "after-cleanup-ok" in result.stdout


def test_cleanup_orphan_shims_project_filter_anchored(tmp_path):
    """Regression guard: the filter MUST use a project label, not a
    bare ``status=`` filter. A bug that drops the project anchor
    would sweep every stopped container on the host — including
    sibling Mastio / Frontdesk / unrelated user containers."""
    path_val, _, log = _build_path(tmp_path, stale_ids=["abc"])
    env = os.environ.copy()
    env["PATH"] = path_val
    script = f"""
set -eo pipefail
SCRIPT_DIR="{tmp_path}"
ok()   {{ echo "ok:   $1"; }}
warn() {{ echo "warn: $1"; }}
err()  {{ echo "err:  $1"; }}
die()  {{ err "$1"; exit 1; }}
step() {{ echo "step: $1"; }}
source "{COMMON_HELPERS}"
_cleanup_orphan_shims "cullis-frontdesk"
"""
    subprocess.run(
        ["bash", "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    docker_log = log.read_text()
    ps_line = next(
        (line for line in docker_log.splitlines() if line.startswith("ps ")),
        None,
    )
    assert ps_line is not None, f"expected a ``docker ps`` invocation in: {docker_log!r}"
    assert "label=com.docker.compose.project=cullis-frontdesk" in ps_line, (
        "filter argv MUST be anchored on the compose project label "
        f"(got: {ps_line!r})"
    )


# ── _hint_on_bind_mount_failure ─────────────────────────────────────────────


def test_hint_silent_on_success(tmp_path):
    """Exit code 0 → no hint emitted. The hint must only fire on
    failure or the operator sees scary "not a directory" guidance on
    every successful ``./deploy.sh`` run."""
    result = _run_helper(
        tmp_path,
        '_hint_on_bind_mount_failure 0 "cullis-mastio"',
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "not a directory" not in (result.stdout + result.stderr).lower()
    assert "orphan container shim" not in (result.stdout + result.stderr).lower()


def test_hint_fires_on_nonzero_with_project_name(tmp_path):
    """Non-zero exit → hint emitted to stderr, including the project
    name in the recovery command so the operator can paste-and-run."""
    result = _run_helper(
        tmp_path,
        '_hint_on_bind_mount_failure 1 "cullis-frontdesk"',
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    combined = result.stdout + result.stderr
    assert "not a directory" in combined
    assert "orphan container shim" in combined.lower()
    # Recovery command must reference the project name + docker rm -f.
    assert "cullis-frontdesk" in combined
    assert "docker rm -f" in combined


def test_hint_includes_recovery_command_template(tmp_path):
    """The hint must spell out the literal recovery command shape so a
    panicked operator can copy-paste without inventing the filter syntax."""
    result = _run_helper(
        tmp_path,
        '_hint_on_bind_mount_failure 1 "cullis-mastio-enterprise"',
    )
    combined = result.stdout + result.stderr
    assert "docker ps -aq" in combined
    assert "label=com.docker.compose.project=cullis-mastio-enterprise" in combined
    assert "./deploy.sh" in combined


# ── bundle deploy.sh wiring ─────────────────────────────────────────────────


def _read(p: pathlib.Path) -> str:
    return p.read_text()


def test_mastio_deploy_wires_cleanup_before_primary_up():
    """``packaging/mastio-bundle/deploy.sh`` must call
    ``_cleanup_orphan_shims`` before the primary ``compose up``."""
    txt = _read(MASTIO_SRC / "deploy.sh")
    assert "_cleanup_orphan_shims" in txt, "mastio deploy.sh must wire the sweep"
    # The cleanup call must appear BEFORE the primary ``compose ... up -d``
    # (the bare-up, not the --wait upgrade-bundle path). Use the bare
    # ``up -d${RESET}`` marker which sits right after the cleanup call.
    cleanup_idx = txt.find('_cleanup_orphan_shims "$COMPOSE_PROJECT_NAME"')
    up_idx = txt.find("--env-file proxy.env up -d${RESET}")
    assert cleanup_idx >= 0 and up_idx >= 0, (cleanup_idx, up_idx)
    assert cleanup_idx < up_idx, (
        "sweep must run BEFORE the primary compose up, not after"
    )


def test_frontdesk_deploy_wires_cleanup_before_primary_up():
    txt = _read(FRONTDESK_SRC / "deploy.sh")
    assert "_cleanup_orphan_shims" in txt, "frontdesk deploy.sh must wire the sweep"
    cleanup_idx = txt.find('_cleanup_orphan_shims "$COMPOSE_PROJECT_NAME"')
    # The primary bare-up call in the frontdesk bundle uses the
    # COMPOSE_PROFILE_FLAGS array; assert ordering against that line.
    up_idx = txt.find('"${COMPOSE_PROFILE_FLAGS[@]}" up -d')
    assert cleanup_idx >= 0 and up_idx >= 0, (cleanup_idx, up_idx)
    assert cleanup_idx < up_idx


def test_enterprise_deploy_wires_cleanup_before_primary_up():
    txt = _read(ENTERPRISE_SRC / "deploy.sh")
    assert "_cleanup_orphan_shims" in txt, "enterprise deploy.sh must wire the sweep"
    cleanup_idx = txt.find('_cleanup_orphan_shims "$COMPOSE_PROJECT_NAME"')
    # The primary up call in the enterprise bundle uses --env-file
    # proxy.env up -d --wait at line ~260.
    up_idx = txt.rfind("docker compose --env-file proxy.env up -d --wait")
    assert cleanup_idx >= 0 and up_idx >= 0, (cleanup_idx, up_idx)
    assert cleanup_idx < up_idx


def test_helpers_define_both_orphan_helpers():
    """Both ``_cleanup_orphan_shims`` and ``_hint_on_bind_mount_failure``
    must be defined in the shared helper so all three deploy.sh see
    the same implementation (no drift across bundles)."""
    txt = _read(COMMON_HELPERS)
    assert "_cleanup_orphan_shims()" in txt
    assert "_hint_on_bind_mount_failure()" in txt
    # The filter is anchored on the project label — guard against a
    # future refactor that drops the anchor.
    assert "label=com.docker.compose.project=" in txt
    # Both status flags are present so the sweep covers "created"
    # (spawned-but-never-started) AND "exited" (crashed) shims.
    assert 'status=created' in txt
    assert 'status=exited' in txt


# ── README troubleshooting backfill ─────────────────────────────────────────


def test_readmes_document_not_a_directory_recovery():
    """Each bundle README must document the ``not a directory: mount``
    recovery so a customer hitting this error from a manual
    ``docker compose up`` outside the wrapper has a concrete fix."""
    for readme in (
        MASTIO_SRC / "README.md",
        FRONTDESK_SRC / "README.md",
        ENTERPRISE_SRC / "README.md",
    ):
        txt = _read(readme)
        assert "not a directory" in txt, f"{readme}: missing troubleshooting entry"
        # The recovery command (or its key parts) must appear, so the
        # README is actionable rather than just descriptive.
        assert "docker rm -f" in txt, f"{readme}: missing recovery command"
