"""P3 MINOR-D: packaging/frontdesk-bundle/generate-frontdesk-env.sh
honors invoker-shell env vars for fields that ship COMMENTED in
``frontdesk.env.example`` (``CONNECTOR_VERSION``, ``CHAT_VERSION``,
``CULLIS_FRONTDESK_MASTIO_URL``, ``CULLIS_SITE_URL``).

Failure mode this pins (dogfood tabula rasa, 2026-05-17): a customer
admin doing version pinning via CI / Ansible runs

    CONNECTOR_VERSION=l3a-fix ./deploy.sh ...

expecting the bundle to pull the ``l3a-fix`` tag. Pre-fix, the env
var was silently dropped: ``docker compose --env-file frontdesk.env``
only reads values FROM the file, the parent shell env is not consulted
for ``${VAR:-default}`` substitutions. The generated ``frontdesk.env``
left ``CONNECTOR_VERSION`` commented (or sed-substituted the wrong
hard-coded default), and the next ``docker compose up`` ran an image
tag the operator never asked for.

The fix mirrors the #772 strip-and-append pattern: every env var that
ships COMMENTED in the example is resolved from invoker shell env
(with a sane default for unset), any pre-existing line (commented or
not) is stripped, and the resolved value is appended.

These tests drive ``generate-frontdesk-env.sh`` directly in a tmp
bundle dir, parse the resulting ``frontdesk.env``, and assert the env
var overrides survive into the file.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BUNDLE_SRC = REPO_ROOT / "packaging" / "frontdesk-bundle"


def _stage_bundle(tmp_path: pathlib.Path) -> pathlib.Path:
    """Mirror the minimum bundle layout into ``tmp_path`` so
    ``generate-frontdesk-env.sh`` finds its siblings
    (``frontdesk.env.example``, ``_lib-admin-secret.sh``).
    """
    bundle = tmp_path / "frontdesk-bundle"
    bundle.mkdir(parents=True)
    for fname in (
        "generate-frontdesk-env.sh",
        "frontdesk.env.example",
        "_lib-admin-secret.sh",
    ):
        shutil.copy2(BUNDLE_SRC / fname, bundle / fname)
    (bundle / "generate-frontdesk-env.sh").chmod(0o755)
    return bundle


def _run_generate(
    bundle: pathlib.Path,
    *args: str,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    # Strip parent-process inherited values for the vars under test so
    # the test does not pick up the running user's shell state.
    for k in (
        "CONNECTOR_VERSION",
        "CHAT_VERSION",
        "CULLIS_FRONTDESK_MASTIO_URL",
        "CULLIS_SITE_URL",
        "CULLIS_FRONTDESK_ORG_ID",
        "CULLIS_FRONTDESK_TRUST_DOMAIN",
        "CULLIS_FRONTDESK_CA_BUNDLE_HOST",
        "CULLIS_CONNECTOR_ADMIN_SECRET",
    ):
        env.pop(k, None)
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["bash", str(bundle / "generate-frontdesk-env.sh"), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        cwd=str(bundle),
    )


def _parse_env(env_path: pathlib.Path) -> dict[str, str]:
    """Parse a frontdesk.env-style file into a dict, ignoring commented
    and blank lines. Trailing newlines on values are stripped so the
    assertion compares literal strings.
    """
    out: dict[str, str] = {}
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _count_lines(env_path: pathlib.Path, prefix: str) -> int:
    """Count how many lines (uncommented or commented) match
    ``^#*[[:space:]]*<prefix>=``. Used to assert idempotency: no
    duplicate lines on rerun.
    """
    count = 0
    for raw in env_path.read_text().splitlines():
        stripped = raw.lstrip("# \t")
        if stripped.startswith(f"{prefix}="):
            count += 1
    return count


# ──────────────────────────────────────────────────────────────────────
# CONNECTOR_VERSION env override
# ──────────────────────────────────────────────────────────────────────


def test_connector_version_env_override_honored(tmp_path: pathlib.Path) -> None:
    """``CONNECTOR_VERSION=l3a-fix ./generate-frontdesk-env.sh`` lands
    ``l3a-fix`` in frontdesk.env, not the hard-coded default.

    Customer admin scenario: version pinning via CI / Ansible. Pre-fix,
    deploy.sh silently dropped the invoker env var because
    ``docker compose --env-file`` does not propagate parent shell env.
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(
        bundle,
        "--defaults",
        "--force",
        env_overrides={"CONNECTOR_VERSION": "l3a-fix"},
    )
    assert result.returncode == 0, (
        f"generate-frontdesk-env.sh failed:\n{result.stderr}"
    )

    env = _parse_env(bundle / "frontdesk.env")
    assert env.get("CONNECTOR_VERSION") == "l3a-fix", (
        f"expected CONNECTOR_VERSION=l3a-fix, got {env.get('CONNECTOR_VERSION')!r}. "
        "P3 MINOR-D regression: invoker env var must override the in-template default."
    )


def test_connector_version_default_when_unset(tmp_path: pathlib.Path) -> None:
    """No CONNECTOR_VERSION env var set: frontdesk.env carries the sane
    default (the same value the bundle README documents).
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(bundle, "--defaults", "--force")
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "frontdesk.env")
    # The exact default tracks the comment shipped in frontdesk.env.example.
    # Asserting non-empty + non-placeholder is enough to pin the regression:
    # the bug was "field missing", not "field has the wrong number".
    assert env.get("CONNECTOR_VERSION", "") != "", (
        "CONNECTOR_VERSION missing from frontdesk.env when unset; "
        "must fall back to a sane default."
    )
    # Sanity: the value looks like a version string, not a placeholder.
    assert env["CONNECTOR_VERSION"] not in ("", "TODO", "change-me")


# ──────────────────────────────────────────────────────────────────────
# CHAT_VERSION env override
# ──────────────────────────────────────────────────────────────────────


def test_chat_version_env_override_honored(tmp_path: pathlib.Path) -> None:
    """Same shape as CONNECTOR_VERSION: the Cullis Chat image tag is
    overridable from the invoker shell. Regression guard against future
    refactors that touch one var and forget the symmetric one.
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(
        bundle,
        "--defaults",
        "--force",
        env_overrides={"CHAT_VERSION": "0.4.2-rc1"},
    )
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "frontdesk.env")
    assert env.get("CHAT_VERSION") == "0.4.2-rc1"


# ──────────────────────────────────────────────────────────────────────
# CULLIS_SITE_URL + CULLIS_FRONTDESK_MASTIO_URL env override
# ──────────────────────────────────────────────────────────────────────


def test_mastio_url_env_overrides_honored(tmp_path: pathlib.Path) -> None:
    """Two Mastio URL fields ship commented in the example. The
    invoker can pin either or both via env. Empty (unset) leaves the
    line commented so the in-template documentation survives and the
    downstream first-boot wizard mode (CULLIS_SITE_URL empty triggers
    the in-browser /setup/discover path) keeps working.
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(
        bundle,
        "--defaults",
        "--force",
        env_overrides={
            "CULLIS_SITE_URL": "https://mastio.acme.local:9443",
            "CULLIS_FRONTDESK_MASTIO_URL": "https://mastio.acme.local:9443",
        },
    )
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "frontdesk.env")
    assert env.get("CULLIS_SITE_URL") == "https://mastio.acme.local:9443"
    assert env.get("CULLIS_FRONTDESK_MASTIO_URL") == "https://mastio.acme.local:9443"


def test_mastio_urls_stay_commented_when_unset(tmp_path: pathlib.Path) -> None:
    """When CULLIS_SITE_URL / CULLIS_FRONTDESK_MASTIO_URL are not set
    in the invoker env, generate-frontdesk-env.sh does NOT write
    an empty uncommented line.

    First-boot wizard mode (ADR-019 Phase 8c) keys off
    ``CULLIS_SITE_URL`` being EMPTY (not set, or commented). Writing
    ``CULLIS_SITE_URL=`` uncommented would still be empty-string in
    practice (docker-compose ``${VAR:-}`` resolves identically), but
    the deploy.sh wizard detection grep would mis-classify a literal
    empty value differently from a missing line and the wizard branch
    would never fire. Keep them commented.
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(bundle, "--defaults", "--force")
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "frontdesk.env")
    assert "CULLIS_SITE_URL" not in env, (
        f"CULLIS_SITE_URL must stay commented when invoker env is unset; "
        f"got {env.get('CULLIS_SITE_URL')!r}"
    )
    assert "CULLIS_FRONTDESK_MASTIO_URL" not in env, (
        f"CULLIS_FRONTDESK_MASTIO_URL must stay commented when invoker env is unset; "
        f"got {env.get('CULLIS_FRONTDESK_MASTIO_URL')!r}"
    )


# ──────────────────────────────────────────────────────────────────────
# Idempotency
# ──────────────────────────────────────────────────────────────────────


def test_rerun_is_idempotent_no_duplicate_lines(tmp_path: pathlib.Path) -> None:
    """Rerunning ``--defaults --force`` with the same env produces
    exactly the same field set: no duplicate
    ``CONNECTOR_VERSION=`` / ``CHAT_VERSION=`` lines piling up on each
    invocation. The strip-and-append pattern must own the line; the
    sed-on-commented-line bug from #772 would have left a commented
    placeholder PLUS the new uncommented line on rerun.
    """
    bundle = _stage_bundle(tmp_path)
    env_overrides = {"CONNECTOR_VERSION": "0.4.7", "CHAT_VERSION": "0.4.2"}

    for _ in range(3):
        result = _run_generate(
            bundle, "--defaults", "--force", env_overrides=env_overrides
        )
        assert result.returncode == 0, result.stderr

    out = bundle / "frontdesk.env"
    assert _count_lines(out, "CONNECTOR_VERSION") == 1, (
        f"expected exactly one CONNECTOR_VERSION= line, got "
        f"{_count_lines(out, 'CONNECTOR_VERSION')}"
    )
    assert _count_lines(out, "CHAT_VERSION") == 1
    # And the value is the latest one.
    env = _parse_env(out)
    assert env["CONNECTOR_VERSION"] == "0.4.7"
    assert env["CHAT_VERSION"] == "0.4.2"


# ──────────────────────────────────────────────────────────────────────
# Multiple vars set simultaneously
# ──────────────────────────────────────────────────────────────────────


def test_multiple_env_vars_all_honored(tmp_path: pathlib.Path) -> None:
    """Full CI-style invocation: 4 env vars at once. All four land in
    frontdesk.env. Guards against a future refactor that drops one
    var while preserving the others (the test_*_env_override_honored
    tests assert each var in isolation, this one asserts the
    combination).
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(
        bundle,
        "--defaults",
        "--force",
        env_overrides={
            "CONNECTOR_VERSION": "0.4.7",
            "CHAT_VERSION": "0.4.2",
            "CULLIS_SITE_URL": "https://mastio.acme.local:9443",
            "CULLIS_FRONTDESK_MASTIO_URL": "https://mastio.acme.local:9443",
        },
    )
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "frontdesk.env")
    assert env.get("CONNECTOR_VERSION") == "0.4.7"
    assert env.get("CHAT_VERSION") == "0.4.2"
    assert env.get("CULLIS_SITE_URL") == "https://mastio.acme.local:9443"
    assert env.get("CULLIS_FRONTDESK_MASTIO_URL") == "https://mastio.acme.local:9443"


def test_prod_mode_honors_env_overrides_too(tmp_path: pathlib.Path) -> None:
    """``--prod`` is the CI / production-rehearsal path. Same env-var
    plumbing must work there: requirement comes from the same customer
    admin scenario (Ansible play, scripted deploy).
    """
    bundle = _stage_bundle(tmp_path)
    # Stage a fake CA bundle so --prod's existence check passes.
    fake_ca = bundle / "fake-ca.pem"
    fake_ca.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

    result = _run_generate(
        bundle,
        "--prod",
        "--force",
        env_overrides={
            "CULLIS_FRONTDESK_ORG_ID": "acme",
            "CULLIS_FRONTDESK_TRUST_DOMAIN": "acme.prod",
            "CULLIS_FRONTDESK_CA_BUNDLE_HOST": str(fake_ca),
            "CONNECTOR_VERSION": "0.4.7",
            "CHAT_VERSION": "0.4.2",
        },
    )
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "frontdesk.env")
    assert env.get("CONNECTOR_VERSION") == "0.4.7"
    assert env.get("CHAT_VERSION") == "0.4.2"
    assert env.get("CULLIS_FRONTDESK_ORG_ID") == "acme"
    assert env.get("CULLIS_FRONTDESK_TRUST_DOMAIN") == "acme.prod"
