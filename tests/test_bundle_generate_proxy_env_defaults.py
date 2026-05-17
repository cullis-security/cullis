"""P3 MINOR-F: packaging/mastio-bundle/generate-proxy-env.sh --defaults
emits a real ``MCP_PROXY_PROXY_PUBLIC_URL`` value instead of leaving
the field empty or commented out.

Failure mode this pins (dogfood tabula rasa, 2026-05-17): an operator
invokes ``./generate-proxy-env.sh --defaults`` from CI / Ansible / a
quick laptop boot, then runs ``./deploy.sh up`` without going through
the deploy.sh interactive prompt. The resulting proxy.env carries no
uncommented ``MCP_PROXY_PROXY_PUBLIC_URL=`` line at all (the
``proxy.env.example`` ships the field commented and the previous sed
substitution silently no-oped on commented lines). Mastio boots, the
docker-compose ``${VAR:-...}`` fallback does NOT apply uniformly to
every consumer of proxy.env (CI smoke tests, Ansible plays, direct
python-dotenv readers), and every agent enrollment fails 401
``Invalid DPoP proof: htu mismatch`` against an empty htu.

The fix: ``--defaults`` (and the interactive prompt's empty-input
fallback) writes the laptop / single-VM default
``https://host.docker.internal:9443``, which matches the
docker-compose.yml fallback and the deploy.sh interactive prompt
default. Operators with a stable public hostname override via the
``PROXY_PUBLIC_URL`` env var or by editing proxy.env after generation.

These tests drive ``generate-proxy-env.sh`` directly in a tmp bundle
dir, parse the resulting proxy.env, and assert the public URL line is
present and uncommented.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
BUNDLE_SRC = REPO_ROOT / "packaging" / "mastio-bundle"


def _stage_bundle(tmp_path: pathlib.Path) -> pathlib.Path:
    """Mirror the minimum bundle layout into ``tmp_path`` so
    ``generate-proxy-env.sh`` finds its ``proxy.env.example`` sibling.
    """
    bundle = tmp_path / "mastio-bundle"
    bundle.mkdir(parents=True)
    shutil.copy2(BUNDLE_SRC / "generate-proxy-env.sh", bundle / "generate-proxy-env.sh")
    shutil.copy2(BUNDLE_SRC / "proxy.env.example", bundle / "proxy.env.example")
    (bundle / "generate-proxy-env.sh").chmod(0o755)
    return bundle


def _run_generate(
    bundle: pathlib.Path,
    *args: str,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PROJECT_DIR"] = str(bundle)
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["bash", str(bundle / "generate-proxy-env.sh"), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def _parse_env(env_path: pathlib.Path) -> dict[str, str]:
    """Parse a proxy.env-style file into a dict, ignoring commented and
    blank lines. Trailing newlines on values are stripped so the
    assertion compares literal URL strings.
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


# ──────────────────────────────────────────────────────────────────────
# --defaults
# ──────────────────────────────────────────────────────────────────────


def test_defaults_emits_proxy_public_url_laptop_default(tmp_path: pathlib.Path) -> None:
    """``--defaults`` writes the laptop / sibling-container URL so the
    resulting proxy.env survives ``./deploy.sh up`` without the
    interactive prompt and never produces 401 htu mismatch on agent
    enrollment.
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(bundle, "--defaults", "--force")
    assert result.returncode == 0, f"generate-proxy-env.sh failed:\n{result.stderr}"

    env = _parse_env(bundle / "proxy.env")
    assert "MCP_PROXY_PROXY_PUBLIC_URL" in env, (
        "MCP_PROXY_PROXY_PUBLIC_URL missing from proxy.env. "
        "P3 MINOR-F regression: --defaults must emit an uncommented value."
    )
    assert env["MCP_PROXY_PROXY_PUBLIC_URL"] == "https://host.docker.internal:9443"


def test_defaults_writes_single_uncommented_line(tmp_path: pathlib.Path) -> None:
    """No duplicate ``MCP_PROXY_PROXY_PUBLIC_URL=`` line. Previous sed
    silently no-oped on commented lines, so a careless ``echo >> $OUT``
    fix would have left the original commented placeholder PLUS the
    new uncommented line. Operators reading the file by hand would see
    two values and pick the wrong one.
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(bundle, "--defaults", "--force")
    assert result.returncode == 0, result.stderr

    lines = (bundle / "proxy.env").read_text().splitlines()
    uncommented = [
        ln for ln in lines if ln.startswith("MCP_PROXY_PROXY_PUBLIC_URL=")
    ]
    commented = [
        ln for ln in lines
        if ln.lstrip().startswith("#")
        and "MCP_PROXY_PROXY_PUBLIC_URL=" in ln
        and not ln.lstrip().startswith("# ")
    ]
    assert len(uncommented) == 1, (
        f"expected exactly one uncommented MCP_PROXY_PROXY_PUBLIC_URL line, "
        f"got {uncommented}"
    )
    # The commented placeholder from proxy.env.example must be stripped
    # so an operator never sees two contradictory values in the same
    # file when they open it to override the public URL.
    assert commented == [], (
        f"commented placeholder still present after --defaults: {commented}"
    )


def test_defaults_env_var_override_wins(tmp_path: pathlib.Path) -> None:
    """An operator with a stable hostname exports
    ``PROXY_PUBLIC_URL=...`` and runs ``--defaults``: the explicit
    value wins over the laptop default. Same pattern as ``--prod``,
    but available from the defaults path so CI / Ansible can pre-bake
    a custom URL without flipping to ``--prod`` (which would also
    require BROKER_URL).
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(
        bundle,
        "--defaults",
        "--force",
        env_overrides={"PROXY_PUBLIC_URL": "https://mastio.acme.local:9443"},
    )
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "proxy.env")
    assert env["MCP_PROXY_PROXY_PUBLIC_URL"] == "https://mastio.acme.local:9443"


# ──────────────────────────────────────────────────────────────────────
# --prod
# ──────────────────────────────────────────────────────────────────────


def test_prod_emits_required_public_url(tmp_path: pathlib.Path) -> None:
    """``--prod`` is the CI / production-rehearsal path: BROKER_URL +
    PROXY_PUBLIC_URL are required env vars, the resulting proxy.env
    must carry both as uncommented values. Regression guard for the
    same sed-on-commented-line bug as --defaults.
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(
        bundle,
        "--prod",
        "--force",
        env_overrides={
            "BROKER_URL": "https://broker.example.com",
            "PROXY_PUBLIC_URL": "https://mastio.acme.example.com",
        },
    )
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "proxy.env")
    assert env["MCP_PROXY_PROXY_PUBLIC_URL"] == "https://mastio.acme.example.com"
    assert env["MCP_PROXY_BROKER_URL"] == "https://broker.example.com"
    assert env["MCP_PROXY_ENVIRONMENT"] == "production"


def test_prod_refuses_without_public_url(tmp_path: pathlib.Path) -> None:
    """``--prod`` without PROXY_PUBLIC_URL must die loudly, never
    silently fall back to the laptop default (which would put a
    development URL into a production proxy.env).
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(
        bundle,
        "--prod",
        "--force",
        env_overrides={"BROKER_URL": "https://broker.example.com"},
    )
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "PROXY_PUBLIC_URL" in combined


# ──────────────────────────────────────────────────────────────────────
# --defaults companion fields
# ──────────────────────────────────────────────────────────────────────


def test_defaults_emits_random_admin_secret_and_signing_key(
    tmp_path: pathlib.Path,
) -> None:
    """Sanity for the rest of the defaults block: the random-generated
    secrets the script claims to write actually land in proxy.env and
    are not the literal ``change-me-in-production`` placeholder.
    Guards against a future refactor that reorders the sed block and
    accidentally drops one of these alongside the public URL fix.
    """
    bundle = _stage_bundle(tmp_path)
    result = _run_generate(bundle, "--defaults", "--force")
    assert result.returncode == 0, result.stderr

    env = _parse_env(bundle / "proxy.env")
    assert env.get("MCP_PROXY_ADMIN_SECRET", "") != ""
    assert env["MCP_PROXY_ADMIN_SECRET"] != "change-me-in-production"
    assert env.get("MCP_PROXY_DASHBOARD_SIGNING_KEY", "") != ""
    assert env["MCP_PROXY_ENVIRONMENT"] == "development"
    # Broker stays at the same-docker-network default for the laptop
    # path (an operator wiring a remote broker uses --prod).
    assert env["MCP_PROXY_BROKER_URL"] == "http://broker:8000"
