"""Tests for ``cullis-connector doctor`` — stale MCP entry audit.

Drives the doctor against a temp directory holding fake IDE config
files. The ``patched_ides`` fixture redirects each registered IDE to
a unique JSON path under ``tmp_path`` so the test never touches the
operator's real Cursor/Claude Desktop/etc. config.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from cullis_connector import doctor, ide_config
from cullis_connector.ide_config import IDEDescriptor, KNOWN_IDES


@pytest.fixture
def patched_ides(monkeypatch, tmp_path):
    """Redirect every IDE to a tmp path we own — same pattern as
    ``tests/connector/test_ide_config.py::patched_ides``."""
    paths = {ide_id: tmp_path / f"{ide_id}.json" for ide_id in KNOWN_IDES}
    fake = {}
    for ide_id, desc in KNOWN_IDES.items():
        p = str(paths[ide_id])
        fake[ide_id] = IDEDescriptor(
            id=desc.id,
            display_name=desc.display_name,
            paths={"darwin": p, "win32": p, "linux": p},
            servers_key=desc.servers_key,
            kind=desc.kind,
            detect_binary=desc.detect_binary,
        )
    monkeypatch.setattr(ide_config, "KNOWN_IDES", fake)
    monkeypatch.setattr(doctor, "KNOWN_IDES", fake)
    return paths


@pytest.fixture
def fake_connector_on_path(monkeypatch, tmp_path):
    """Pretend ``cullis-connector`` is reachable via ``shutil.which``.

    Doctor's binary check uses the system ``shutil.which`` — patching
    it here keeps the test independent of whether the test runner
    happens to have the connector installed in PATH.
    """
    fake_bin = tmp_path / "fake-bin" / "cullis-connector"
    fake_bin.parent.mkdir(parents=True)
    fake_bin.write_text("#!/bin/sh\nexit 0\n")
    fake_bin.chmod(0o755)

    real_which = shutil.which

    def _which(cmd: str, *a, **kw):
        if cmd == "cullis-connector":
            return str(fake_bin)
        return real_which(cmd, *a, **kw)

    monkeypatch.setattr(doctor.shutil, "which", _which)
    return fake_bin


def _write_config(path: Path, entries: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": entries}, indent=2))


# ── _looks_like_cullis ─────────────────────────────────────────────────────


def test_looks_like_cullis_matches_connector_command():
    assert doctor._looks_like_cullis("cullis", "/usr/bin/cullis-connector", ["serve"])


def test_looks_like_cullis_matches_renamed_entry_with_serve():
    """Operator renamed ``cullis`` to ``cullis-prod`` — still ours."""
    assert doctor._looks_like_cullis("cullis-prod", "/some/path", ["serve", "--profile", "p"])


def test_looks_like_cullis_rejects_unrelated_server():
    assert not doctor._looks_like_cullis("postgres", "/usr/bin/postgres", ["--port", "5432"])


# ── _extract_profile_dir ───────────────────────────────────────────────────


def test_extract_profile_dir_from_dash_dash_profile():
    p = doctor._extract_profile_dir(["serve", "--profile", "work"])
    assert p is not None and p.name == "work"


def test_extract_profile_dir_from_equals_form():
    p = doctor._extract_profile_dir(["serve", "--profile=work"])
    assert p is not None and p.name == "work"


def test_extract_profile_dir_config_dir_takes_priority(tmp_path):
    """``--config-dir`` is the authoritative override — if both are
    set, doctor must validate the config-dir, not the profile-derived
    path. (The runtime resolution in ``ConnectorConfig`` follows the
    same precedence.)"""
    p = doctor._extract_profile_dir([
        "serve", "--profile", "work",
        "--config-dir", str(tmp_path),
    ])
    assert p == tmp_path


def test_extract_profile_dir_returns_none_when_neither_set():
    assert doctor._extract_profile_dir(["serve"]) is None


# ── scan(): happy path ─────────────────────────────────────────────────────


def test_scan_reports_ok_when_binary_and_profile_exist(
    patched_ides, fake_connector_on_path, tmp_path,
):
    """Healthy entry → ``ok`` so a clean dogfood run exits 0."""
    profile_dir = tmp_path / "profiles" / "work"
    profile_dir.mkdir(parents=True)
    monkeypatched_default = tmp_path
    # Doctor resolves --profile against DEFAULT_CONFIG_DIR; point it
    # at our tmp tree for the test.
    import cullis_connector.doctor as _d
    _d.DEFAULT_CONFIG_DIR = monkeypatched_default

    _write_config(patched_ides["cursor"], {
        "cullis": {
            "command": "cullis-connector",
            "args": ["serve", "--profile", "work"],
        }
    })
    entries = doctor.scan(["cursor"])
    assert len(entries) == 1
    assert entries[0].status == "ok"
    assert not doctor.has_problems(entries)


def test_scan_flags_stale_profile_dir(
    patched_ides, fake_connector_on_path, tmp_path,
):
    """Profile dir vanished → ``stale_profile`` + non-zero exit.

    This is the literal dogfood Finding #8: ``profile=dotfiles`` was
    in the MCP config but the dir had been wiped weeks earlier.
    """
    import cullis_connector.doctor as _d
    _d.DEFAULT_CONFIG_DIR = tmp_path  # no profiles/ subtree exists

    _write_config(patched_ides["cursor"], {
        "cullis": {
            "command": "cullis-connector",
            "args": ["serve", "--profile", "dotfiles"],
        }
    })
    entries = doctor.scan(["cursor"])
    assert len(entries) == 1
    assert entries[0].status == "stale_profile"
    assert "dotfiles" in entries[0].detail
    assert doctor.has_problems(entries)


def test_scan_flags_stale_binary(patched_ides, monkeypatch):
    """Binary missing → ``stale_binary`` so doctor explains why the
    IDE can't launch the MCP server, instead of letting the user
    discover it on first invocation."""
    monkeypatch.setattr(doctor.shutil, "which", lambda c: None)
    _write_config(patched_ides["cursor"], {
        "cullis": {
            "command": "cullis-connector",
            "args": ["serve", "--profile", "work"],
        }
    })
    entries = doctor.scan(["cursor"])
    assert len(entries) == 1
    assert entries[0].status == "stale_binary"
    assert doctor.has_problems(entries)


def test_scan_ignores_non_cullis_entries(patched_ides, fake_connector_on_path):
    """A foreign MCP server in the same config file must be silently
    skipped — doctor reports only the entries it knows belong to us."""
    _write_config(patched_ides["cursor"], {
        "postgres": {"command": "postgres-mcp", "args": []},
        "github": {"command": "gh-mcp", "args": []},
    })
    assert doctor.scan(["cursor"]) == []


def test_scan_flags_unreadable_config(patched_ides):
    """Garbled JSON → ``unreadable`` instead of an unhandled exception
    leaking out of the doctor command."""
    p = patched_ides["cursor"]
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not valid json")
    entries = doctor.scan(["cursor"])
    assert len(entries) == 1
    assert entries[0].status == "unreadable"
    assert doctor.has_problems(entries)


def test_scan_skips_clients_without_a_config_file(patched_ides):
    """Pre-install state: most operators won't have every supported
    client. Empty result is correct, doctor must not warn about it."""
    # No config files written at all — every patched path is missing.
    entries = doctor.scan(list(patched_ides.keys()))
    # COMMAND-kind clients (claude-code-cli) may yield ``advise`` rows
    # when ``claude`` is on PATH, but never the file-kind problem
    # statuses; the lack of a config file is silence by design.
    assert all(e.status in {"advise"} for e in entries)


# ── _cmd_doctor (CLI integration) ─────────────────────────────────────────


def test_cmd_doctor_returns_zero_on_clean_scan(
    patched_ides, fake_connector_on_path, tmp_path, capsys,
):
    """End-to-end: ``cullis-connector doctor`` exits 0 when nothing is
    broken — composes correctly with ``set -e`` in install scripts."""
    import argparse
    import cullis_connector.doctor as _d
    _d.DEFAULT_CONFIG_DIR = tmp_path
    (tmp_path / "profiles" / "work").mkdir(parents=True)

    _write_config(patched_ides["cursor"], {
        "cullis": {
            "command": "cullis-connector",
            "args": ["serve", "--profile", "work"],
        }
    })

    from cullis_connector.cli import _cmd_doctor
    from cullis_connector.config import ConnectorConfig

    cfg = ConnectorConfig(config_dir=tmp_path)
    args = argparse.Namespace(ides=["cursor"])
    rc = _cmd_doctor(cfg, args)
    out = capsys.readouterr().out
    assert rc == 0
    assert "ok" in out


def test_cmd_doctor_returns_one_on_stale_entry(
    patched_ides, fake_connector_on_path, tmp_path, capsys,
):
    """Stale profile detected → exit 1 so CI / scripts can react."""
    import argparse
    import cullis_connector.doctor as _d
    _d.DEFAULT_CONFIG_DIR = tmp_path  # profile ``dotfiles`` does not exist

    _write_config(patched_ides["cursor"], {
        "cullis": {
            "command": "cullis-connector",
            "args": ["serve", "--profile", "dotfiles"],
        }
    })

    from cullis_connector.cli import _cmd_doctor
    from cullis_connector.config import ConnectorConfig

    cfg = ConnectorConfig(config_dir=tmp_path)
    args = argparse.Namespace(ides=["cursor"])
    rc = _cmd_doctor(cfg, args)
    out = capsys.readouterr().out
    assert rc == 1
    assert "stale_profile" in out
    assert "dotfiles" in out
