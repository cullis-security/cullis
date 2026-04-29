"""Tests for the restart hint that ``install-mcp`` prints after
writing the Cullis entry into one or more clients (Finding #7,
2026-04-29 dogfood).

Without the hint, operators invoke a tool, get a "tool not found"
error, and only then realise the existing Claude Code / Cursor
session loaded its MCP config at startup and has not yet seen the
new server. The hint pre-empts that loop.
"""
from __future__ import annotations

import argparse

import pytest

from cullis_connector.cli import _cmd_install_mcp
from cullis_connector.config import ConnectorConfig
from cullis_connector import ide_config
from cullis_connector.ide_config import (
    IDEDescriptor,
    IDEStatus,
    KNOWN_IDES,
)


@pytest.fixture
def patched_ides(monkeypatch, tmp_path):
    """Same redirect-to-tmp pattern as test_ide_config / test_doctor."""
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
    # cli imports KNOWN_IDES inside the function — monkeypatch where
    # the import lands.
    monkeypatch.setattr("cullis_connector.cli.KNOWN_IDES", fake, raising=False)
    return paths


def _make_args(ides=None, uninstall=False, list_only=False) -> argparse.Namespace:
    return argparse.Namespace(
        ides=ides,
        ide_uninstall=uninstall,
        ide_list_only=list_only,
        profile=None,
        config_dir=None,
        site_url=None,
        verify_tls=None,
    )


def test_install_emits_restart_hint_with_client_name(
    patched_ides, tmp_path, capsys, monkeypatch,
):
    """A successful install must print a hint that names the
    affected clients — generic "restart your IDE" wording is too
    vague when several clients are configured at once."""
    cfg = ConnectorConfig(config_dir=tmp_path)

    # Stub the underlying writer so the test doesn't actually touch
    # disk via ide_config — we only care about the message the CLI
    # surfaces to the operator.
    from cullis_connector.ide_config import InstallResult

    def _fake_install(ide_id, *, backup_dir, args):
        return InstallResult(
            ide_id=ide_id,
            status="installed",
            config_path=patched_ides[ide_id],
        )

    monkeypatch.setattr("cullis_connector.ide_config.install_mcp", _fake_install)
    # Pretend Cursor is detected so the install path actually runs.
    monkeypatch.setattr(
        "cullis_connector.ide_config.detect_ide_status",
        lambda i: type(
            "D", (), {"status": IDEStatus.DETECTED, "display_name": KNOWN_IDES[i].display_name, "note": None},
        )(),
    )
    monkeypatch.setattr(
        "cullis_connector.ide_config.detect_all", lambda: [],
    )

    rc = _cmd_install_mcp(cfg, _make_args(ides=["cursor"]))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Restart" in out
    assert "Cursor" in out  # specific display name, not just "your IDE"
    assert "Existing sessions" in out  # warns the live session won't see them


def test_install_does_not_emit_hint_when_uninstalling(
    patched_ides, tmp_path, capsys, monkeypatch,
):
    """``--uninstall`` removes the entry; nothing for the operator to
    restart-to-load. The hint would be confusing here."""
    cfg = ConnectorConfig(config_dir=tmp_path)

    from cullis_connector.ide_config import InstallResult

    def _fake_uninstall(ide_id, *, backup_dir):
        return InstallResult(
            ide_id=ide_id,
            status="installed",  # uninstall reuses ``installed`` status to mean "took effect"
            config_path=patched_ides[ide_id],
        )

    monkeypatch.setattr("cullis_connector.ide_config.uninstall_mcp", _fake_uninstall)
    monkeypatch.setattr(
        "cullis_connector.ide_config.detect_ide_status",
        lambda i: type(
            "D", (), {"status": IDEStatus.CONFIGURED, "display_name": KNOWN_IDES[i].display_name, "note": None},
        )(),
    )

    rc = _cmd_install_mcp(cfg, _make_args(ides=["cursor"], uninstall=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Restart" not in out


def test_install_does_not_emit_hint_when_already_configured(
    patched_ides, tmp_path, capsys, monkeypatch,
):
    """Re-running ``install-mcp`` is idempotent — if no entry actually
    changed, the operator does NOT need to restart anything."""
    cfg = ConnectorConfig(config_dir=tmp_path)

    from cullis_connector.ide_config import InstallResult

    def _fake_install(ide_id, *, backup_dir, args):
        return InstallResult(
            ide_id=ide_id,
            status="already_configured",
            config_path=patched_ides[ide_id],
        )

    monkeypatch.setattr("cullis_connector.ide_config.install_mcp", _fake_install)
    monkeypatch.setattr(
        "cullis_connector.ide_config.detect_ide_status",
        lambda i: type(
            "D", (), {"status": IDEStatus.CONFIGURED, "display_name": KNOWN_IDES[i].display_name, "note": None},
        )(),
    )

    rc = _cmd_install_mcp(cfg, _make_args(ides=["cursor"]))
    out = capsys.readouterr().out
    assert rc == 0
    assert "Restart" not in out
