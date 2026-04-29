"""Tests for cullis_connector.autostart — OS-native login registration.

We cover the file-rendering layer (plist / service-unit generation) and
mock out the actual ``launchctl`` / ``schtasks`` / ``systemctl`` calls,
because those are side-effecting commands that would register real
services on the test host.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cullis_connector import autostart


@pytest.fixture
def tmp_home(tmp_path, monkeypatch):
    """Redirect ``Path.home()`` so installer writes stay inside tmp_path."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


# ── Plist / unit file rendering ──────────────────────────────────────────


def test_mac_plist_contains_label_and_args():
    text = autostart._render_mac_plist(
        ["cullis-connector", "dashboard", "--no-open-browser"],
        Path("/fake/log"),
    )
    assert "<key>Label</key>" in text
    assert f"<string>{autostart.SERVICE_LABEL}</string>" in text
    assert "<string>cullis-connector</string>" in text
    assert "<string>dashboard</string>" in text
    assert "<string>--no-open-browser</string>" in text
    assert "RunAtLoad" in text
    assert "/fake/log/connector.out.log" in text


def test_mac_plist_escapes_xml_in_args():
    text = autostart._render_mac_plist(
        ["foo", "a<b&c>"],
        Path("/tmp"),
    )
    assert "<string>a&lt;b&amp;c&gt;</string>" in text


def test_linux_unit_has_exec_start_and_install_target():
    text = autostart._render_linux_unit(
        ["cullis-connector", "dashboard", "--no-open-browser"],
    )
    assert "[Unit]" in text
    assert "[Service]" in text
    assert "[Install]" in text
    assert "ExecStart=cullis-connector dashboard --no-open-browser" in text
    assert "WantedBy=default.target" in text


def test_linux_unit_escapes_spaces_in_args():
    text = autostart._render_linux_unit(
        ["/usr/local/bin/cullis-connector", "dashboard", "--note=with space"],
    )
    # systemd expects backslash-escaped spaces in ExecStart
    assert "with\\ space" in text


def test_linux_unit_prevents_crash_loop_on_port_busy():
    """Dogfood Finding #1 (2026-04-29): a stale autostart unit and a
    manually-launched dashboard collided on 7777 and the unit's
    ``Restart=on-failure RestartSec=3s`` produced ~350 fail/h.
    The CLI now exits 78 (EX_CONFIG) on port-busy; the unit must
    pin that exit code into ``RestartPreventExitStatus`` so systemd
    stops looping.
    """
    text = autostart._render_linux_unit(["cullis-connector", "dashboard"])
    assert "RestartPreventExitStatus=78" in text
    # Sanity: the existing on-failure restart stays in place — only
    # the EX_CONFIG signal is excluded from the retry policy.
    assert "Restart=on-failure" in text


# ── Linux install / uninstall (file-level, subprocess mocked) ───────────


def test_linux_install_writes_unit_file(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    monkeypatch.setattr(autostart.shutil, "which", lambda _: "/usr/bin/systemctl")
    with patch("cullis_connector.autostart.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        result = autostart.install_autostart(["cullis-connector", "dashboard"])

    assert result.status == "installed"
    assert result.platform == "linux"
    unit_path = tmp_home / ".config/systemd/user/cullis-connector.service"
    assert unit_path.exists()
    content = unit_path.read_text()
    assert "ExecStart=cullis-connector dashboard" in content

    # systemctl daemon-reload + enable --now called
    assert run.call_count >= 2


def test_linux_install_is_idempotent(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    monkeypatch.setattr(autostart.shutil, "which", lambda _: "/usr/bin/systemctl")
    with patch("cullis_connector.autostart.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        first = autostart.install_autostart(["cullis-connector", "dashboard"])
        second = autostart.install_autostart(["cullis-connector", "dashboard"])

    assert first.status == "installed"
    assert second.status == "already_configured"


def test_linux_install_reports_note_when_systemctl_fails_soft(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    monkeypatch.setattr(autostart.shutil, "which", lambda _: "/usr/bin/systemctl")
    with patch("cullis_connector.autostart.subprocess.run") as run:
        # daemon-reload succeeds, enable --now fails (common on headless CI
        # where no user session is active).
        outputs = [
            type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
            type("R", (), {"returncode": 1, "stdout": "", "stderr": "Failed to connect to bus"})(),
        ]
        run.side_effect = outputs
        result = autostart.install_autostart(["cullis-connector", "dashboard"])

    # File is written; we soft-fail on enable so user sees a helpful note.
    assert result.status == "installed"
    assert "enable" in (result.note or "").lower() or "bus" in (result.note or "").lower()


def test_linux_install_errors_without_systemctl(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    monkeypatch.setattr(autostart.shutil, "which", lambda _: None)
    result = autostart.install_autostart(["cullis-connector", "dashboard"])
    assert result.status == "error"
    assert "systemd" in (result.error or "").lower()


def test_linux_uninstall_removes_file(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    monkeypatch.setattr(autostart.shutil, "which", lambda _: "/usr/bin/systemctl")
    # First install so a file exists.
    with patch("cullis_connector.autostart.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        autostart.install_autostart(["cullis-connector", "dashboard"])
        result = autostart.uninstall_autostart()

    assert result.status == "uninstalled"
    assert not (tmp_home / ".config/systemd/user/cullis-connector.service").exists()


def test_linux_uninstall_on_missing_is_noop(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    result = autostart.uninstall_autostart()
    assert result.status == "missing"


def test_linux_status(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    status = autostart.autostart_status()
    assert status.installed is False

    # File presence alone flips status to installed — we don't shell out
    # to systemctl for status reads because that's flaky on CI.
    unit = tmp_home / ".config/systemd/user/cullis-connector.service"
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text("[Service]\n")
    status = autostart.autostart_status()
    assert status.installed is True


# ── macOS install path (subprocess mocked) ──────────────────────────────


def test_mac_install_writes_plist(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "darwin")
    monkeypatch.setattr(autostart.os, "getuid", lambda: 1000)
    with patch("cullis_connector.autostart.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        result = autostart.install_autostart(["cullis-connector", "dashboard"])

    assert result.status == "installed"
    assert result.platform == "darwin"
    plist = tmp_home / "Library/LaunchAgents" / f"{autostart.SERVICE_LABEL}.plist"
    assert plist.exists()
    assert "<key>Label</key>" in plist.read_text()


def test_mac_install_idempotent(tmp_home, monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "darwin")
    monkeypatch.setattr(autostart.os, "getuid", lambda: 1000)
    with patch("cullis_connector.autostart.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        first = autostart.install_autostart(["cullis-connector", "dashboard"])
        second = autostart.install_autostart(["cullis-connector", "dashboard"])

    assert first.status == "installed"
    assert second.status == "already_configured"


# ── Command recommendation ──────────────────────────────────────────────


def test_recommend_command_falls_back_to_python_m(monkeypatch):
    monkeypatch.setattr(autostart.shutil, "which", lambda _: None)
    cmd = autostart.recommend_command()
    assert cmd[1:] == ["-m", "cullis_connector", "dashboard", "--no-open-browser"]


def test_recommend_command_prefers_binary_on_path(monkeypatch):
    monkeypatch.setattr(autostart.shutil, "which", lambda name: "/usr/bin/cullis-connector")
    cmd = autostart.recommend_command()
    assert cmd == ["/usr/bin/cullis-connector", "dashboard", "--no-open-browser"]


# ── Empty-command guard ────────────────────────────────────────────────


def test_install_refuses_empty_argv():
    result = autostart.install_autostart([])
    assert result.status == "error"
