"""Launch the connector dashboard at login — one abstraction, three OSes.

* **macOS** — user-level LaunchAgent plist in ``~/Library/LaunchAgents/``.
  Registered with ``launchctl bootstrap`` so it survives reboot and kicks
  in automatically on the next GUI login.
* **Windows** — Scheduled Task created via ``schtasks.exe`` with trigger
  ``onlogon``. No Administrator rights required because we install under
  the current user.
* **Linux** — systemd user service in ``~/.config/systemd/user/``.
  Enabled with ``systemctl --user enable --now``; ``loginctl
  enable-linger`` is the user's call if they want the service alive
  outside of a graphical session (headless servers rarely want this).

The command we register is whatever the caller passes, typically::

    ["cullis-connector", "dashboard", "--no-open-browser"]

We refuse to guess the binary path — callers decide whether to use
``shutil.which``, an absolute PyInstaller bundle path, or ``python -m``.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path


SERVICE_LABEL = "io.cullis.connector"
WIN_TASK_NAME = "Cullis Connector"
LINUX_UNIT_NAME = "cullis-connector.service"


@dataclass
class AutostartResult:
    status: str  # "installed", "already_configured", "uninstalled", "missing", "error"
    platform: str
    service_path: Path | None = None
    note: str | None = None
    error: str | None = None


@dataclass
class AutostartStatus:
    installed: bool
    platform: str
    service_path: Path | None = None
    note: str | None = None


# ── Public API ───────────────────────────────────────────────────────────


def install_autostart(command: list[str]) -> AutostartResult:
    """Register ``command`` to run on user login.

    ``command`` is an argv list — its first element is the binary to
    exec. Passing a relative name (``"cullis-connector"``) is fine on
    macOS/Linux because the shell PATH is searched; on Windows the task
    scheduler expects an absolute path so callers should resolve it with
    ``shutil.which()`` before calling.
    """
    if not command:
        return AutostartResult(
            "error", _os_key(), error="Command argv cannot be empty."
        )

    osk = _os_key()
    if osk == "darwin":
        return _install_mac(command)
    if osk == "win32":
        return _install_windows(command)
    if osk == "linux":
        return _install_linux(command)
    return AutostartResult(
        "error", osk, error=f"Autostart not supported on {osk}."
    )


def uninstall_autostart() -> AutostartResult:
    osk = _os_key()
    if osk == "darwin":
        return _uninstall_mac()
    if osk == "win32":
        return _uninstall_windows()
    if osk == "linux":
        return _uninstall_linux()
    return AutostartResult(
        "error", osk, error=f"Autostart not supported on {osk}."
    )


def autostart_status() -> AutostartStatus:
    osk = _os_key()
    if osk == "darwin":
        return _status_mac()
    if osk == "win32":
        return _status_windows()
    if osk == "linux":
        return _status_linux()
    return AutostartStatus(False, osk, note=f"Unsupported OS: {osk}")


# ── macOS (LaunchAgent) ──────────────────────────────────────────────────


def _launchagents_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def _mac_plist_path() -> Path:
    return _launchagents_dir() / f"{SERVICE_LABEL}.plist"


def _render_mac_plist(command: list[str], log_dir: Path) -> str:
    args_xml = "\n".join(f"        <string>{_xml_escape(a)}</string>" for a in command)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir / 'connector.out.log'}</string>
    <key>StandardErrorPath</key>
    <string>{log_dir / 'connector.err.log'}</string>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"""


def _install_mac(command: list[str]) -> AutostartResult:
    plist = _mac_plist_path()
    plist.parent.mkdir(parents=True, exist_ok=True)
    log_dir = Path.home() / ".cullis" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    content = _render_mac_plist(command, log_dir)
    if plist.exists() and plist.read_text() == content:
        return AutostartResult(
            "already_configured", "darwin", service_path=plist,
        )

    try:
        plist.write_text(content)
    except OSError as exc:
        return AutostartResult(
            "error", "darwin", service_path=plist, error=str(exc),
        )

    # Re-bootstrap so the change takes effect immediately (bootout is a
    # no-op if the service isn't loaded yet).
    uid = os.getuid()
    subprocess.run(
        ["launchctl", "bootout", f"gui/{uid}/{SERVICE_LABEL}"],
        capture_output=True,  # swallow "not loaded" error
    )
    boot = subprocess.run(
        ["launchctl", "bootstrap", f"gui/{uid}", str(plist)],
        capture_output=True, text=True,
    )
    if boot.returncode != 0:
        # The file is still in place, so autostart will work next login
        # even if bootstrap failed right now. Surface the stderr for
        # debugging but treat it as a soft failure.
        return AutostartResult(
            "installed", "darwin", service_path=plist,
            note=(
                "Plist written; will run at next login. "
                f"launchctl bootstrap said: {boot.stderr.strip() or boot.stdout.strip()}"
            ),
        )
    return AutostartResult("installed", "darwin", service_path=plist)


def _uninstall_mac() -> AutostartResult:
    plist = _mac_plist_path()
    if not plist.exists():
        return AutostartResult("missing", "darwin", service_path=plist)
    uid = os.getuid()
    subprocess.run(
        ["launchctl", "bootout", f"gui/{uid}/{SERVICE_LABEL}"],
        capture_output=True,
    )
    try:
        plist.unlink()
    except OSError as exc:
        return AutostartResult(
            "error", "darwin", service_path=plist, error=str(exc),
        )
    return AutostartResult("uninstalled", "darwin", service_path=plist)


def _status_mac() -> AutostartStatus:
    plist = _mac_plist_path()
    if not plist.exists():
        return AutostartStatus(False, "darwin", service_path=plist)
    return AutostartStatus(True, "darwin", service_path=plist)


# ── Windows (Scheduled Task) ─────────────────────────────────────────────


def _install_windows(command: list[str]) -> AutostartResult:
    if shutil.which("schtasks") is None:
        return AutostartResult(
            "error", "win32",
            error="schtasks.exe not found — Windows 10+ ships with it.",
        )

    # schtasks wants the executable in /TR with arguments embedded. A
    # single quoted string does the trick; schtasks is picky about quotes
    # so wrap individual args that contain spaces.
    tr = " ".join(_win_quote(a) for a in command)

    # Delete any pre-existing task so re-installs always win — /f
    # suppresses the confirmation prompt. Silent on first install.
    subprocess.run(
        ["schtasks", "/delete", "/tn", WIN_TASK_NAME, "/f"],
        capture_output=True,
    )

    create = subprocess.run(
        [
            "schtasks", "/create",
            "/tn", WIN_TASK_NAME,
            "/tr", tr,
            "/sc", "onlogon",
            "/rl", "limited",
            "/f",
        ],
        capture_output=True, text=True,
    )
    if create.returncode != 0:
        return AutostartResult(
            "error", "win32",
            error=(create.stderr or create.stdout or "schtasks failed").strip(),
        )
    return AutostartResult(
        "installed", "win32",
        note=f"Scheduled Task registered as '{WIN_TASK_NAME}'",
    )


def _uninstall_windows() -> AutostartResult:
    if shutil.which("schtasks") is None:
        return AutostartResult(
            "error", "win32", error="schtasks.exe not found.",
        )
    result = subprocess.run(
        ["schtasks", "/delete", "/tn", WIN_TASK_NAME, "/f"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        # Most common failure: task was never installed. Treat as missing.
        out = (result.stderr or result.stdout).lower()
        if "cannot find" in out or "does not exist" in out:
            return AutostartResult("missing", "win32")
        return AutostartResult(
            "error", "win32", error=result.stderr.strip() or result.stdout.strip(),
        )
    return AutostartResult("uninstalled", "win32")


def _status_windows() -> AutostartStatus:
    if shutil.which("schtasks") is None:
        return AutostartStatus(False, "win32", note="schtasks.exe not found")
    result = subprocess.run(
        ["schtasks", "/query", "/tn", WIN_TASK_NAME],
        capture_output=True, text=True,
    )
    return AutostartStatus(result.returncode == 0, "win32")


# ── Linux (systemd --user) ───────────────────────────────────────────────


def _systemd_user_dir() -> Path:
    return Path.home() / ".config" / "systemd" / "user"


def _linux_unit_path() -> Path:
    return _systemd_user_dir() / LINUX_UNIT_NAME


def _render_linux_unit(command: list[str]) -> str:
    # Escape spaces in individual argv entries for ExecStart. systemd
    # respects double-quoted words and backslash-escaped spaces; we pick
    # the backslash route so log output matches the original argv.
    exec_start = " ".join(a.replace(" ", r"\ ") for a in command)
    # ``RestartPreventExitStatus=78`` keeps a port-busy or other
    # configuration error (the CLI exits 78 = EX_CONFIG, see
    # ``cullis_connector._port_check``) from turning into a crash-loop
    # — dogfood 2026-04-29 saw ~350 fail/h before this guard landed.
    return textwrap.dedent(
        f"""
        [Unit]
        Description=Cullis Connector — local onboarding + MCP bridge
        After=network-online.target graphical-session.target
        Wants=network-online.target

        [Service]
        Type=simple
        ExecStart={exec_start}
        Restart=on-failure
        RestartSec=3s
        RestartPreventExitStatus=78
        StandardOutput=append:%h/.cullis/logs/connector.out.log
        StandardError=append:%h/.cullis/logs/connector.err.log

        [Install]
        WantedBy=default.target
        """
    ).lstrip()


def _install_linux(command: list[str]) -> AutostartResult:
    if shutil.which("systemctl") is None:
        return AutostartResult(
            "error", "linux",
            error="systemctl not found — autostart requires systemd.",
        )

    unit = _linux_unit_path()
    unit.parent.mkdir(parents=True, exist_ok=True)
    (Path.home() / ".cullis" / "logs").mkdir(parents=True, exist_ok=True)

    content = _render_linux_unit(command)
    if unit.exists() and unit.read_text() == content:
        return AutostartResult(
            "already_configured", "linux", service_path=unit,
        )
    try:
        unit.write_text(content)
    except OSError as exc:
        return AutostartResult(
            "error", "linux", service_path=unit, error=str(exc),
        )

    reload_ = subprocess.run(
        ["systemctl", "--user", "daemon-reload"],
        capture_output=True, text=True,
    )
    enable = subprocess.run(
        ["systemctl", "--user", "enable", "--now", LINUX_UNIT_NAME],
        capture_output=True, text=True,
    )
    if enable.returncode != 0:
        return AutostartResult(
            "installed", "linux", service_path=unit,
            note=(
                "Unit file written; will run at next login. "
                f"systemctl enable said: {enable.stderr.strip() or enable.stdout.strip()}"
            ),
        )
    _ = reload_  # keep reference so the lint pass doesn't complain
    return AutostartResult("installed", "linux", service_path=unit)


def _uninstall_linux() -> AutostartResult:
    unit = _linux_unit_path()
    if not unit.exists():
        return AutostartResult("missing", "linux", service_path=unit)
    if shutil.which("systemctl") is not None:
        subprocess.run(
            ["systemctl", "--user", "disable", "--now", LINUX_UNIT_NAME],
            capture_output=True,
        )
    try:
        unit.unlink()
    except OSError as exc:
        return AutostartResult(
            "error", "linux", service_path=unit, error=str(exc),
        )
    return AutostartResult("uninstalled", "linux", service_path=unit)


def _status_linux() -> AutostartStatus:
    unit = _linux_unit_path()
    if not unit.exists():
        return AutostartStatus(False, "linux", service_path=unit)
    return AutostartStatus(True, "linux", service_path=unit)


# ── Helpers ──────────────────────────────────────────────────────────────


def _os_key() -> str:
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p.startswith("win"):
        return "win32"
    if p == "darwin":
        return "darwin"
    return p  # Return the raw platform — caller will error on unknown.


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _win_quote(arg: str) -> str:
    """Escape a single argument for ``schtasks /TR``. Simple rule: wrap in
    escaped double quotes if the arg has a space, otherwise leave raw."""
    if " " in arg or '"' in arg:
        return '\\"' + arg.replace('"', '\\"') + '\\"'
    return arg


def recommend_command() -> list[str]:
    """Return the command we'd suggest the caller register: the currently
    installed ``cullis-connector`` binary running the dashboard in
    headless mode (no auto-open browser).

    Resolution order:
      1. PyInstaller single-file bundle → register ``sys.executable``
         directly (absolute path of the packaged binary). This matters
         on Windows where the install dir isn't on PATH.
      2. ``cullis-connector`` on PATH → register that.
      3. Dev checkout → fall back to ``python -m cullis_connector``.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable, "dashboard", "--no-open-browser"]
    binary = shutil.which("cullis-connector")
    if binary is not None:
        return [binary, "dashboard", "--no-open-browser"]
    return [sys.executable, "-m", "cullis_connector", "dashboard", "--no-open-browser"]
