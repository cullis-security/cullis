"""``cullis-connector doctor`` — scan IDE MCP configs for stale Cullis entries.

Closes Finding #8 from the 2026-04-29 dogfood: an MCP entry pointed
at a profile (``dotfiles``) and a Mastio (``localhost:9100``) that
hadn't existed for months. Nothing surfaced the breakage until the
operator typed ``claude mcp list`` by hand and noticed.

This module walks the same ``KNOWN_IDES`` registry that
``install-mcp`` uses, finds entries that look like a Cullis serve
invocation, and validates two cheap, deterministic things:

1. **The binary in ``command`` is reachable.** ``cullis-connector`` was
   commonly installed in a venv that has since been blown away. We
   check via ``shutil.which`` plus an absolute-path ``Path.exists``
   for the literal command string the entry persisted.
2. **The profile dir referenced by ``--profile X`` (or ``--config-dir
   Y``) still exists.** This is the case from the dogfood: profile
   went away, MCP entry didn't.

We deliberately do NOT probe the Site at this stage — that pulls in
``httpx``, requires the network, and produces transient noise on a
flaky link. Operators who want a live Site check can run
``cullis-connector hello-site`` against the profile separately.

The CLI prints one line per entry with a status tag; doctor exits 0
on a clean scan and 1 if anything is broken so it composes with
``set -e`` in install scripts and CI.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from cullis_connector.config import DEFAULT_CONFIG_DIR
from cullis_connector.ide_config import (
    KNOWN_IDES,
    IDEDescriptor,
    InstallerKind,
    resolve_config_path,
)


@dataclass
class DoctorEntry:
    """One row in the doctor report."""

    ide_id: str
    ide_display: str
    server_name: str  # the JSON key inside ``mcpServers`` (usually "cullis")
    command: str  # the executable string the IDE will invoke
    args: list[str]
    config_path: Path | None
    status: str  # "ok", "stale_binary", "stale_profile", "unreadable", "no_config"
    detail: str  # human-readable explanation


_CONNECTOR_HINT = "cullis-connector"


def _looks_like_cullis(server_name: str, command: str, args: list[str]) -> bool:
    """Heuristic: does this MCP server entry call our connector?

    We match on the binary name AND the entry server name so that an
    operator who renamed our entry to e.g. ``cullis-prod`` still gets
    audited, and so a third-party server that happens to invoke an
    unrelated ``cullis-connector`` (vanishingly unlikely but not zero)
    doesn't get flagged.
    """
    if _CONNECTOR_HINT in command:
        return True
    # If the server is named ``cullis`` or ``cullis-*`` and it
    # explicitly carries our ``serve`` subcommand, treat it as ours.
    if server_name == "cullis" or server_name.startswith("cullis-"):
        if "serve" in args:
            return True
    return False


def _extract_profile_dir(args: list[str]) -> Path | None:
    """Resolve the on-disk dir the MCP entry will use as its profile.

    Mirrors ``ConnectorConfig`` resolution but without importing the
    YAML/env loader — we only need the cases the install path
    persists: ``--profile X`` (uses ``DEFAULT_CONFIG_DIR/profiles/X``)
    or ``--config-dir Y`` (uses ``Y`` verbatim). Returns ``None`` if
    neither is set; absence of both means the entry runs against the
    legacy flat layout, which is its own warning class.
    """
    config_dir = _flag_value(args, "--config-dir")
    if config_dir:
        return Path(config_dir).expanduser()
    profile = _flag_value(args, "--profile")
    if profile:
        return DEFAULT_CONFIG_DIR / "profiles" / profile
    return None


def _flag_value(args: list[str], flag: str) -> str | None:
    """``--flag X`` → ``X``; ``--flag=X`` → ``X``; absent → None."""
    for i, a in enumerate(args):
        if a == flag:
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return None


def _binary_exists(command: str) -> bool:
    """True iff the IDE will be able to launch this command on PATH /
    at the persisted absolute path."""
    if not command:
        return False
    if "/" in command or "\\" in command:
        return Path(command).expanduser().exists()
    return shutil.which(command) is not None


def _scan_file_ide(ide: IDEDescriptor) -> Iterator[DoctorEntry]:
    path = resolve_config_path(ide.id)
    if path is None:
        return
    if not path.exists():
        # Most operators won't have every supported IDE installed.
        # Silence is the right answer — the ``--list`` flag of
        # install-mcp already exists for "show me all of them".
        return
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        yield DoctorEntry(
            ide_id=ide.id,
            ide_display=ide.display_name,
            server_name="?",
            command="",
            args=[],
            config_path=path,
            status="unreadable",
            detail=f"cannot parse {path.name}: {exc}",
        )
        return

    servers = data.get(ide.servers_key, {}) if isinstance(data, dict) else {}
    if not isinstance(servers, dict):
        return

    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        command = str(entry.get("command", ""))
        args_raw = entry.get("args", [])
        args = [str(a) for a in args_raw] if isinstance(args_raw, list) else []
        if not _looks_like_cullis(name, command, args):
            continue

        if not _binary_exists(command):
            yield DoctorEntry(
                ide_id=ide.id,
                ide_display=ide.display_name,
                server_name=name,
                command=command,
                args=args,
                config_path=path,
                status="stale_binary",
                detail=(
                    f"command ``{command}`` is not on PATH and is not an "
                    "existing absolute file — IDE will fail to launch the "
                    "MCP server. Re-install with ``cullis-connector "
                    "install-mcp`` or remove the stale entry."
                ),
            )
            continue

        profile_dir = _extract_profile_dir(args)
        if profile_dir is not None and not profile_dir.exists():
            yield DoctorEntry(
                ide_id=ide.id,
                ide_display=ide.display_name,
                server_name=name,
                command=command,
                args=args,
                config_path=path,
                status="stale_profile",
                detail=(
                    f"profile dir ``{profile_dir}`` no longer exists. "
                    "The MCP entry was likely written when this profile "
                    "was active and not cleaned up when the profile was "
                    "removed."
                ),
            )
            continue

        yield DoctorEntry(
            ide_id=ide.id,
            ide_display=ide.display_name,
            server_name=name,
            command=command,
            args=args,
            config_path=path,
            status="ok",
            detail=(
                f"profile=``{profile_dir.name}`` (resolved at {profile_dir})"
                if profile_dir is not None
                else "running against the legacy flat layout (no --profile / --config-dir)"
            ),
        )


def _scan_command_ide(ide: IDEDescriptor) -> Iterator[DoctorEntry]:
    """COMMAND-kind IDEs (Claude Code CLI today) keep their MCP config
    inside the binary's own state. We can't deterministically read it
    without invoking the CLI, which would couple ``doctor`` to a
    specific Claude Code version and add a flaky out-of-process call.

    Yield a single advisory entry pointing the operator at the right
    command for that client, instead of pretending to validate.
    """
    if not _binary_exists(ide.detect_binary or ""):
        # Binary missing → nothing to advise about, skip silently.
        return
    yield DoctorEntry(
        ide_id=ide.id,
        ide_display=ide.display_name,
        server_name="?",
        command=ide.detect_binary or "",
        args=[],
        config_path=None,
        status="advise",
        detail=(
            f"{ide.display_name} stores MCP entries in its own state. "
            "Run ``claude mcp list`` to see registered servers and "
            "``claude mcp remove cullis`` to drop a stale one."
        ),
    )


def scan(ides: Iterable[str] | None = None) -> list[DoctorEntry]:
    """Walk the registry and return all Cullis-shaped entries with status.

    ``ides=None`` scans every supported client; pass an explicit list
    to limit the scan (e.g. ``[\"cursor\"]`` for a focused report).
    """
    targets = list(ides) if ides else list(KNOWN_IDES.keys())
    out: list[DoctorEntry] = []
    for ide_id in targets:
        ide = KNOWN_IDES.get(ide_id)
        if ide is None:
            continue
        if ide.kind is InstallerKind.COMMAND:
            out.extend(_scan_command_ide(ide))
        else:
            out.extend(_scan_file_ide(ide))
    return out


def has_problems(entries: Iterable[DoctorEntry]) -> bool:
    """``True`` iff anything in the report needs operator attention.

    ``ok`` and ``advise`` are clean (advise is informational); the
    other statuses (``stale_binary``, ``stale_profile``, ``unreadable``)
    are problems doctor's exit code reflects.
    """
    return any(e.status in {"stale_binary", "stale_profile", "unreadable"} for e in entries)
