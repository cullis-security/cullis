"""Regression guard for the CLI dispatcher.

`_ensure_subcommand` and the argparse subparsers are two registries
that must stay in sync: anything added to `_build_parser`'s subparser
list MUST also live in `_KNOWN_SUBCOMMANDS`, and any shared flag
added to `_add_shared_args` MUST live in `_SHARED_VALUE_FLAGS` or
`_SHARED_STORE_FLAGS`.

M3.1 forgot to register `desktop` and M3.3a forgot `--profile`; both
showed up as `cullis-connector: error: unrecognized arguments: …`
on the VM after a clean install. These tests pin the two registries
against the parser so the next subcommand/flag can't drift.
"""
from __future__ import annotations

import pytest

from cullis_connector.cli import (
    _KNOWN_SUBCOMMANDS,
    _SHARED_STORE_FLAGS,
    _SHARED_VALUE_FLAGS,
    _build_parser,
    _ensure_subcommand,
)


# ── Subparser ↔ _KNOWN_SUBCOMMANDS ───────────────────────────────────


def _parser_subcommands() -> set[str]:
    """Return the subcommand names argparse actually knows about."""
    parser = _build_parser()
    # The top-level parser has exactly one _SubParsersAction holding
    # every registered subcommand.
    for action in parser._actions:
        if hasattr(action, "choices") and action.choices:
            return set(action.choices)
    raise AssertionError("no subparsers action found")


def test_known_subcommands_matches_parser():
    """The hardcoded set must cover every subcommand the parser
    exposes — any new subcommand has to be added here too, or
    `_ensure_subcommand` silently prepends `serve` and argparse
    then surfaces the new command as `unrecognized arguments`."""
    assert _KNOWN_SUBCOMMANDS == _parser_subcommands()


@pytest.mark.parametrize("cmd", ["serve", "dashboard", "desktop"])
def test_known_subcommand_is_passed_through(cmd):
    """A bare subcommand must round-trip through _ensure_subcommand
    unchanged (no silent `serve` prefix injection)."""
    assert _ensure_subcommand([cmd]) == [cmd]


def test_unknown_first_token_gets_serve_prefix():
    """A root-level flag (no subcommand) still defaults to `serve`
    — this is the carve-out the docstring documents."""
    assert _ensure_subcommand(["--config-dir", "/tmp/x"]) == [
        "serve",
        "--config-dir",
        "/tmp/x",
    ]


# ── Shared flag registry ↔ _add_shared_args ──────────────────────────


def _parser_shared_flags() -> tuple[set[str], set[str]]:
    """Walk the 'serve' subparser and collect the flag strings it
    declares. Returns ``(value_flags, store_flags)`` — value_flags take
    an argument, store_flags are boolean switches."""
    parser = _build_parser()
    for action in parser._actions:
        if hasattr(action, "choices") and action.choices:
            serve = action.choices["serve"]
            break
    else:
        raise AssertionError("no serve subparser")

    value_flags: set[str] = set()
    store_flags: set[str] = set()
    for sub_action in serve._actions:
        for opt in sub_action.option_strings:
            if not opt.startswith("--"):
                continue
            if opt in ("--help",):
                continue
            if sub_action.nargs == 0 or sub_action.const is not None:
                store_flags.add(opt)
            else:
                value_flags.add(opt)
    return value_flags, store_flags


def test_shared_value_flags_registry_is_complete():
    """Every --foo VALUE flag on the serve subparser must appear in
    _SHARED_VALUE_FLAGS; otherwise pre-subcommand use of that flag
    (common in IDE mcp.json configs) leaks into `remainder` and
    argparse rejects the command."""
    value_flags, _ = _parser_shared_flags()
    missing = value_flags - _SHARED_VALUE_FLAGS
    assert missing == set(), (
        f"these flags take a value but aren't in _SHARED_VALUE_FLAGS: "
        f"{missing}. Add them or pre-subcommand harvesting breaks."
    )


def test_shared_store_flags_registry_is_complete():
    _, store_flags = _parser_shared_flags()
    missing = store_flags - _SHARED_STORE_FLAGS
    assert missing == set(), (
        f"these boolean flags aren't in _SHARED_STORE_FLAGS: {missing}"
    )


# ── End-to-end harvesting cases that used to be broken ───────────────


def test_profile_flag_before_subcommand_gets_moved_after():
    """MCP configs sometimes list args as
    `[--profile, north, --site-url, X, serve]`. _ensure_subcommand
    must hoist the flags past the subcommand so the subparser sees
    them. Before the fix `--profile` fell into `remainder` and
    argparse said `unrecognized arguments: --profile north`."""
    out = _ensure_subcommand(
        ["--profile", "north", "--site-url", "http://x", "serve"]
    )
    assert out[0] == "serve"
    assert "--profile" in out
    assert "north" in out
    # Values stick next to their flag.
    assert out.index("north") == out.index("--profile") + 1


def test_desktop_with_flags_round_trips():
    argv = ["desktop", "--profile", "south", "--port", "7788"]
    assert _ensure_subcommand(argv) == argv


# ── install-mcp --ide choices + alias resolution ─────────────────────


def test_install_mcp_ide_choices_include_every_known_client():
    """Finding #6 (dogfood 2026-04-29): the registry already knew
    about ``claude-code-cli``, ``zed``, and ``windsurf`` but the CLI
    flag accepted only the original three. Pin the choices against
    the registry so any new descriptor lands in argparse too."""
    from cullis_connector.cli import _build_parser
    from cullis_connector.ide_config import KNOWN_IDES

    parser = _build_parser()
    install_mcp = None
    for action in parser._actions:
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            install_mcp = action.choices.get("install-mcp")
            break
    assert install_mcp is not None

    ide_action = next(
        a for a in install_mcp._actions if a.dest == "ides"
    )
    choices = set(ide_action.choices)
    # Every registry id must be a valid choice.
    assert set(KNOWN_IDES.keys()) <= choices
    # And the friendly alias is also accepted.
    assert "claude-code" in choices


def test_install_mcp_alias_resolves_to_canonical_id():
    """``claude-code`` is an operator-friendly alias that the
    install-mcp dispatch must normalise to the registry's canonical
    ``claude-code-cli`` before lookup."""
    from cullis_connector.cli import _resolve_ide_id
    assert _resolve_ide_id("claude-code") == "claude-code-cli"
    # Anything not in the alias map passes through unchanged.
    assert _resolve_ide_id("cursor") == "cursor"
    assert _resolve_ide_id("zed") == "zed"
