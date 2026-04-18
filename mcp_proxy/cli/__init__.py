"""cullis-proxy CLI — operational commands for the proxy.

Entry point: `python -m mcp_proxy.cli <subcommand>`.

Subcommands:
  rebuild-cache    Drop and re-fetch the federation cache from the broker.
  reset-password   Overwrite the admin bcrypt hash and re-enable local sign-in.

Each subcommand is a thin async wrapper around helpers that live next
to the runtime code (e.g. mcp_proxy.sync.cache_admin) so the CLI itself
stays trivial and the operational logic stays unit-testable.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys

from mcp_proxy.config import get_settings
from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.sync.cache_admin import drop_federation_cache

_log = logging.getLogger("mcp_proxy.cli")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cullis-proxy",
        description="Operational CLI for the Cullis MCP Proxy.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rebuild = sub.add_parser(
        "rebuild-cache",
        help="Drop the federation cache so the subscriber re-fetches "
        "every event on next start. Safe to run on a live proxy: the "
        "subscriber will replay from seq=0 and converge in seconds.",
    )
    rebuild.add_argument(
        "--yes", action="store_true",
        help="Skip the interactive confirmation prompt.",
    )

    reset = sub.add_parser(
        "reset-password",
        help="Recovery path: overwrite the admin bcrypt hash and "
        "re-enable the local password sign-in toggle. Use when the "
        "admin password is lost OR the SSO-only toggle was flipped "
        "off and the IdP is unreachable.",
    )
    reset.add_argument(
        "--password",
        help="New password (skip the interactive prompt). Length must "
        "meet the proxy's MIN_PASSWORD_LENGTH. If omitted the CLI "
        "prompts twice on stderr.",
    )

    return parser


async def _cmd_rebuild_cache(args: argparse.Namespace) -> int:
    if not args.yes:
        # Reading from stdin keeps the prompt out of the test path —
        # tests always pass --yes. Operators see a clear warning.
        sys.stderr.write(
            "This will DROP all rows in cached_federated_agents, "
            "cached_policies, cached_bindings, and reset the federation "
            "cursor for this proxy. The subscriber will refetch from "
            "the broker on next connection.\n"
            "Continue? [y/N]: "
        )
        sys.stderr.flush()
        ans = sys.stdin.readline().strip().lower()
        if ans not in ("y", "yes"):
            sys.stderr.write("aborted\n")
            return 1

    settings = get_settings()
    await init_db(settings.database_url)
    try:
        counts = await drop_federation_cache()
    finally:
        await dispose_db()

    sys.stdout.write(
        f"federation cache dropped: "
        f"agents={counts['agents']}, "
        f"policies={counts['policies']}, "
        f"bindings={counts['bindings']}, "
        f"cursor_rows={counts['cursor']}\n"
    )
    return 0


async def _cmd_reset_password(args: argparse.Namespace) -> int:
    from mcp_proxy.dashboard.session import (
        MIN_PASSWORD_LENGTH,
        set_admin_password,
        set_local_password_login_enabled,
    )
    from mcp_proxy.db import log_audit

    password = args.password
    if not password:
        # Read from a TTY, never from stdin pipe — the user asked for an
        # interactive reset explicitly when they didn't pass --password.
        password = getpass.getpass("New admin password: ")
        confirm = getpass.getpass("Confirm: ")
        if password != confirm:
            sys.stderr.write("passwords do not match — aborted\n")
            return 1

    if len(password) < MIN_PASSWORD_LENGTH:
        sys.stderr.write(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters\n"
        )
        return 1

    settings = get_settings()
    await init_db(settings.database_url)
    try:
        await set_admin_password(password)
        # The only reason someone runs this CLI is to get back in. If the
        # toggle was disabled (that's precisely the lockout scenario),
        # re-enable it so the next login actually works — otherwise the
        # reset is silently useless.
        await set_local_password_login_enabled(True)
        await log_audit(
            agent_id="admin",
            action="auth.password_reset_cli",
            status="success",
            detail="admin password reset + local password sign-in re-enabled",
        )
    finally:
        await dispose_db()

    sys.stdout.write(
        "admin password reset; local password sign-in re-enabled. "
        "Sign in at /proxy/login.\n"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "rebuild-cache":
        return asyncio.run(_cmd_rebuild_cache(args))
    if args.command == "reset-password":
        return asyncio.run(_cmd_reset_password(args))

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
