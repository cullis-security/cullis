"""cullis-proxy CLI — operational commands for the proxy.

Entry point: `python -m mcp_proxy.cli <subcommand>`.

Subcommands:
  rebuild-cache              Drop + re-fetch the federation cache.
  reset-password             Overwrite the admin bcrypt hash.
  migrate-org-ca-to-vault    Copy Org CA from proxy_config DB into Vault
                             (ADR-031 follow-up to PR #684).

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

    migrate = sub.add_parser(
        "migrate-org-ca-to-vault",
        help="One-shot copy of the Org CA keypair from proxy_config DB "
        "to Vault KV v2 (ADR-031). Reads org_ca_key + org_ca_cert via "
        "the local source, writes them via the in-tree VaultKMSProvider, "
        "verifies by read-back, optionally clears the DB rows.",
    )
    migrate.add_argument(
        "--yes", action="store_true",
        help="Skip the interactive confirmation prompt.",
    )
    migrate.add_argument(
        "--dry-run", action="store_true",
        help="Validate end-to-end (DB has the keys, Vault is reachable, "
        "target path either empty or --force) without writing to Vault "
        "or touching the DB.",
    )
    migrate.add_argument(
        "--clear-db", action="store_true",
        help="After a successful write + read-back verification, NULL "
        "out org_ca_key and org_ca_cert in proxy_config. Recommended "
        "as the final operator step; omit when running a staged copy.",
    )
    migrate.add_argument(
        "--force", action="store_true",
        help="Overwrite the Vault path even if it already holds an "
        "Org CA. Without this flag the CLI refuses to write when Vault "
        "already has key_pem + cert_pem to avoid clobbering a prior "
        "migration.",
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


async def _cmd_migrate_org_ca_to_vault(args: argparse.Namespace) -> int:
    """Copy the Org CA from proxy_config DB to Vault KV v2 (ADR-031).

    Uses the in-tree LocalKMSProvider as the read source and a fresh
    VaultKMSProvider as the write target. We instantiate both
    explicitly rather than going through the factory because the
    operator typically runs this CLI while the Mastio is still on
    ``kms_backend=local`` (otherwise the running Mastio would already
    read from Vault and there is nothing to migrate). The factory's
    cached provider is bypassed entirely.
    """
    from mcp_proxy.db import log_audit
    from mcp_proxy.kms.local import LocalKMSProvider
    from mcp_proxy.kms.vault import VaultKMSProvider

    settings = get_settings()

    # Vault settings must be present — VaultKMSProvider() raises
    # ValueError otherwise, but a clearer up-front message helps.
    missing = [
        name for name, value in (
            ("MCP_PROXY_VAULT_ADDR", settings.vault_addr),
            ("MCP_PROXY_VAULT_TOKEN", settings.vault_token),
            ("MCP_PROXY_VAULT_ORG_CA_PATH", settings.vault_org_ca_path),
        ) if not value
    ]
    if missing:
        sys.stderr.write(
            "Vault settings missing: " + ", ".join(missing) + ". "
            "Set them in proxy.env or via the dashboard /proxy/vault "
            "page before running this migration.\n"
        )
        return 1

    await init_db(settings.database_url)
    try:
        src = LocalKMSProvider()
        dst = VaultKMSProvider(
            vault_addr=settings.vault_addr,
            vault_token=settings.vault_token,
            org_ca_path=settings.vault_org_ca_path,
            verify_tls=settings.vault_verify_tls,
            ca_cert_path=settings.vault_ca_cert_path,
        )

        source = await src.load_org_ca()
        if source is None:
            sys.stderr.write(
                "proxy_config has no Org CA to migrate (org_ca_key / "
                "org_ca_cert are empty). This Mastio either never "
                "generated a CA, or was already migrated.\n"
            )
            return 1
        key_pem, cert_pem = source

        existing = await dst.load_org_ca()
        if existing is not None and not args.force:
            sys.stderr.write(
                f"Vault path {settings.vault_org_ca_path} already holds "
                "an Org CA (key_pem + cert_pem present). Refusing to "
                "overwrite without --force. If you intentionally want "
                "to replace it (e.g. after a rotation), re-run with "
                "--force.\n"
            )
            return 1

        if args.dry_run:
            sys.stdout.write(
                f"DRY RUN: would write Org CA "
                f"(key_pem={len(key_pem)} bytes, "
                f"cert_pem={len(cert_pem)} bytes) to "
                f"{settings.vault_addr}/v1/{settings.vault_org_ca_path}\n"
            )
            if existing is not None:
                sys.stdout.write(
                    "DRY RUN: target path is non-empty; --force is set, "
                    "so the real run would overwrite.\n"
                )
            if args.clear_db:
                sys.stdout.write(
                    "DRY RUN: --clear-db is set; the real run would "
                    "clear proxy_config.org_ca_key and org_ca_cert "
                    "after read-back verification.\n"
                )
            return 0

        if not args.yes:
            sys.stderr.write(
                f"This will write the Org CA private key + cert to "
                f"{settings.vault_addr}/v1/{settings.vault_org_ca_path}"
            )
            if existing is not None:
                sys.stderr.write(" (OVERWRITING existing value, --force)")
            if args.clear_db:
                sys.stderr.write(
                    " and then clear proxy_config.org_ca_key + "
                    "org_ca_cert"
                )
            sys.stderr.write(".\nContinue? [y/N]: ")
            sys.stderr.flush()
            ans = sys.stdin.readline().strip().lower()
            if ans not in ("y", "yes"):
                sys.stderr.write("aborted\n")
                return 1

        await dst.store_org_ca(key_pem, cert_pem)

        # Read-back verification — the whole point of this CLI is to
        # be safe to follow with --clear-db. We must be certain the
        # write landed and that what came back matches what we sent.
        verify = await dst.load_org_ca()
        if verify is None:
            await log_audit(
                agent_id="admin",
                action="kms.org_ca_migrate_to_vault",
                status="failure",
                detail="read-back returned None after store",
            )
            sys.stderr.write(
                "ABORT: read-back from Vault returned None after the "
                "write. The DB still holds the original Org CA — "
                "nothing was cleared. Inspect the Vault path manually "
                "before retrying.\n"
            )
            return 2
        verify_key, verify_cert = verify
        if verify_key != key_pem or verify_cert != cert_pem:
            await log_audit(
                agent_id="admin",
                action="kms.org_ca_migrate_to_vault",
                status="failure",
                detail="read-back mismatch",
            )
            sys.stderr.write(
                "ABORT: read-back from Vault does not match what was "
                "written. The DB still holds the original Org CA — "
                "nothing was cleared. Inspect the Vault path manually "
                "before retrying.\n"
            )
            return 2

        cleared = False
        if args.clear_db:
            # Set to empty string rather than DELETE the row, so the
            # LocalKMSProvider treats it as unseeded (its truthiness
            # check is ``if key_pem and cert_pem``) without disturbing
            # the proxy_config schema. Operators who later flip back
            # to local mode are forced to re-seed explicitly.
            from mcp_proxy.db import set_config
            await set_config("org_ca_key", "")
            await set_config("org_ca_cert", "")
            cleared = True

        await log_audit(
            agent_id="admin",
            action="kms.org_ca_migrate_to_vault",
            status="success",
            detail=(
                f"target={settings.vault_org_ca_path} "
                f"overwrote={existing is not None} "
                f"cleared_db={cleared}"
            ),
        )

        sys.stdout.write(
            f"Org CA migrated to Vault at {settings.vault_org_ca_path}. "
            f"Read-back verified. "
        )
        if cleared:
            sys.stdout.write(
                "proxy_config.org_ca_key + org_ca_cert have been "
                "cleared. "
            )
        sys.stdout.write(
            "Restart the Mastio with MCP_PROXY_KMS_BACKEND=vault to "
            "switch the live key source.\n"
        )
        return 0
    finally:
        await dispose_db()


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
    if args.command == "migrate-org-ca-to-vault":
        return asyncio.run(_cmd_migrate_org_ca_to_vault(args))

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
