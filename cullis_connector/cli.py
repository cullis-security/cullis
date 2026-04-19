"""Command-line entry point for cullis-connector.

Three top-level modes:

* ``cullis-connector serve`` (default when no subcommand is given) — run
  the MCP stdio server. Requires a valid identity on disk; fails with a
  clear hint if none is present yet.

* ``cullis-connector enroll`` — one-shot device-code enrollment: generate
  keypair, submit to the Site, print the admin URL, poll until approved,
  persist cert + metadata under ``~/.cullis/identity/``.

* ``cullis-connector install-mcp`` — merge the Cullis MCP entry into
  Claude Desktop / Cursor / Cline config files. Idempotent, backed-up.
  The dashboard calls this same code when the user clicks "Configure";
  the CLI is the scripted path for headless / CI installs.

* ``cullis-connector dashboard`` — local web UI on http://127.0.0.1:7777
  that wraps enrollment in a three-screen wizard and can auto-configure
  Claude Desktop / Cursor / Cline. Intended as the default onboarding
  path for end users who shouldn't need the CLI.

Shared flags (``--site-url``, ``--config-dir``, ``--no-verify-tls``,
``--log-level``) must be placed **after** the subcommand name — git-style.
If you omit the subcommand we inject ``serve`` for you so
``cullis-connector --config-dir ~/foo`` keeps working, but once a
subcommand is present argparse parses its flags from that subparser
only.
"""
from __future__ import annotations

import argparse
import sys
from typing import Sequence

from cullis_connector import __version__
from cullis_connector._logging import get_logger, setup_logging
from cullis_connector.config import ConnectorConfig, load_config
from cullis_connector.identity import IdentityNotFound, has_identity, load_identity

_log = get_logger("cli")


# ── Argument parser ──────────────────────────────────────────────────────


def _add_shared_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--site-url",
        dest="site_url",
        help="Base URL of the Cullis Site (e.g. https://cullis.acme.local:9443). "
             "Overrides CULLIS_SITE_URL env var and config.yaml.",
    )
    parser.add_argument(
        "--config-dir",
        dest="config_dir",
        help="Directory holding config.yaml and identity/. Defaults to ~/.cullis/. "
             "Use distinct dirs for multi-org setups.",
    )
    parser.add_argument(
        "--no-verify-tls",
        dest="verify_tls",
        action="store_false",
        default=None,
        help="Disable TLS verification (development only — never use in production).",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        choices=["debug", "info", "warning", "error"],
        help="Set log verbosity. Logs always go to stderr.",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cullis-connector",
        description=(
            "Cullis Connector — MCP server bridging local MCP clients to "
            "the Cullis federated agent trust network."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"cullis-connector {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser(
        "serve",
        help="Run the MCP stdio server (default when no subcommand given).",
    )
    _add_shared_args(serve)

    enroll = subparsers.add_parser(
        "enroll",
        help="Run the device-code enrollment flow once and exit.",
    )
    _add_shared_args(enroll)
    enroll.add_argument(
        "--requester-name",
        required=True,
        help="Your full name as the admin will see it in the pending list.",
    )
    enroll.add_argument(
        "--requester-email",
        required=True,
        help="Your email — admin uses it to verify you are who you claim.",
    )
    enroll.add_argument(
        "--reason",
        default=None,
        help="Short note for the admin explaining why you need access.",
    )
    enroll.add_argument(
        "--device-info",
        default=None,
        help="Free-form host/OS string recorded in the enrollment audit.",
    )

    install_mcp = subparsers.add_parser(
        "install-mcp",
        help="Write the Cullis MCP entry into Claude Desktop / Cursor / Cline.",
    )
    _add_shared_args(install_mcp)
    install_mcp.add_argument(
        "--ide",
        dest="ides",
        action="append",
        default=None,
        choices=["claude-desktop", "cursor", "cline"],
        help="Target a specific IDE (repeatable). Omit to auto-configure "
             "every detected IDE on this machine.",
    )
    install_mcp.add_argument(
        "--list",
        dest="ide_list_only",
        action="store_true",
        help="Do not write anything — just print detection status per IDE.",
    )
    install_mcp.add_argument(
        "--uninstall",
        dest="ide_uninstall",
        action="store_true",
        help="Remove the Cullis entry from each IDE's MCP config.",
    )

    install_autostart = subparsers.add_parser(
        "install-autostart",
        help="Start the connector dashboard at login (LaunchAgent / Task / systemd).",
    )
    _add_shared_args(install_autostart)
    install_autostart.add_argument(
        "--uninstall",
        dest="autostart_uninstall",
        action="store_true",
        help="Remove the autostart entry instead of installing it.",
    )
    install_autostart.add_argument(
        "--status",
        dest="autostart_status_only",
        action="store_true",
        help="Report current autostart status without changing anything.",
    )

    dashboard = subparsers.add_parser(
        "dashboard",
        help="Run the local onboarding web UI (http://127.0.0.1:7777).",
    )
    _add_shared_args(dashboard)
    dashboard.add_argument(
        "--host",
        dest="web_host",
        default="127.0.0.1",
        help="Bind address for the dashboard. Defaults to 127.0.0.1 — do "
             "not expose to the network without a reason.",
    )
    dashboard.add_argument(
        "--port",
        dest="web_port",
        type=int,
        default=7777,
        help="Dashboard port (default 7777). Increment if something else "
             "already holds the port.",
    )
    dashboard.add_argument(
        "--no-open-browser",
        dest="open_browser",
        action="store_false",
        default=True,
        help="Do not auto-open a browser tab on startup.",
    )

    return parser


_KNOWN_SUBCOMMANDS = frozenset({
    "serve",
    "enroll",
    "install-mcp",
    "install-autostart",
    "dashboard",
})

# Shared flags are parsed by the subparser that owns the chosen command.
# When the caller wrote them *before* the subcommand (the pre-fix layout
# some users already have persisted in MCP configs), we relocate them so
# argparse finds them on the right subparser.
_SHARED_VALUE_FLAGS = frozenset({"--site-url", "--config-dir", "--log-level"})
_SHARED_STORE_FLAGS = frozenset({"--no-verify-tls"})


def _ensure_subcommand(argv: list[str]) -> list[str]:
    """Normalize argv so shared flags land on the correct subparser.

    Shared flags (``--site-url`` etc.) live only on the subparsers so
    the subcommand-level ``dest`` doesn't get silently clobbered back
    to None by a duplicated root-level one. Two UX carve-outs keep the
    older call conventions working:

    * No subcommand at all → prepend ``serve`` (covers ``cullis-connector
      --config-dir ~/foo``).
    * Shared flag appears *before* the subcommand → move it after it
      (covers MCP configs that list args as
      ``[--site-url, X, --config-dir, Y, serve]``).

    ``--version`` / ``--help`` on the root exit before dispatch, so
    we leave argv alone when we see them.
    """
    for tok in argv:
        if tok in ("--version", "-V", "-h", "--help"):
            return list(argv)

    sub_idx = next(
        (i for i, tok in enumerate(argv) if tok in _KNOWN_SUBCOMMANDS),
        None,
    )
    if sub_idx is None:
        return ["serve", *argv]
    if sub_idx == 0:
        return list(argv)

    # Harvest shared flags (and their values) from the run of tokens
    # before the subcommand. Anything unrecognised is left in place so
    # argparse still raises the usual "unrecognized arguments" error
    # — we don't want to silently drop a typo.
    extracted: list[str] = []
    remainder: list[str] = []
    i = 0
    before = argv[:sub_idx]
    while i < len(before):
        tok = before[i]
        base = tok.split("=", 1)[0]
        if base in _SHARED_VALUE_FLAGS:
            if "=" in tok:
                extracted.append(tok)
                i += 1
            elif i + 1 < len(before):
                extracted.extend([tok, before[i + 1]])
                i += 2
            else:
                remainder.append(tok)
                i += 1
        elif tok in _SHARED_STORE_FLAGS:
            extracted.append(tok)
            i += 1
        else:
            remainder.append(tok)
            i += 1

    after = argv[sub_idx:]
    return [*remainder, after[0], *extracted, *after[1:]]


# ── Commands ─────────────────────────────────────────────────────────────


def _cmd_serve(cfg: ConnectorConfig) -> int:
    if not has_identity(cfg.config_dir):
        _log.error(
            "No identity found at %s — run `cullis-connector enroll "
            "--requester-name ... --requester-email ...` first.",
            cfg.config_dir,
        )
        return 2

    try:
        identity = load_identity(cfg.config_dir)
    except IdentityNotFound as exc:
        _log.error("Identity load failed: %s", exc)
        return 2

    # Import late so the bare `enroll` command has no MCP dependency.
    from cullis_connector.server import build_server
    from cullis_connector.state import get_state

    state = get_state()
    state.agent_id = identity.metadata.agent_id
    state.extra["identity"] = identity

    # The enrollment flow already pinned the Site URL in metadata.json —
    # adopt it if the operator did not pass --site-url / CULLIS_SITE_URL.
    # Without this, diagnostic tools like hello_site report "not configured"
    # even though the identity we just loaded was issued against that site.
    if not cfg.site_url and identity.metadata.site_url:
        cfg.site_url = identity.metadata.site_url
        _log.info(
            "adopted site_url from identity metadata: %s", cfg.site_url,
        )

    # Build the CullisClient from the on-disk enrollment bundle.
    #
    # The Phase 1 ``connect`` tool went away with enrollment but the
    # wiring was never completed: every tool reached for a client that
    # nobody constructed. We build it here and load the signing key so
    # ``send_oneshot`` (API-key + DPoP + inner/outer signatures, no
    # broker JWT) works out of the box.
    #
    # We deliberately *do not* call ``login_via_proxy()`` eagerly:
    # it asks the Mastio to sign a client_assertion with the agent's
    # private key, but device-code enrollment leaves that key on the
    # user's machine, not on the Mastio — so the call 404s with
    # "agent credentials not available on proxy". Session-based tools
    # mint the token lazily via ``ensure_broker_token`` and surface a
    # clear error if it can't be obtained; one-shot tools don't need
    # a token at all.
    try:
        from cullis_sdk import CullisClient

        client = CullisClient.from_connector(cfg.config_dir)
        key_path = cfg.config_dir / "identity" / "agent.key"
        if key_path.exists():
            client._signing_key_pem = key_path.read_text()
        state.client = client
    except Exception as exc:
        _log.error(
            "Failed to initialize CullisClient from %s: %s. "
            "Tools requiring a connected client will not work.",
            cfg.config_dir, exc,
        )

    _log.info(
        "serving as %s (cert subject %s)",
        identity.metadata.agent_id or "unknown",
        identity.cert.subject.rfc4514_string(),
    )

    server = build_server(cfg)
    server.run(transport="stdio")
    return 0


def _cmd_enroll(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    if not cfg.site_url:
        _log.error(
            "enroll requires --site-url (or CULLIS_SITE_URL env / config.yaml)"
        )
        return 2

    if has_identity(cfg.config_dir):
        _log.error(
            "Identity already present at %s — refusing to overwrite. Remove "
            "the existing files manually if you really want to re-enroll.",
            cfg.config_dir / "identity",
        )
        return 2

    # Import here to keep `--version` + arg parsing fast.
    from cullis_connector.enrollment import (
        EnrollmentFailed,
        RequesterInfo,
        enroll,
    )

    try:
        enroll(
            site_url=cfg.site_url,
            config_dir=cfg.config_dir,
            requester=RequesterInfo(
                name=args.requester_name,
                email=args.requester_email,
                reason=args.reason,
                device_info=args.device_info,
            ),
            verify_tls=cfg.verify_tls,
            request_timeout_s=cfg.request_timeout_s,
        )
    except EnrollmentFailed as exc:
        _log.error("Enrollment failed: %s", exc)
        return 1
    return 0


def _cmd_install_mcp(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    from cullis_connector.ide_config import (
        KNOWN_IDES,
        IDEStatus,
        detect_all,
        detect_ide_status,
        install_mcp,
        uninstall_mcp,
    )

    target_ids = args.ides or list(KNOWN_IDES.keys())

    if args.ide_list_only:
        print(f"{'IDE':<22} {'STATUS':<14} PATH")
        print("-" * 80)
        for r in detect_all():
            if r.ide_id not in target_ids:
                continue
            path = str(r.config_path) if r.config_path else "—"
            print(f"{r.display_name:<22} {r.status.value:<14} {path}")
            if r.note:
                print(f"{'':<22} {'':<14} ↳ {r.note}")
        return 0

    backup_dir = cfg.config_dir / "backups"
    any_error = False

    for ide_id in target_ids:
        detection = detect_ide_status(ide_id)

        # Skip IDEs that aren't on this machine unless the user asked
        # explicitly — then we still try, so mistakes produce clear errors.
        if detection.status == IDEStatus.MISSING and not args.ides:
            print(f"[skip] {detection.display_name}: {detection.note or 'not detected'}")
            continue

        if args.ide_uninstall:
            result = uninstall_mcp(ide_id, backup_dir=backup_dir)
            verb = "uninstall"
        else:
            result = install_mcp(ide_id, backup_dir=backup_dir)
            verb = "install"

        name = KNOWN_IDES[ide_id].display_name
        if result.status == "installed":
            action = "removed" if args.ide_uninstall else "configured"
            print(f"[ok]   {name}: {action} at {result.config_path}")
            if result.backup_path:
                print(f"       ↳ backup: {result.backup_path}")
        elif result.status == "already_configured":
            print(f"[skip] {name}: already {'' if args.ide_uninstall else 'configured '}in place")
        else:
            any_error = True
            print(f"[err]  {name}: {result.error}")

        _log.debug("%s result for %s: %s", verb, ide_id, result)

    return 1 if any_error else 0


def _cmd_install_autostart(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    from cullis_connector.autostart import (
        autostart_status,
        install_autostart,
        recommend_command,
        uninstall_autostart,
    )

    if args.autostart_status_only:
        status = autostart_status()
        state = "enabled" if status.installed else "disabled"
        print(f"{state:<10} platform={status.platform}  path={status.service_path or '—'}")
        if status.note:
            print(f"           ↳ {status.note}")
        return 0

    if args.autostart_uninstall:
        result = uninstall_autostart()
        if result.status == "uninstalled":
            print(f"[ok]   removed {result.service_path}")
            return 0
        if result.status == "missing":
            print("[skip] nothing to remove — autostart was not registered.")
            return 0
        print(f"[err]  {result.error or 'unknown failure'}")
        return 1

    command = recommend_command()
    result = install_autostart(command)
    if result.status == "installed":
        print(f"[ok]   autostart registered for {result.platform}")
        print(f"       ↳ command: {' '.join(command)}")
        if result.service_path:
            print(f"       ↳ service: {result.service_path}")
        if result.note:
            print(f"       ↳ note: {result.note}")
        return 0
    if result.status == "already_configured":
        print(f"[skip] already registered at {result.service_path}")
        return 0
    print(f"[err]  {result.error or 'unknown failure'}")
    return 1


def _cmd_dashboard(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        _log.error(
            "dashboard requires extra deps — install with "
            "`pip install 'cullis-connector[dashboard]'` (adds fastapi, "
            "uvicorn, jinja2)."
        )
        return 2

    # Import late so the dashboard deps stay optional for serve/enroll.
    from cullis_connector.web import build_app

    app = build_app(cfg)

    host = getattr(args, "web_host", "127.0.0.1")
    port = int(getattr(args, "web_port", 7777))
    url = f"http://{host}:{port}"

    if getattr(args, "open_browser", True):
        import threading
        import webbrowser

        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    _log.info("dashboard listening on %s — open it in a browser to enroll", url)
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=cfg.log_level if cfg.log_level != "debug" else "info",
        access_log=False,
    )
    return 0


# ── Entry point ──────────────────────────────────────────────────────────


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for both ``python -m cullis_connector`` and the
    installed ``cullis-connector`` console script."""
    parser = _build_parser()
    raw = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(_ensure_subcommand(raw))
    cfg = load_config(vars(args))
    setup_logging(cfg.log_level)

    command = args.command or "serve"
    _log.info(
        "connector command=%s version=%s site_url=%s config_dir=%s",
        command,
        __version__,
        cfg.site_url or "(unset)",
        cfg.config_dir,
    )

    if command == "enroll":
        return _cmd_enroll(cfg, args)
    if command == "install-mcp":
        return _cmd_install_mcp(cfg, args)
    if command == "install-autostart":
        return _cmd_install_autostart(cfg, args)
    if command == "dashboard":
        return _cmd_dashboard(cfg, args)
    return _cmd_serve(cfg)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
