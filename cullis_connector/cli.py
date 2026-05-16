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
        help="Directory holding config.yaml and identity/. Overrides "
             "--profile entirely; only use this when you need to point "
             "the connector at an arbitrary path.",
    )
    parser.add_argument(
        "--profile",
        dest="profile",
        help="Name of the profile to activate (default: 'default'). Each "
             "profile has its own enrollment under "
             "~/.cullis/profiles/<name>/ — use distinct profiles to "
             "host several identities on one machine (e.g. 'north' and "
             "'south').",
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
        help="Write the Cullis MCP entry into a supported MCP client.",
    )
    _add_shared_args(install_mcp)
    # Source the choices from the IDE registry so adding a new client
    # (claude-code, zed, windsurf — landed before this PR but not
    # exposed as ``--ide`` values) doesn't drift the CLI surface.
    # ``claude-code`` is accepted as an operator-friendly alias for
    # ``claude-code-cli``; the canonical id is the value the descriptor
    # carries, but ``claude-code-cli`` reads like an internal slug to
    # someone typing the flag.
    from cullis_connector.ide_config import KNOWN_IDES as _KNOWN_IDES
    _IDE_CHOICES = sorted(set(_KNOWN_IDES.keys()) | {"claude-code"})
    install_mcp.add_argument(
        "--ide",
        dest="ides",
        action="append",
        default=None,
        choices=_IDE_CHOICES,
        help="Target a specific MCP client (repeatable). Omit to "
             "auto-configure every detected client on this machine. "
             "``claude-code`` is an alias for ``claude-code-cli``.",
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

    desktop = subparsers.add_parser(
        "desktop",
        help="Run the Connector as a native desktop shell (tray icon + "
             "system webview wrapping the dashboard — no terminal).",
    )
    _add_shared_args(desktop)
    desktop.add_argument(
        "--host",
        dest="web_host",
        default="127.0.0.1",
        help="Bind address for the embedded dashboard (default 127.0.0.1).",
    )
    desktop.add_argument(
        "--port",
        dest="web_port",
        type=int,
        default=7777,
        help="Dashboard port (default 7777).",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="Audit IDE MCP configs for stale Cullis entries.",
    )
    _add_shared_args(doctor)
    doctor.add_argument(
        "--ide",
        dest="ides",
        action="append",
        default=None,
        help="Limit the scan to these clients (repeatable). Omit to "
             "scan every supported MCP client.",
    )

    # show-token: print the loopback Ambassador Bearer token so the
    # operator can paste it into a third-party OpenAI-compatible client
    # (LibreChat, Cherry Studio, AnythingLLM, OpenWebUI, ...). The token
    # already lives at ``<config_dir>/local.token`` mode 0600 but is
    # invisible to anyone who does not know the path — this surfaces it
    # in one command. ``--quiet`` suppresses the security warning on
    # stderr so a script can ``$(cullis-connector show-token --quiet)``
    # and grab just the token. ADR-027 culk_ tokens cover the remote
    # /v1/* path; this is the local loopback equivalent.
    show_token = subparsers.add_parser(
        "show-token",
        help="Print the local Ambassador Bearer token (treat as a password).",
    )
    _add_shared_args(show_token)
    show_token.add_argument(
        "--quiet", "-q",
        dest="quiet",
        action="store_true",
        help="Print only the token (no security warning on stderr). "
             "Use in scripts: TOKEN=$(cullis-connector show-token --quiet)",
    )

    # ADR-032 Layer 2 — Connector OIDC login. Opens a local OIDC flow,
    # binds the resulting user identity to the enrolled Connector via
    # the Mastio's /v1/principals/connector-login endpoint, and persists
    # the session to ``<config_dir>/oidc_session.json``.
    login = subparsers.add_parser(
        "login",
        help="Bind a user identity (via OIDC SSO) on top of the enrolled "
             "Connector agent.",
    )
    _add_shared_args(login)
    login.add_argument(
        "--idp",
        dest="idp_issuer",
        help="Override the OIDC issuer URL (otherwise read from the "
             "Mastio's proxy_config / a local config.yaml override).",
    )
    login.add_argument(
        "--client-id",
        dest="oidc_client_id",
        help="OIDC client_id for this Connector. Required when --idp is "
             "passed and no Mastio-side config is reachable.",
    )
    login.add_argument(
        "--client-secret",
        dest="oidc_client_secret",
        default=None,
        help="Optional OIDC client_secret. PKCE alone is enough for "
             "public-client IdPs; pass this only when the IdP rejects "
             "anonymous token exchanges.",
    )
    login.add_argument(
        "--callback-port",
        dest="callback_port",
        type=int,
        default=None,
        help="Bind a specific loopback port for the OIDC redirect_uri. "
             "Default: ask the OS for a free port (avoids the 7777 "
             "dashboard collision).",
    )
    login.add_argument(
        "--no-open-browser",
        dest="open_browser",
        action="store_false",
        default=True,
        help="Print the authorization URL instead of opening it in a "
             "browser (headless / SSH scenarios).",
    )

    logout = subparsers.add_parser(
        "logout",
        help="Revoke the bound user identity on the Mastio and remove "
             "the local session row.",
    )
    _add_shared_args(logout)

    whoami = subparsers.add_parser(
        "whoami",
        help="Report which user identity (if any) the Connector is "
             "currently bound to.",
    )
    _add_shared_args(whoami)

    return parser


_KNOWN_SUBCOMMANDS = frozenset({
    "serve",
    "enroll",
    "install-mcp",
    "install-autostart",
    "dashboard",
    "desktop",
    "doctor",
    "show-token",
    "login",
    "logout",
    "whoami",
})

# Shared flags are parsed by the subparser that owns the chosen command.
# When the caller wrote them *before* the subcommand (the pre-fix layout
# some users already have persisted in MCP configs), we relocate them so
# argparse finds them on the right subparser.
_SHARED_VALUE_FLAGS = frozenset({
    "--site-url",
    "--config-dir",
    "--log-level",
    "--profile",
})
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
    # ``from_connector`` loads ``identity/agent.key`` + ``identity/agent.crt``
    # eagerly so send_oneshot (API-key + DPoP + inner/outer signatures)
    # and session tools (broker JWT via challenge-response login) both
    # work out of the box.
    #
    # Tech-debt #2 closed: we now call ``login_via_proxy_with_local_key``
    # eagerly. The Mastio issues a short-lived nonce, the Connector
    # signs the client_assertion locally (the key never leaves this
    # machine), and the Mastio verifies + counter-signs. Previously
    # this step was skipped because the legacy ``login_via_proxy`` path
    # asks the Mastio to sign on our behalf — which 404s when the key
    # lives on-device. Failure here is non-fatal: one-shot tools work
    # without a broker JWT, and ``_require_client`` retries lazily.
    try:
        from cullis_sdk import CullisClient

        # Honour ``--no-verify-tls`` (cfg.verify_tls=False) end-to-end.
        # ``from_connector`` derives a default from the site_url scheme;
        # without an explicit override the dev/lab path with a
        # self-signed Org CA can't login_via_proxy_with_local_key.
        client = CullisClient.from_connector(
            cfg.config_dir, verify_tls=cfg.verify_tls,
        )
        # Attach the loaded identity bundle so downstream helpers
        # (canonical_recipient, etc.) can derive the sender's org from
        # the cert subject without reaching into process-global state.
        client.identity = identity
        state.client = client

        try:
            client.login_via_proxy_with_local_key()
            _log.info("broker JWT obtained via challenge-response login")
        except Exception as login_exc:  # noqa: BLE001
            _log.warning(
                "eager login_via_proxy_with_local_key failed: %s. "
                "Session tools will retry lazily; send_oneshot works "
                "regardless.",
                login_exc,
            )
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
            verify_tls=cfg.verify_arg,
            request_timeout_s=cfg.request_timeout_s,
        )
    except EnrollmentFailed as exc:
        _log.error("Enrollment failed: %s", exc)
        return 1
    return 0


_IDE_ALIASES = {"claude-code": "claude-code-cli"}


def _resolve_ide_id(value: str) -> str:
    """Map operator-friendly aliases to the canonical registry id."""
    return _IDE_ALIASES.get(value, value)


def _cmd_install_mcp(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    from cullis_connector.ide_config import (
        KNOWN_IDES,
        IDEStatus,
        detect_all,
        detect_ide_status,
        install_mcp,
        uninstall_mcp,
    )

    target_ids = (
        [_resolve_ide_id(i) for i in args.ides]
        if args.ides else list(KNOWN_IDES.keys())
    )

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

    # Propagate the shared flags the operator passed on the install-mcp
    # invocation into the persisted MCP entry. Without this the saved
    # ``args`` would be just ``["serve"]`` — every IDE/MCP client would
    # then bind to the ``default`` profile against an unset site_url and
    # connect to nothing useful (memory: feedback_install_mcp_no_profile).
    serve_args: list[str] = ["serve"]
    if getattr(args, "profile", None):
        serve_args += ["--profile", args.profile]
    if getattr(args, "config_dir", None):
        serve_args += ["--config-dir", args.config_dir]
    if getattr(args, "site_url", None):
        serve_args += ["--site-url", args.site_url]
    # ``args.verify_tls`` is True/False/None. None = not specified
    # (inherit), False = ``--no-verify-tls`` was set on the command
    # line, True = ``--verify-tls`` (no current flag for this — kept
    # for symmetry).
    if getattr(args, "verify_tls", None) is False:
        serve_args += ["--no-verify-tls"]

    backup_dir = cfg.config_dir / "backups"
    any_error = False
    installed_names: list[str] = []

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
            result = install_mcp(ide_id, backup_dir=backup_dir, args=serve_args)
            verb = "install"

        name = KNOWN_IDES[ide_id].display_name
        if result.status == "installed":
            action = "removed" if args.ide_uninstall else "configured"
            print(f"[ok]   {name}: {action} at {result.config_path}")
            if result.backup_path:
                print(f"       ↳ backup: {result.backup_path}")
            if not args.ide_uninstall:
                installed_names.append(name)
        elif result.status == "already_configured":
            print(f"[skip] {name}: already {'' if args.ide_uninstall else 'configured '}in place")
        else:
            any_error = True
            print(f"[err]  {name}: {result.error}")

        _log.debug("%s result for %s: %s", verb, ide_id, result)

    # Finding #7 (dogfood 2026-04-29): clients load their MCP config
    # at session startup, so an already-running Claude Code / Cursor
    # / Cline session won't see the new server until it restarts.
    # Without this hint operators would invoke the tools, get a
    # "tool not found" error, and only then realise.
    if installed_names and not args.ide_uninstall:
        joined = ", ".join(installed_names)
        print(
            f"\n→ Restart {joined} to load the Cullis MCP server. "
            "Existing sessions will not see the new tools until a fresh "
            "session is opened."
        )

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
    from cullis_connector._port_check import (
        EXIT_PORT_UNAVAILABLE,
        check_port_available,
        detect_running_dashboard,
    )

    host = getattr(args, "web_host", "127.0.0.1")
    port = int(getattr(args, "web_port", 7777))
    url = f"http://{host}:{port}"

    # Pre-flight: a port-busy here used to bubble up as ``errno 98 address
    # already in use`` from inside uvicorn's loop. With ``Restart=on-failure``
    # in the systemd autostart unit, that meant ~350 fail/h crash-loop
    # (dogfood Finding #1, 2026-04-29). Failing fast with EX_CONFIG (78)
    # lets the unit's ``RestartPreventExitStatus=78`` keep the loop
    # quiet and gives the operator an actionable message.
    if not check_port_available(host, port):
        kind = detect_running_dashboard(host, port)
        if kind == "cullis_connector":
            _log.error(
                "Another Cullis Connector dashboard is already serving "
                "%s. Open it in your browser, or pass ``--port <N>`` to "
                "run a second instance on a different port (e.g. 7778).",
                url,
            )
        elif kind == "unknown":
            _log.error(
                "Port %d on %s is already in use by another process "
                "(not a Connector dashboard). Stop it, or pass "
                "``--port <N>`` to choose a different port.",
                port, host,
            )
        else:
            _log.error(
                "Cannot bind %s — the port is unavailable but no "
                "process responded to a probe. Pass ``--port <N>`` "
                "or check ``ss -ltnp | grep :%d``.",
                url, port,
            )
        return EXIT_PORT_UNAVAILABLE

    app = build_app(cfg)

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


def _cmd_desktop(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    from cullis_connector.desktop_app import run_desktop_app

    host = getattr(args, "web_host", "127.0.0.1")
    port = int(getattr(args, "web_port", 7777))
    return run_desktop_app(cfg, host=host, port=port)


def _cmd_login(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    """ADR-032 Layer 2 — bind a user identity via OIDC."""
    if not has_identity(cfg.config_dir):
        _log.error(
            "Cannot login as a user: this Connector is not enrolled yet. "
            "Run `cullis-connector enroll --requester-name ... "
            "--requester-email ...` first."
        )
        return 2

    try:
        identity = load_identity(cfg.config_dir)
    except IdentityNotFound as exc:
        _log.error("Identity load failed: %s", exc)
        return 2

    site_url = cfg.site_url or identity.metadata.site_url
    if not site_url:
        _log.error(
            "Cannot login without a Site URL (pass --site-url, set "
            "CULLIS_SITE_URL, or re-enroll so metadata.site_url is filled)."
        )
        return 2

    issuer_url = getattr(args, "idp_issuer", None)
    client_id = getattr(args, "oidc_client_id", None)
    if not issuer_url or not client_id:
        _log.error(
            "OIDC login requires --idp <issuer-url> and --client-id <client>. "
            "Mastio-side defaults will be wired in a follow-up — pass them "
            "explicitly for now."
        )
        return 2

    from cullis_connector.login import LoginError, perform_login

    try:
        session = perform_login(
            config_dir=cfg.config_dir,
            identity=identity,
            site_url=site_url,
            verify_tls=cfg.verify_tls,
            issuer_url=issuer_url,
            client_id=client_id,
            client_secret=getattr(args, "oidc_client_secret", None),
            callback_port=getattr(args, "callback_port", None),
            open_browser=getattr(args, "open_browser", True),
        )
    except LoginError as exc:
        _log.error("login failed: %s", exc)
        return 1

    print(  # noqa: T201
        f"Logged in as {session.display_name or session.sso_subject} "
        f"@ {session.idp_issuer}"
    )
    print(  # noqa: T201
        f"Session expires at {session.expires_at.isoformat(timespec='seconds')}"
    )
    return 0


def _cmd_logout(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    """ADR-032 Layer 2 — revoke the bound user identity."""
    from cullis_connector.login import perform_logout
    from cullis_connector.identity.oidc_session import load_session

    try:
        identity = load_identity(cfg.config_dir) if has_identity(cfg.config_dir) else None
    except IdentityNotFound:
        identity = None
    site_url = cfg.site_url or (identity.metadata.site_url if identity else "")

    existing = load_session(cfg.config_dir)
    if existing is None:
        print("No active session to log out of.")  # noqa: T201
        return 0

    if not site_url:
        # Still allow a local-only logout so the user can clear stale
        # state even if their Site URL is misconfigured.
        from cullis_connector.identity.oidc_session import delete_session
        delete_session(cfg.config_dir)
        print(  # noqa: T201
            "Local session cleared (no Site URL available — server-side "
            "revoke skipped)."
        )
        return 0

    removed = perform_logout(
        config_dir=cfg.config_dir,
        site_url=site_url,
        verify_tls=cfg.verify_tls,
    )
    if removed:
        print(  # noqa: T201
            f"Logged out from {existing.display_name or existing.sso_subject}"
        )
    else:
        print("No session row removed.")  # noqa: T201
    return 0


def _cmd_whoami(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    """ADR-032 Layer 2 — print the bound user identity status."""
    from cullis_connector.login import describe_session

    print(describe_session(cfg.config_dir))  # noqa: T201
    return 0


def _cmd_show_token(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    """Print the loopback Ambassador Bearer token.

    Generates the token on first call (same behaviour as the Ambassador's
    first startup), so an operator who installed the connector but never
    ran ``dashboard``/``desktop`` still gets a token instead of an empty
    file error. The token goes to stdout one line, no trailing extra
    whitespace, so ``$(cullis-connector show-token --quiet)`` works in
    a script. Security guidance goes to stderr so it does NOT pollute
    stdout capture.
    """
    from cullis_connector.ambassador.auth import (
        LOCAL_TOKEN_FILENAME,
        ensure_local_token,
    )

    token = ensure_local_token(cfg.config_dir)
    token_path = cfg.config_dir / LOCAL_TOKEN_FILENAME

    if not args.quiet:
        print(
            f"# Local Ambassador Bearer token at {token_path}\n"
            "# Treat as a password. Copy into your OpenAI-compatible client's\n"
            "# Authorization: Bearer <token> setting, or paste below into the\n"
            "# API key field (LibreChat / Cherry Studio / AnythingLLM / OpenWebUI / ...).\n"
            "# The Ambassador only accepts this token from 127.0.0.1, so a leak\n"
            "# off-host is harmless until an attacker also has loopback access.",
            file=sys.stderr,
        )
    print(token)
    return 0


def _cmd_doctor(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    """Audit IDE MCP configs for stale Cullis entries (Finding #8)."""
    from cullis_connector.doctor import has_problems, scan

    ide_filter = (
        [_resolve_ide_id(i) for i in args.ides] if args.ides else None
    )
    entries = scan(ide_filter)
    if not entries:
        print("No Cullis MCP entries found in any supported client.")
        print(
            "(Run ``cullis-connector install-mcp --list`` to see which "
            "clients are detected on this machine.)"
        )
        return 0

    print(f"{'IDE':<22} {'STATUS':<14} ENTRY")
    print("-" * 80)
    for e in entries:
        print(f"{e.ide_display:<22} {e.status:<14} {e.server_name}")
        if e.config_path is not None:
            print(f"{'':<22} {'':<14} ↳ at {e.config_path}")
        print(f"{'':<22} {'':<14} ↳ {e.detail}")

    return 1 if has_problems(entries) else 0


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
    if command == "desktop":
        return _cmd_desktop(cfg, args)
    if command == "doctor":
        return _cmd_doctor(cfg, args)
    if command == "show-token":
        return _cmd_show_token(cfg, args)
    if command == "login":
        return _cmd_login(cfg, args)
    if command == "logout":
        return _cmd_logout(cfg, args)
    if command == "whoami":
        return _cmd_whoami(cfg, args)
    return _cmd_serve(cfg)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


# ── `cullis` thin CLI (agent-targeted send/inbox) ────────────────────────
#
# Roadmap session 2026-05-15 scope #4 v1. ``cullis`` is a separate
# console script that talks HTTP to the local Connector daemon
# (``http://127.0.0.1:7777``) and never touches the SDK directly. Every
# subcommand resolves to one HTTP call against an existing Ambassador
# route — no new server-side endpoints. Targets coding-CLI agents
# (Claude Code / Codex / Cursor) that want a quick ``cullis send`` /
# ``cullis inbox`` shortcut instead of curl + Bearer juggling.
#
# Out of scope for v1: ``discover`` / ``list-agents`` (need Broker
# endpoints that don't exist yet) and ``send-to-user`` (different
# Broker route shape).

# Ambassador default bind from ``cullis_connector/web.py`` —
# loopback-only, fixed port. Kept in sync there by the dashboard
# command's ``--port`` default; if the user moved the daemon they
# override with ``--connector-url``.
_DEFAULT_CONNECTOR_URL = "http://127.0.0.1:7777"


class _CullisCLIError(Exception):
    """Friendly CLI failure. Message goes to stderr, exit code 1."""


def _resolve_token_path(args: argparse.Namespace) -> "Path":
    """Pick the file holding the loopback Bearer token.

    Precedence (highest first):

    * ``--token-file`` on the CLI.
    * ``CULLIS_BEARER_TOKEN_FILE`` env var.
    * The active profile's ``config_dir / "local.token"`` (the same
      file ``cullis-connector show-token`` reads), so a user running
      ``--profile north`` picks up the matching token without touching
      the env.

    The function does NOT read the file — it just decides where to
    look. ``_get_bearer_token`` opens it and produces the friendly
    error if it's missing.
    """
    from pathlib import Path
    import os as _os

    explicit = getattr(args, "token_file", None)
    if explicit:
        return Path(explicit).expanduser()
    env_path = _os.environ.get("CULLIS_BEARER_TOKEN_FILE", "").strip()
    if env_path:
        return Path(env_path).expanduser()
    cfg = load_config({
        "profile": getattr(args, "profile", None),
        "config_dir": getattr(args, "config_dir", None),
    })
    from cullis_connector.ambassador.auth import LOCAL_TOKEN_FILENAME
    return cfg.config_dir / LOCAL_TOKEN_FILENAME


def _get_bearer_token(args: argparse.Namespace) -> str:
    """Read the loopback Bearer token from disk.

    Raises ``_CullisCLIError`` with an actionable hint if the file
    isn't there — the most likely cause is the daemon never started,
    not a permissions issue.
    """
    token_path = _resolve_token_path(args)
    if not token_path.exists():
        raise _CullisCLIError(
            f"No Cullis Connector token at {token_path}.\n"
            "Start the daemon first:\n"
            "    cullis-connector dashboard --profile <name>\n"
            "or\n"
            "    cullis-connector serve\n"
            "then re-run this command. Override the path with "
            "--token-file or $CULLIS_BEARER_TOKEN_FILE."
        )
    token = token_path.read_text(encoding="utf-8").strip()
    if not token:
        raise _CullisCLIError(
            f"Cullis Connector token at {token_path} is empty. "
            "Rotate it from the dashboard's API keys page or delete "
            "the file and restart the daemon."
        )
    return token


def _http_request(
    args: argparse.Namespace,
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
    params: dict | None = None,
) -> dict:
    """Call the local Ambassador. Returns the parsed JSON body.

    Network / 4xx / 5xx errors raise ``_CullisCLIError`` with a one-
    line summary the caller can print verbatim. The daemon answers
    JSON on every documented route; if it doesn't (eg. a reverse
    proxy injected an HTML 502 page), we surface the status + the
    first 200 bytes of the body so the user can diagnose.
    """
    import httpx

    token = _get_bearer_token(args)
    base = args.connector_url.rstrip("/")
    url = f"{base}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.request(
                method, url, headers=headers, json=json_body, params=params,
            )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise _CullisCLIError(
            f"Cannot reach Cullis Connector at {base} ({exc}). "
            "Check the daemon is running: `cullis-connector dashboard` "
            "or `cullis-connector serve`."
        ) from exc

    if resp.status_code >= 400:
        # Mastio + Ambassador both speak JSON ``{detail: ...}`` on
        # errors. Fall back to a truncated raw body for anything else.
        try:
            detail = resp.json().get("detail", resp.text[:200])
        except Exception:
            detail = resp.text[:200]
        raise _CullisCLIError(
            f"HTTP {resp.status_code} from {method} {path}: {detail}"
        )

    try:
        body = resp.json()
    except Exception as exc:
        raise _CullisCLIError(
            f"Cullis Connector returned non-JSON at {method} {path}: "
            f"{resp.text[:200]}"
        ) from exc
    return body if isinstance(body, dict) else {"data": body}


def _cullis_build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cullis",
        description=(
            "Cullis CLI — thin alias for the local Connector daemon. "
            "Wraps the loopback Ambassador's /v1/inbox + /v1/ambassador "
            "routes; the daemon must already be running."
        ),
    )
    parser.add_argument("--version", action="version", version=f"cullis {__version__}")
    parser.add_argument(
        "--connector-url",
        dest="connector_url",
        default=_DEFAULT_CONNECTOR_URL,
        help=(
            "Override the Connector daemon URL "
            f"(default: {_DEFAULT_CONNECTOR_URL})."
        ),
    )
    parser.add_argument(
        "--token-file",
        dest="token_file",
        default=None,
        help=(
            "Path to the loopback Bearer token file. Defaults to "
            "$CULLIS_BEARER_TOKEN_FILE if set, otherwise "
            "<config_dir>/local.token resolved through --profile."
        ),
    )
    parser.add_argument(
        "--profile",
        dest="profile",
        default=None,
        help=(
            "Connector profile name (default: 'default'). Maps to "
            "~/.cullis/profiles/<name>/ for token lookup. Mirrors the "
            "cullis-connector --profile flag."
        ),
    )
    parser.add_argument(
        "--config-dir",
        dest="config_dir",
        default=None,
        help=(
            "Explicit config_dir override (escape hatch — usually "
            "--profile is enough)."
        ),
    )

    sub = parser.add_subparsers(dest="command", required=True)

    send = sub.add_parser(
        "send",
        help="Send a one-shot intra-org message to another principal.",
        description=(
            "POST /v1/inbox/send via the local Connector. The Ambassador "
            "resolves the recipient through the Mastio's egress, signs + "
            "envelopes the payload, and queues the delivery."
        ),
    )
    send.add_argument(
        "--to", dest="to", required=True,
        help="Recipient principal id (e.g. orga::alice, user::mario).",
    )
    body_group = send.add_mutually_exclusive_group(required=True)
    body_group.add_argument(
        "--content", dest="content",
        help="Plain-text message body — wrapped as {\"text\": <content>}.",
    )
    body_group.add_argument(
        "--payload-json", dest="payload_json",
        help="Structured JSON object payload (e.g. '{\"intent\":\"ping\"}').",
    )
    send.add_argument(
        "--correlation-id", dest="correlation_id", default=None,
        help="Optional correlation id propagated to the recipient.",
    )
    send.add_argument(
        "--reply-to", dest="reply_to", default=None,
        help="Optional msg_id this message replies to.",
    )
    send.add_argument(
        "--ttl", dest="ttl_seconds", type=int, default=300,
        help="Server-side TTL in seconds for offline delivery (default 300).",
    )

    inbox = sub.add_parser(
        "inbox",
        help="List recent inbox messages.",
        description="GET /v1/inbox via the local Connector.",
    )
    inbox.add_argument(
        "--since", dest="since", default=None,
        help="Return only messages newer than this msg_id.",
    )
    inbox.add_argument(
        "--limit", dest="limit", type=int, default=50,
        help="Maximum messages to return (default 50).",
    )
    inbox.add_argument(
        "--format", dest="format", choices=("text", "json"), default="text",
        help="text (compact table, default) or json (raw response).",
    )

    sub.add_parser(
        "health",
        help="Check the local Connector daemon is reachable.",
        description="GET /v1/ambassador/health via the local Connector.",
    )

    return parser


def _cmd_cullis_send(args: argparse.Namespace) -> int:
    if args.payload_json is not None:
        import json as _json
        try:
            payload: dict = _json.loads(args.payload_json)
        except _json.JSONDecodeError as exc:
            raise _CullisCLIError(f"--payload-json is not valid JSON: {exc}")
        if not isinstance(payload, dict):
            raise _CullisCLIError("--payload-json must decode to a JSON object")
    else:
        payload = {"text": args.content}

    body: dict = {
        "recipient_id": args.to,
        "payload": payload,
        "ttl_seconds": int(args.ttl_seconds),
    }
    if args.correlation_id:
        body["correlation_id"] = args.correlation_id
    if args.reply_to:
        body["reply_to"] = args.reply_to

    result = _http_request(args, "POST", "/v1/inbox/send", json_body=body)
    import json as _json
    print(_json.dumps(result, indent=2, sort_keys=True))
    return 0


def _cmd_cullis_inbox(args: argparse.Namespace) -> int:
    params: dict = {"limit": int(args.limit)}
    if args.since:
        params["since"] = args.since
    result = _http_request(args, "GET", "/v1/inbox", params=params)

    if args.format == "json":
        import json as _json
        print(_json.dumps(result, indent=2, sort_keys=True))
        return 0

    # Mastio + Ambassador wrap the rows under ``messages``. Tolerate the
    # bare-list shape too in case a future Ambassador version drops the
    # wrapper.
    messages = result.get("messages")
    if messages is None and isinstance(result.get("data"), list):
        messages = result["data"]
    if messages is None:
        messages = []
    if not messages:
        print("(inbox empty)")
        return 0

    header = f"{'MSG_ID':<24}  {'SENDER':<28}  PAYLOAD"
    print(header)
    print("-" * len(header))
    for m in messages:
        msg_id = str(m.get("msg_id") or m.get("id") or "?")[:23]
        sender = str(m.get("sender_id") or m.get("sender_agent_id") or "?")[:27]
        payload = m.get("payload")
        if isinstance(payload, dict):
            preview = payload.get("text") or payload
        else:
            preview = payload
        preview_str = str(preview)
        if len(preview_str) > 60:
            preview_str = preview_str[:57] + "..."
        print(f"{msg_id:<24}  {sender:<28}  {preview_str}")
    return 0


def _cmd_cullis_health(args: argparse.Namespace) -> int:
    result = _http_request(args, "GET", "/v1/ambassador/health")
    profile = getattr(args, "profile", None) or "default"
    agent = result.get("agent_id") or "(unbound)"
    site = result.get("site_url") or "(unset)"
    print(
        f"Cullis Connector OK at {args.connector_url} "
        f"(profile={profile}, agent={agent}, site={site})"
    )
    return 0


def cullis_main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``cullis`` console script."""
    parser = _cullis_build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])

    try:
        if args.command == "send":
            return _cmd_cullis_send(args)
        if args.command == "inbox":
            return _cmd_cullis_inbox(args)
        if args.command == "health":
            return _cmd_cullis_health(args)
    except _CullisCLIError as exc:
        print(f"cullis: {exc}", file=sys.stderr)
        return 1
    # argparse with ``required=True`` on the subparsers prevents this
    # branch in practice, but keep an explicit fallback so the type
    # checker can prove the function returns an int.
    parser.print_help(sys.stderr)
    return 2
