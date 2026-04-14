"""Command-line entry point for cullis-connector."""
from __future__ import annotations

import argparse
import sys
from typing import Sequence

from cullis_connector import __version__
from cullis_connector._logging import get_logger, setup_logging
from cullis_connector.config import load_config
from cullis_connector.server import build_server

_log = get_logger("cli")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cullis-connector",
        description=(
            "Cullis Connector — MCP server bridging local MCP clients to "
            "the Cullis federated agent trust network."
        ),
    )
    parser.add_argument(
        "--site-url",
        dest="site_url",
        help="Base URL of the Cullis Site (e.g. https://cullis-site.acme.local:9443). "
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
    parser.add_argument(
        "--version",
        action="version",
        version=f"cullis-connector {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by both ``python -m cullis_connector`` and the
    installed ``cullis-connector`` console script."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    cfg = load_config(vars(args))
    setup_logging(cfg.log_level)
    _log.info(
        "starting connector",
        extra={
            "version": __version__,
            "site_url": cfg.site_url or "(unset)",
            "config_dir": str(cfg.config_dir),
        },
    )
    server = build_server(cfg)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
