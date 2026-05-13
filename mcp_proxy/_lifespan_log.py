"""Lifespan-safe structured log emission.

Audit 2026-05-14 (PR #687 follow-up). Several lifespan call-sites emit
``_log.info`` records that never reach ``docker compose logs`` even
though the logger config is correct on paper: handler is the JSON
StreamHandler from ``logging_setup.py``, level is INFO, propagation is
off but the handler is on the ``mcp_proxy`` parent. Empirically
identical to the silently-muted dispatch-time records the global rate
limit middleware documents in its module header (cullis-enterprise#11).

Affected paths so far:

* ``mcp_proxy.main.lifespan`` — ``MCP resource registry populated`` and
  ``Failed to load MCP resources``.
* ``mcp_proxy.tools.resource_loader.load_resources_into_registry`` —
  ``MCP resource loader: %d loaded, %d skipped``.
* ``mcp_proxy.tools.registry.register_definition`` — per-resource
  ``Registered tool ...`` lines.

All three end up invisible despite emitting through the same logger
hierarchy that publishes ``Org CA loaded`` and ``local sweeper started``
seconds earlier and later. The pattern matches the middleware
workaround: uvicorn appears to repoint the handler stream at some
point during lifespan and a window of records is dropped.

Until the upstream root-cause is fixed, lifespan callers that need
guaranteed visibility — operator diagnostics, audit traces — bypass
the logger and write a single-line JSON record straight to ``sys.stderr``.
The shape matches ``logging_setup.JSONFormatter`` so SIEM / Loki / Grafana
parsers treat it identically to a regular log line.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone


def emit_lifespan_log(*, level: str, logger: str, message: str) -> None:
    """Write a JSON log record directly to stderr.

    Use ONLY from lifespan-time code paths where the standard logger has
    been observed to silently drop records. Builtins under
    ``mcp_proxy.*`` are the only intended callers; third-party plugins
    have no business calling this — they get the same logger hierarchy
    everyone else uses.
    """
    record = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "logger": logger,
        "message": message,
    }, default=str)
    print(record, file=sys.stderr, flush=True)
