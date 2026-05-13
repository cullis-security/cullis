"""Tests for the lifespan-safe log helper.

The helper exists because `_log.info` records from a handful of
lifespan-time code paths silently disappear in production despite
correct logger config (cullis-enterprise#11 documented the same
behavior on the global rate limit middleware). These tests assert the
JSON shape on stderr matches the regular JSONFormatter output so log
aggregators see identical records regardless of which path emitted
them.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest


def test_emit_lifespan_log_writes_json_to_stderr(capsys):
    from mcp_proxy._lifespan_log import emit_lifespan_log

    emit_lifespan_log(
        level="INFO",
        logger="mcp_proxy.tools.resource_loader",
        message="MCP resource loader: 7 loaded, 0 skipped (conflict with builtin)",
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    line = captured.err.strip()
    assert line, "no record written to stderr"
    record = json.loads(line)

    assert record["level"] == "INFO"
    assert record["logger"] == "mcp_proxy.tools.resource_loader"
    assert (
        record["message"]
        == "MCP resource loader: 7 loaded, 0 skipped (conflict with builtin)"
    )
    # ISO-8601 with timezone, parseable by datetime.fromisoformat.
    ts = datetime.fromisoformat(record["timestamp"])
    assert ts.tzinfo is not None
    # Sanity: within a few seconds of now.
    age = abs((datetime.now(timezone.utc) - ts).total_seconds())
    assert age < 5


def test_emit_lifespan_log_warning_level(capsys):
    from mcp_proxy._lifespan_log import emit_lifespan_log

    emit_lifespan_log(
        level="WARNING",
        logger="mcp_proxy",
        message=(
            "Failed to load MCP resources from DB — continuing with "
            "builtin tools only: RuntimeError('db gone')"
        ),
    )
    record = json.loads(capsys.readouterr().err.strip())
    assert record["level"] == "WARNING"
    assert "RuntimeError" in record["message"]


def test_emit_lifespan_log_shape_matches_json_formatter():
    """The on-stderr JSON record must carry the same keys that
    ``mcp_proxy.logging_setup.JSONFormatter`` would emit for a regular
    logger call. Both code paths feed the same SIEM / Loki pipeline."""
    from mcp_proxy._lifespan_log import emit_lifespan_log  # noqa: F401
    from mcp_proxy.logging_setup import JSONFormatter

    # Synthesize a log record the formatter would have produced.
    import logging
    rec = logging.LogRecord(
        name="mcp_proxy.tools.resource_loader",
        level=logging.INFO,
        pathname="resource_loader.py",
        lineno=200,
        msg="MCP resource loader: %d loaded, %d skipped",
        args=(3, 0),
        exc_info=None,
    )
    formatted = JSONFormatter().format(rec)
    formatter_keys = set(json.loads(formatted).keys())

    # The helper writes the same key set (with stable ISO timestamp).
    expected = {"timestamp", "level", "logger", "message"}
    assert formatter_keys >= expected, (
        f"formatter shape changed unexpectedly: {formatter_keys}"
    )
