"""Structured logging setup for cullis-connector."""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any


class _JsonFormatter(logging.Formatter):
    """Emit one JSON object per line on stderr.

    stdout is reserved for the MCP stdio protocol; everything human/machine
    readable from the connector itself must go to stderr.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for k, v in record.__dict__.items():
            if k in {"args", "msg", "name", "levelname", "levelno", "pathname",
                     "filename", "module", "exc_info", "exc_text", "stack_info",
                     "lineno", "funcName", "created", "msecs", "relativeCreated",
                     "thread", "threadName", "processName", "process",
                     "taskName", "asctime", "message"}:
                continue
            payload[k] = v
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: str = "info") -> None:
    """Configure the root cullis_connector logger.

    Always writes to stderr (stdout is owned by the MCP stdio transport).
    """
    numeric = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger("cullis_connector")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the cullis_connector namespace."""
    if not name.startswith("cullis_connector"):
        name = f"cullis_connector.{name}"
    return logging.getLogger(name)
