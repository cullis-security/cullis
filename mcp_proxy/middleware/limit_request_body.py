"""Limit inbound request-body size (F-A-303).

A single authenticated agent on ``/v1/chat/completions`` or
``/v1/mcp`` (tools/call) can POST a body of arbitrary size. Without
an explicit cap the body is buffered into memory before pydantic
ever sees it, so the cost-of-attack (RAM + CPU + audit row noise)
is already paid by the time the schema layer rejects it.

This middleware reads the ``Content-Length`` header on every inbound
HTTP request and short-circuits with ``413 Payload Too Large`` when
the advertised size exceeds the configured ceiling. Chunked uploads
(no ``Content-Length``) are not bounded here because the streaming
ASGI receive path would require buffering to enforce a true cap;
the schema-level ``max_length`` constraints on
``ChatCompletionRequest``/``ChatMessage``/``ToolExecuteRequest``
catch oversized payloads once parsed. The middleware therefore is
defence-in-depth on the cheap path (declared length) and the
schemas cover the rest.

Bypasses observability + key distribution endpoints so a misbehaved
scraper sending a 5 MB body to ``/metrics`` never blacks out
``/health``.

Wired in ``mcp_proxy/main.py`` next to the existing strip-header /
global-rate-limit middlewares so Starlette's LIFO order runs the
size check before any handler observes the body.

References: CWE-770 (allocation of resources without limits),
OWASP A04 Insecure Design. Pairs with the per-principal token-budget
limiter on ``/v1/chat/completions`` (rate axis) — this is the size
axis.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

_log = logging.getLogger("mcp_proxy")

# Default body ceiling: 2 MiB. Generous enough for a 200-message
# Anthropic-shaped chat (max_length=200 on messages × max_length=
# 200_000 chars per message would technically yield 40 MB — but the
# real-world ceiling is the provider's own per-request limit, which
# is well under 2 MiB for prose). Operators tuning for embedding /
# vision / RAG payloads can bump via env.
DEFAULT_MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB

# Paths exempt from the size cap. ``/health`` + ``/metrics`` must
# never be blocked; ``/.well-known/`` carries JWKS payloads from
# dependents and is read-only.
_BYPASS_PREFIXES: tuple[str, ...] = (
    "/health",
    "/healthz",
    "/readyz",
    "/metrics",
    "/.well-known/",
)


def _emit_oversize_log(
    path: str, method: str, declared: int, ceiling: int,
) -> None:
    """Write a WARNING record straight to stderr, matching the JSON
    shape of ``mcp_proxy.logging_setup.JSONFormatter``. Same rationale
    as ``global_rate_limit._emit_shed_log`` — the ``mcp_proxy`` logger
    is silently muted inside the ASGI dispatch path at runtime, so
    we bypass logging.Logger and write directly.
    """
    record = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "WARNING",
        "logger": "mcp_proxy",
        "message": (
            f"request body oversize: path={path} method={method} "
            f"declared_bytes={declared} ceiling_bytes={ceiling}"
        ),
    }, default=str)
    print(record, file=sys.stderr, flush=True)


def _oversize_body(ceiling: int) -> bytes:
    return json.dumps({
        "detail": (
            f"Request body exceeds the per-request size limit of "
            f"{ceiling} bytes."
        ),
        "error": "request_body_too_large",
    }).encode()


def _oversize_headers(body: bytes) -> list[tuple[bytes, bytes]]:
    return [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"x-cullis-shed-reason", b"request_body_too_large"),
    ]


class LimitRequestBodyMiddleware:
    """Pure ASGI middleware. Wired via ``app.add_middleware(...)``."""

    def __init__(
        self,
        app,
        max_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES,
        bypass_prefixes: tuple[str, ...] = _BYPASS_PREFIXES,
    ) -> None:
        if max_bytes <= 0:
            raise ValueError(
                f"max_bytes must be positive, got {max_bytes}"
            )
        self.app = app
        self._max_bytes = int(max_bytes)
        self._bypass_prefixes = bypass_prefixes
        self._rejected_count = 0

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(p) for p in self._bypass_prefixes):
            await self.app(scope, receive, send)
            return

        declared: int | None = None
        for name, value in scope.get("headers", ()):
            if name.lower() == b"content-length":
                try:
                    declared = int(value.decode("ascii"))
                except (UnicodeDecodeError, ValueError):
                    declared = None
                break

        if declared is not None and declared > self._max_bytes:
            self._rejected_count += 1
            method = scope.get("method", "?")
            _emit_oversize_log(path, method, declared, self._max_bytes)
            body = _oversize_body(self._max_bytes)
            await send({
                "type": "http.response.start",
                "status": 413,
                "headers": _oversize_headers(body),
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        await self.app(scope, receive, send)

    @property
    def rejected_count(self) -> int:
        """Total requests rejected since process start. Exposed for
        tests + metrics integration."""
        return self._rejected_count

    @property
    def max_bytes(self) -> int:
        return self._max_bytes
