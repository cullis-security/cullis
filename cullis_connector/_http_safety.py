"""Connector-side HTTPException detail sanitiser (audit F-B-402).

10+ call sites in the Ambassador router (single + shared mode) raised
``HTTPException(detail=f"...: {exc}")`` on caught exceptions, leaking
SQLAlchemy bound parameters, upstream Mastio response bodies, cert
subject DNs, internal hostnames, etc. to whatever called the
OpenAI-shaped ``/v1/chat/completions`` endpoint.

In Frontdesk shared mode this is particularly bad: the SPA renders the
detail field directly in the chat banner, so a multi-tenant deployment
could surface user-A error text into user-B's session.

This helper is the Connector-side twin of ``mcp_proxy._http_safety``.
Same shape, same trace-id bridge to the log line. Kept as a separate
module because the Connector package is shipped standalone (PyInstaller
desktop bundle + Frontdesk Docker image) and must not import from
``mcp_proxy``.

Use:

    from cullis_connector._http_safety import safe_http_detail

    try:
        ...
    except Exception as exc:
        _log.exception("inbox send failed for recipient=%s", recipient_id)
        raise HTTPException(
            502,
            safe_http_detail(
                exc,
                public_hint="inbox send failed",
                log_context="inbox_send",
                extra={"recipient": recipient_id},
            ),
        ) from exc
"""
from __future__ import annotations

import logging
import secrets
from typing import Any

_log = logging.getLogger("cullis_connector._http_safety")


def _generate_trace_id() -> str:
    return secrets.token_hex(4)


def safe_http_detail(
    exc: BaseException,
    *,
    public_hint: str,
    log_context: str = "",
    extra: dict[str, Any] | None = None,
) -> str:
    """Return a sanitised HTTPException detail string.

    Logs ``exc`` at ERROR with a fresh trace id, returns
    ``"{public_hint}; trace_id={trace_id}"``. Nothing from the exception
    value reaches the client — operators grep the log for the trace id
    to recover the full context.
    """
    trace_id = _generate_trace_id()
    extras = " ".join(f"{k}={v}" for k, v in (extra or {}).items())
    _log.error(
        "safe_http_detail trace_id=%s context=%s exc_type=%s %sexc=%s",
        trace_id,
        log_context or "(none)",
        type(exc).__name__,
        f"{extras} " if extras else "",
        exc,
    )
    return f"{public_hint}; trace_id={trace_id}"
