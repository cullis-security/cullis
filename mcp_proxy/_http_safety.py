"""HTTPException detail sanitiser (audit F-A-306, F-B-119).

Several Mastio call sites raised ``HTTPException(detail=f"...: {exc}")``
on caught exceptions. The detail string is rendered into the JSON
response body and reaches whoever called the endpoint. Caught
``Exception`` / ``RuntimeError`` / unknown class can be:

  * ``sqlalchemy.exc.DBAPIError`` whose ``str()`` includes
    ``[parameters: (...)]`` — leaks bcrypt password hashes, encrypted
    secrets, or any other bound value (memory
    ``feedback_sqlalchemy_exc_leaks_bound_params``).
  * Upstream LLM provider errors carrying ``sk-...`` API key prefixes
    or request body fragments.
  * Cert subject DNs / internal hostnames / IP addresses.
  * Pydantic ``ValidationError`` whose ``str()`` interpolates the input
    data into the error message.

The Cullis pattern is "raise a curated domain exception with a safe
``__str__``". This helper restores that posture for sites that still
catch a broad type: log the exception at ERROR with a short opaque
trace id, then return a redacted detail string the SPA / dashboard /
SDK can safely render. Operators grep the audit log for the trace id
to find the full exception context.

Use:

    from mcp_proxy._http_safety import safe_http_detail

    try:
        ...
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=safe_http_detail(
                exc,
                public_hint="rotation failed",
                log_context="rotate_mastio_ca",
            ),
        ) from exc
"""
from __future__ import annotations

import logging
import secrets
from typing import Any

_log = logging.getLogger("mcp_proxy._http_safety")


def _generate_trace_id() -> str:
    """Return an 8-char hex token correlated to the log line. 32 bits
    of entropy is plenty — the trace id is only meant to disambiguate
    log lines within a short window, not to be cryptographic."""
    return secrets.token_hex(4)


def safe_http_detail(
    exc: BaseException,
    *,
    public_hint: str,
    log_context: str = "",
    extra: dict[str, Any] | None = None,
) -> str:
    """Return a sanitised HTTPException detail string.

    Logs ``exc`` (with ``log_context`` and ``extra`` if provided) at
    ERROR with a fresh trace id, then returns
    ``"{public_hint}; trace_id={trace_id}"``. The trace id is the only
    bridge between the operator's log and the client's error response;
    nothing from the exception value reaches the client.
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


def pydantic_validation_summary(exc: BaseException) -> list[dict[str, str]]:
    """Convert a pydantic ``ValidationError`` into a redacted summary
    safe to expose to API clients.

    Returns a list of ``{"loc": "...", "type": "...", "msg": "..."}``
    dicts; the ``input`` field that pydantic normally includes is
    dropped because it echoes the offending payload back to the caller.
    Falls back to a single generic entry when the exception is not a
    pydantic error.
    """
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return [{"loc": "", "type": "schema_error", "msg": "schema validation failed"}]
    out: list[dict[str, str]] = []
    try:
        for err in errors():
            loc = ".".join(str(p) for p in err.get("loc", ()))
            out.append(
                {
                    "loc": loc,
                    "type": str(err.get("type", "")),
                    "msg": str(err.get("msg", "")),
                }
            )
    except Exception:  # noqa: BLE001 — defensive
        return [{"loc": "", "type": "schema_error", "msg": "schema validation failed"}]
    if not out:
        return [{"loc": "", "type": "schema_error", "msg": "schema validation failed"}]
    return out
