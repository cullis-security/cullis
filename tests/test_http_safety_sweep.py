"""Tests for the HTTPException detail sanitisers (F-A-306, F-B-119, F-B-402).

Two parallel helpers — ``mcp_proxy._http_safety.safe_http_detail`` and
``cullis_connector._http_safety.safe_http_detail`` — with identical
behaviour. We exercise both because the Connector ships as a separate
package (PyInstaller desktop bundle, Frontdesk Docker image) and the
Mastio helper isn't available there.

We also pin a regression test on the actual call sites: a representative
exception fed through the Mastio + Connector code paths must produce an
HTTP detail that does NOT contain known leak markers (bcrypt hash
prefix ``$2b$``, API key prefix ``sk-``, SQLAlchemy bound-parameter
fingerprint ``[parameters:``).
"""
from __future__ import annotations

import logging
import re

import pytest


# ── Helper unit tests — Mastio side ────────────────────────────────


def test_mastio_helper_returns_redacted_detail():
    from mcp_proxy._http_safety import safe_http_detail

    exc = RuntimeError(
        "DB error [parameters: ('$2b$12$abcdefghijabcdefghijabcdefghijabcdefghij',"
        " 'sk-test-1234567890abcdef')]"
    )
    detail = safe_http_detail(
        exc,
        public_hint="rotation failed",
        log_context="unit-test",
    )
    assert detail.startswith("rotation failed; trace_id=")
    # None of the leak markers reach the client.
    assert "$2b$" not in detail
    assert "sk-test" not in detail
    assert "[parameters:" not in detail


def test_mastio_helper_logs_exception_with_trace_id(monkeypatch):
    """The trace_id surfaced to the client also appears in the log line.

    ``mcp_proxy.logging_setup`` sets ``propagate=False`` on the package
    logger, and the full test suite picks up additional ancestor
    handlers that interfere with ``caplog`` / local-attached
    StreamHandler buffers. Monkeypatching the bound logger method is
    the cleanest way to assert what gets logged regardless of how the
    surrounding suite has configured the logger hierarchy.
    """
    from mcp_proxy import _http_safety as hs

    captured: list[str] = []

    def _fake_error(msg, *args, **kwargs):
        captured.append(msg % args if args else msg)

    monkeypatch.setattr(hs._log, "error", _fake_error)

    exc = ValueError("internal-hostname-db-01.internal.example.com")
    detail = hs.safe_http_detail(
        exc,
        public_hint="probe failed",
        log_context="ai_provider_test",
        extra={"provider": "anthropic"},
    )

    trace_id = re.search(r"trace_id=([0-9a-f]{8})", detail).group(1)
    assert captured, "safe_http_detail did not call _log.error"
    log_line = captured[0]
    assert trace_id in log_line
    assert "ValueError" in log_line
    assert "internal-hostname-db-01" in log_line
    assert "provider=anthropic" in log_line


def test_pydantic_validation_summary_drops_input_field():
    from mcp_proxy._http_safety import pydantic_validation_summary

    class _FakePydanticError(Exception):
        def errors(self):
            return [
                {
                    "loc": ("messages", 0, "content"),
                    "type": "string_type",
                    "msg": "Input should be a valid string",
                    # The thing we MUST NOT echo back.
                    "input": {"secret_password": "p@ssw0rd!"},
                },
            ]

    summary = pydantic_validation_summary(_FakePydanticError())
    assert summary == [
        {
            "loc": "messages.0.content",
            "type": "string_type",
            "msg": "Input should be a valid string",
        },
    ]
    # Sanity — serialise the summary and confirm no input leak.
    import json
    payload = json.dumps(summary)
    assert "p@ssw0rd" not in payload
    assert "secret_password" not in payload


def test_pydantic_validation_summary_falls_back_for_non_pydantic():
    from mcp_proxy._http_safety import pydantic_validation_summary

    summary = pydantic_validation_summary(RuntimeError("not a pydantic error"))
    assert summary == [
        {"loc": "", "type": "schema_error", "msg": "schema validation failed"},
    ]


# ── Helper unit tests — Connector side ─────────────────────────────


def test_connector_helper_returns_redacted_detail():
    from cullis_connector._http_safety import safe_http_detail

    exc = RuntimeError("upstream Mastio said: principal_id=alice@orgB token=eyJh…")
    detail = safe_http_detail(
        exc,
        public_hint="inbox send failed",
        log_context="inbox_send",
        extra={"recipient": "bob"},
    )
    assert detail.startswith("inbox send failed; trace_id=")
    # Other-principal identifier does not surface to the caller.
    assert "alice@orgB" not in detail
    assert "eyJh" not in detail


def test_connector_helper_logs_with_trace_id(monkeypatch):
    """Same monkeypatch-the-logger pattern as the Mastio helper — the
    Connector root logger is also configured with propagate=False by
    ``cullis_connector._logging.setup_logging``."""
    from cullis_connector import _http_safety as hs

    captured: list[str] = []

    def _fake_error(msg, *args, **kwargs):
        captured.append(msg % args if args else msg)

    monkeypatch.setattr(hs._log, "error", _fake_error)

    exc = ConnectionError("internal-mastio.lan:9443 connection refused")
    detail = hs.safe_http_detail(
        exc,
        public_hint="Cullis cloud call failed",
        log_context="chat_completions.tool_use_loop",
    )

    trace_id = re.search(r"trace_id=([0-9a-f]{8})", detail).group(1)
    assert captured, "safe_http_detail did not call _log.error"
    log_line = captured[0]
    assert trace_id in log_line
    assert "ConnectionError" in log_line
    assert "internal-mastio.lan" in log_line


# ── Regression: known call sites no longer leak ──────────────────


def test_broker_bridge_rotation_no_longer_echoes_court_text():
    """F-A-306 regression — ``broker_bridge.propagate_mastio_key_rotation``
    must NOT include the Court response body in the HTTPException detail
    when Court returns 4xx/5xx. We inspect the source to keep the test
    package-import-free (the call site needs a live broker_bridge state
    machine that's not worth materialising in a unit test)."""
    import pathlib

    src = pathlib.Path("mcp_proxy/egress/broker_bridge.py").read_text()
    # No f-string interpolation of resp.text into HTTPException detail.
    assert "detail=f\"court rejected rotation with" not in src
    assert "detail=f\"court rejected rotation: {resp.text}" not in src
    # The constant-detail replacement is present.
    assert 'detail="court rejected rotation"' in src


def test_connector_router_no_longer_interpolates_exc_into_detail():
    """F-B-402 regression — sweep the router source for ``f"...: {exc}"``
    inside ``HTTPException`` constructors."""
    import pathlib

    for path in (
        "cullis_connector/ambassador/router.py",
        "cullis_connector/ambassador/shared/router.py",
    ):
        src = pathlib.Path(path).read_text()
        # Pattern: HTTPException(..., f"...{exc}") or detail=f"...{exc}"
        # Both old leak shapes should be gone.
        assert "{exc}\"" not in src, (
            f"{path}: ``f\"...{{exc}}\"`` interpolation still present — "
            "use safe_http_detail() instead"
        )


def test_mastio_admin_modules_no_longer_interpolate_exc_into_detail():
    """F-B-119 regression — same sweep for the Mastio admin / egress
    modules that were flagged in the audit. ``mcp_proxy/_http_safety.py``
    is the canonical channel and is allowed to contain the pattern in
    its own docstring."""
    import pathlib

    files = [
        "mcp_proxy/admin/mastio_ca.py",
        "mcp_proxy/admin/ai_providers.py",
        "mcp_proxy/egress/ai_gateway.py",
        "mcp_proxy/auth/user_session.py",
        "mcp_proxy/guardian/ticket.py",
    ]
    for path in files:
        src = pathlib.Path(path).read_text()
        # Look for HTTPException(... f"...{exc}") or GatewayError(... f"...{exc}")
        # but only within the audit-flagged lines. Easiest: assert the
        # raw f-string fragments are gone.
        for needle in (
            'detail=f"rotation failed: {exc}',
            'detail=f"{type(exc).__name__}: {exc}',
            'detail=f"Upstream payload failed Mastio schema: {exc}',
            'detail=f"LiteLLM response failed Mastio schema: {exc}',
            'detail=f"WebAuthn assertion rejected: {exc}',
            'detail=f"GUARDIAN_TICKET_KEY base64url decode failed: {exc}',
        ):
            assert needle not in src, f"{path}: legacy leak pattern still present: {needle}"
