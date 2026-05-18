"""ADR-033 Phase 1 — Frontdesk shared-mode audit warning.

Verifies that ``maybe_stamp_user_session`` emits:
  (a) a WARNING log entry, and
  (b) an audit chain row of type
      ``frontdesk_shared_unauthenticated_user_session_warning``

whenever a session is accepted but lacks a ``user_signed_assertion``
field (i.e. every session today, pre-Phase-2).

Also verifies that setting ``MCP_PROXY_FRONTDESK_AUDIT_WARNING_ENABLED=false``
suppresses both the log entry and the audit row (opt-out for dev/test).

Note: ``mcp_proxy`` loggers set ``propagate=False`` at configure time so
pytest caplog does not capture them by default. We use ``monkeypatch`` on
``_log.warning`` to intercept calls — the same pattern used across the
suite (see memory ``feedback_mcp_proxy_logger_caplog``).
"""
from __future__ import annotations

import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import text
from starlette.requests import Request

from mcp_proxy.auth.user_context import (
    reset_on_behalf_of_user,
    set_on_behalf_of_user,
)
from mcp_proxy.auth.user_session import (
    ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION,
    maybe_stamp_user_session,
)
from mcp_proxy.db import create_user_session, dispose_db, get_db, init_db


pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "frontdesk_warn.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    monkeypatch.setenv("MCP_PROXY_FRONTDESK_AUDIT_WARNING_ENABLED", "true")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()
        get_settings.cache_clear()


@pytest.fixture(autouse=True)
def clear_contextvar():
    tok = set_on_behalf_of_user(None)
    yield
    reset_on_behalf_of_user(tok)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(headers: dict[str, str]) -> Request:
    raw = [
        (k.lower().encode("latin-1"), v.encode("latin-1"))
        for k, v in headers.items()
    ]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/egress/anything",
        "headers": raw,
        "query_string": b"",
    }
    return Request(scope)


async def _seed_session(
    *,
    session_id: str,
    principal_id: str = "acme::user::daniele",
    thumbprint: str = "a" * 64,
) -> None:
    await create_user_session(
        session_id=session_id,
        principal_id=principal_id,
        agent_cert_thumbprint=thumbprint,
        sso_subject="daniele@acme.com",
        idp_issuer="https://idp.acme.com",
        display_name="Daniele",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


async def _count_audit_rows_by_action(action: str) -> int:
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT COUNT(*) FROM audit_log WHERE action = :action"),
            {"action": action},
        )).first()
    return int(row[0]) if row else 0


async def _flush_pending_tasks() -> None:
    """Let any fire-and-forget asyncio.Tasks spawned by the helper complete."""
    await asyncio.sleep(0)
    await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# Tests: warning emitted
# ---------------------------------------------------------------------------


async def test_warning_log_emitted_for_session_without_user_assertion(
    proxy_db, monkeypatch,
):
    """A valid session (no user_signed_assertion in the row) triggers WARNING.

    Uses monkeypatch on ``_log.warning`` because the mcp_proxy logger
    hierarchy sets ``propagate=False``, which prevents pytest caplog from
    capturing these records.
    """
    await _seed_session(session_id="warn-sess-001")

    import mcp_proxy.auth.user_session as _us_mod

    warning_calls: list[str] = []
    original_warn = _us_mod._log.warning

    def _capture_warning(msg, *args, **kwargs):
        warning_calls.append(msg % args if args else msg)
        original_warn(msg, *args, **kwargs)

    monkeypatch.setattr(_us_mod._log, "warning", _capture_warning)

    req = _make_request({
        "X-Cullis-Session-Token": "warn-sess-001",
        "X-Cullis-On-Behalf-Of-User": "acme::user::daniele",
    })

    result = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::frontdesk-connector",
    )

    assert result == "acme::user::daniele", "session should still be accepted"
    assert any(
        "frontdesk-shared" in m and "without user cryptographic assertion" in m
        for m in warning_calls
    ), f"expected frontdesk warning in log, got: {warning_calls}"


async def test_audit_chain_row_written_for_session_without_user_assertion(proxy_db):
    """The audit chain row with the correct action type is written."""
    await _seed_session(session_id="warn-sess-002")

    req = _make_request({
        "X-Cullis-Session-Token": "warn-sess-002",
        "X-Cullis-On-Behalf-Of-User": "acme::user::daniele",
    })

    await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::frontdesk-connector",
    )

    # Allow the fire-and-forget Task to complete.
    await _flush_pending_tasks()

    count = await _count_audit_rows_by_action(
        ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION,
    )
    assert count >= 1, (
        f"expected at least 1 audit row with action="
        f"'{ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION}', got {count}"
    )


async def test_audit_row_contains_correct_agent_and_user_fields(proxy_db):
    """The audit row detail JSON carries connector_agent_id and claimed_user_principal_id."""
    import json

    await _seed_session(
        session_id="warn-sess-003",
        principal_id="acme::user::alice",
    )

    req = _make_request({
        "X-Cullis-Session-Token": "warn-sess-003",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice",
    })

    await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::frontdesk-node-1",
    )
    await _flush_pending_tasks()

    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT agent_id, action, detail FROM audit_log "
                "WHERE action = :action ORDER BY id DESC LIMIT 1"
            ),
            {"action": ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION},
        )).mappings().first()

    assert row is not None
    assert row["agent_id"] == "acme::frontdesk-node-1"

    detail = json.loads(row["detail"])
    assert detail["connector_agent_id"] == "acme::frontdesk-node-1"
    assert detail["claimed_user_principal_id"] == "acme::user::alice"
    assert "timestamp" in detail


# ---------------------------------------------------------------------------
# Tests: opt-out via env var
# ---------------------------------------------------------------------------


async def test_warning_suppressed_when_env_var_disabled(
    tmp_path, monkeypatch,
):
    """When FRONTDESK_AUDIT_WARNING_ENABLED=false, no WARNING and no audit row."""
    db_file = tmp_path / "frontdesk_optout.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    monkeypatch.setenv("MCP_PROXY_FRONTDESK_AUDIT_WARNING_ENABLED", "false")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)

    try:
        await _seed_session(session_id="optout-sess-001")

        import mcp_proxy.auth.user_session as _us_mod

        warning_calls: list[str] = []
        original_warn = _us_mod._log.warning

        def _capture_warning(msg, *args, **kwargs):
            warning_calls.append(msg % args if args else msg)
            original_warn(msg, *args, **kwargs)

        monkeypatch.setattr(_us_mod._log, "warning", _capture_warning)

        req = _make_request({
            "X-Cullis-Session-Token": "optout-sess-001",
            "X-Cullis-On-Behalf-Of-User": "acme::user::daniele",
        })

        result = await maybe_stamp_user_session(
            req,
            caller_agent_id="acme::frontdesk-connector",
        )

        await _flush_pending_tasks()

        # Session still accepted.
        assert result == "acme::user::daniele"

        # No frontdesk warning log.
        frontdesk_warnings = [m for m in warning_calls if "frontdesk-shared" in m]
        assert frontdesk_warnings == [], (
            f"expected no frontdesk warning log when disabled, got: {frontdesk_warnings}"
        )

        # No audit row for the warning action.
        count = await _count_audit_rows_by_action(
            ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION,
        )
        assert count == 0, (
            f"expected 0 audit rows for warning action when disabled, got {count}"
        )

    finally:
        await dispose_db()
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Tests: sessions that are rejected do not emit the warning
# ---------------------------------------------------------------------------


async def test_no_warning_when_session_token_absent(proxy_db, monkeypatch):
    """No warning when X-Cullis-Session-Token header is absent."""
    import mcp_proxy.auth.user_session as _us_mod

    warning_calls: list[str] = []
    monkeypatch.setattr(
        _us_mod._log, "warning",
        lambda msg, *a, **kw: warning_calls.append(msg % a if a else msg),
    )

    req = _make_request({})

    result = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::frontdesk-connector",
    )

    assert result is None
    frontdesk_warnings = [m for m in warning_calls if "frontdesk-shared" in m]
    assert frontdesk_warnings == []


async def test_no_warning_when_session_is_rejected_due_to_mismatch(
    proxy_db, monkeypatch,
):
    """No warning when principal_id header mismatches the stored row."""
    await _seed_session(session_id="warn-mismatch-001", principal_id="acme::user::alice")

    warning_calls: list[str] = []
    import mcp_proxy.auth.user_session as _us_mod
    monkeypatch.setattr(
        _us_mod._log, "warning",
        lambda msg, *a, **kw: warning_calls.append(msg % a if a else msg),
    )

    req = _make_request({
        "X-Cullis-Session-Token": "warn-mismatch-001",
        # Claims a different user than the session row has.
        "X-Cullis-On-Behalf-Of-User": "acme::user::eve",
    })

    result = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::frontdesk-connector",
    )
    await _flush_pending_tasks()

    assert result is None
    # No audit warning row should be written for a rejected session.
    count = await _count_audit_rows_by_action(
        ACTION_FRONTDESK_SHARED_UNAUTHENTICATED_SESSION,
    )
    assert count == 0
