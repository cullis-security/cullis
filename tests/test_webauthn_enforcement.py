"""ADR-033 Phase 2 — enforcement gate on ``maybe_stamp_user_session``.

Covers four states the new ``MCP_PROXY_WEBAUTHN_ENFORCEMENT`` flag puts
:func:`mcp_proxy.auth.user_session.maybe_stamp_user_session` into:

* ``off``       → accept the session, do not emit the Phase 1 audit row.
* ``warn``      → keep the legacy behaviour (accept + warn) when the
  session row lacks ``user_signed_assertion``, and accept silently
  when the field is populated.
* ``required``  → raise HTTP 401 when the field is missing; accept
  when the field is populated.

These tests do not touch the third-party ``webauthn`` library at all —
the only thing under test is the gate inside Mastio. The storage path
is exercised in :mod:`test_webauthn_storage`.
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

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import HTTPException
from starlette.requests import Request

from mcp_proxy.auth.user_context import (
    current_on_behalf_of_user,
    reset_on_behalf_of_user,
    set_on_behalf_of_user,
)
from mcp_proxy.auth.user_session import maybe_stamp_user_session
from mcp_proxy.db import create_user_session, dispose_db, init_db


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "webauthn_enforce.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
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


def _request_with_headers(headers: dict[str, str]) -> Request:
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


async def _seed(
    *,
    session_id: str,
    thumb: str = "a" * 64,
    user_signed_assertion: str | None = None,
    user_credential_id: bytes | None = None,
) -> None:
    await create_user_session(
        session_id=session_id,
        principal_id="acme::user::alice",
        agent_cert_thumbprint=thumb,
        sso_subject="local:alice",
        idp_issuer="local",
        display_name="Alice",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        user_signed_assertion=user_signed_assertion,
        user_credential_id=user_credential_id,
    )


def _force_enforcement(monkeypatch, value: str) -> None:
    """Pin ``webauthn_enforcement`` on the cached settings singleton."""
    from mcp_proxy.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "webauthn_enforcement", value)
    monkeypatch.setattr(settings, "frontdesk_audit_warning_enabled", True)


async def test_enforcement_off_accepts_without_assertion(proxy_db, monkeypatch):
    _force_enforcement(monkeypatch, "off")
    await _seed(session_id="sess-off")
    req = _request_with_headers({
        "X-Cullis-Session-Token": "sess-off",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice",
    })

    out = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::connector",
        caller_cert_thumbprint="a" * 64,
    )

    assert out == "acme::user::alice"
    assert current_on_behalf_of_user() == "acme::user::alice"


async def test_enforcement_warn_accepts_and_warns(proxy_db, monkeypatch):
    """Default Phase 2 migration mode: accept session, emit warning audit."""
    _force_enforcement(monkeypatch, "warn")
    await _seed(session_id="sess-warn")

    captured: list[tuple] = []
    real_log_audit = __import__("mcp_proxy.db", fromlist=["log_audit"]).log_audit

    async def fake_log_audit(*args, **kwargs):
        captured.append((args, kwargs))
        await real_log_audit(*args, **kwargs)

    monkeypatch.setattr("mcp_proxy.db.log_audit", fake_log_audit)

    req = _request_with_headers({
        "X-Cullis-Session-Token": "sess-warn",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice",
    })

    out = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::connector",
        caller_cert_thumbprint="a" * 64,
    )

    assert out == "acme::user::alice"
    actions = [args[1] for args, _ in captured]
    assert "frontdesk_shared_unauthenticated_user_session_warning" in actions


async def test_enforcement_required_rejects_missing_assertion(
    proxy_db, monkeypatch,
):
    _force_enforcement(monkeypatch, "required")
    await _seed(session_id="sess-req-missing")

    req = _request_with_headers({
        "X-Cullis-Session-Token": "sess-req-missing",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice",
    })

    with pytest.raises(HTTPException) as excinfo:
        await maybe_stamp_user_session(
            req,
            caller_agent_id="acme::connector",
            caller_cert_thumbprint="a" * 64,
        )
    assert excinfo.value.status_code == 401
    assert "WebAuthn" in excinfo.value.detail
    # contextvar must not have been stamped before the raise.
    assert current_on_behalf_of_user() is None


async def test_enforcement_required_accepts_when_assertion_present(
    proxy_db, monkeypatch,
):
    _force_enforcement(monkeypatch, "required")
    await _seed(
        session_id="sess-req-ok",
        user_signed_assertion='{"id":"cred-1","type":"public-key"}',
        user_credential_id=b"\xde\xad\xbe\xef",
    )
    req = _request_with_headers({
        "X-Cullis-Session-Token": "sess-req-ok",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice",
    })

    out = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::connector",
        caller_cert_thumbprint="a" * 64,
    )

    assert out == "acme::user::alice"
    assert current_on_behalf_of_user() == "acme::user::alice"


async def test_enforcement_warn_skips_warning_when_assertion_present(
    proxy_db, monkeypatch,
):
    _force_enforcement(monkeypatch, "warn")
    await _seed(
        session_id="sess-warn-ok",
        user_signed_assertion='{"id":"cred-2","type":"public-key"}',
        user_credential_id=b"\xca\xfe",
    )

    captured_actions: list[str] = []
    real_log_audit = __import__("mcp_proxy.db", fromlist=["log_audit"]).log_audit

    async def fake_log_audit(agent_id, action, *args, **kwargs):
        captured_actions.append(action)
        await real_log_audit(agent_id, action, *args, **kwargs)

    monkeypatch.setattr("mcp_proxy.db.log_audit", fake_log_audit)

    req = _request_with_headers({
        "X-Cullis-Session-Token": "sess-warn-ok",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice",
    })

    out = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::connector",
        caller_cert_thumbprint="a" * 64,
    )

    assert out == "acme::user::alice"
    assert "frontdesk_shared_unauthenticated_user_session_warning" not in captured_actions
