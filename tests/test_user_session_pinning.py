"""ADR-032 Layer 2 — ``maybe_stamp_user_session`` cert-thumbprint pinning.

Closes the MEDIUM "dead pinning code path" finding from the R1 review:
the helper accepted a ``caller_cert_thumbprint`` keyword but no
caller passed it, so the docstring-claimed
``session bound to a different device`` check never ran. The cert+DPoP
auth dep now threads the verified cert digest in; these tests pin
the on / off / mismatch paths so a future refactor can't accidentally
drop the wire-up without a red test.
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
    db_file = tmp_path / "user_session_pin.db"
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


def _make_request(headers: dict[str, str]) -> Request:
    """Build a minimal Starlette Request with the given headers.

    The helper only reads ``request.headers``; no body / state / scope
    fields are touched, so a trimmed ASGI scope is enough.
    """
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


async def _seed_session(*, session_id: str, thumbprint: str) -> None:
    await create_user_session(
        session_id=session_id,
        principal_id="acme::user::alice-deadbeef",
        agent_cert_thumbprint=thumbprint,
        sso_subject="alice@acme.com",
        idp_issuer="https://idp.example.com",
        display_name="Alice",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


async def test_pin_matches_stamps_contextvar(proxy_db):
    await _seed_session(session_id="sess-pin-ok", thumbprint="a" * 64)
    req = _make_request({
        "X-Cullis-Session-Token": "sess-pin-ok",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice-deadbeef",
    })

    out = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::connector",
        caller_cert_thumbprint="a" * 64,
    )

    assert out == "acme::user::alice-deadbeef"
    assert current_on_behalf_of_user() == "acme::user::alice-deadbeef"


async def test_pin_mismatch_refuses_to_stamp(proxy_db):
    """The session is valid + unexpired + principal_id matches the
    header, but the caller's cert thumbprint disagrees with the one
    the session was bound to. The helper must NOT stamp the contextvar
    — otherwise a stolen session token from one Connector could be
    replayed by a different device and still attribute audit rows to
    the original user.
    """
    await _seed_session(session_id="sess-pin-bad", thumbprint="a" * 64)
    req = _make_request({
        "X-Cullis-Session-Token": "sess-pin-bad",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice-deadbeef",
    })

    out = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::other-connector",
        caller_cert_thumbprint="b" * 64,  # ≠ bound thumb
    )

    assert out is None
    assert current_on_behalf_of_user() is None


async def test_pin_absent_falls_back_to_principal_check(proxy_db):
    """When the caller cannot derive a thumbprint (Bearer-DPoP path,
    LOCAL_TOKEN path, dev plain-HTTP), the pinning check is skipped
    by design — the agent identity already authenticated the call.
    The principal header check still runs.
    """
    await _seed_session(session_id="sess-no-pin", thumbprint="a" * 64)
    req = _make_request({
        "X-Cullis-Session-Token": "sess-no-pin",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice-deadbeef",
    })

    out = await maybe_stamp_user_session(
        req,
        caller_agent_id="acme::connector",
        caller_cert_thumbprint=None,
    )

    assert out == "acme::user::alice-deadbeef"
    assert current_on_behalf_of_user() == "acme::user::alice-deadbeef"


async def test_expired_session_refuses_to_stamp(proxy_db):
    expired_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    await create_user_session(
        session_id="sess-expired",
        principal_id="acme::user::alice-deadbeef",
        agent_cert_thumbprint="a" * 64,
        sso_subject="alice@acme.com",
        idp_issuer="https://idp.example.com",
        display_name="Alice",
        expires_at=expired_until,
    )
    req = _make_request({
        "X-Cullis-Session-Token": "sess-expired",
        "X-Cullis-On-Behalf-Of-User": "acme::user::alice-deadbeef",
    })

    out = await maybe_stamp_user_session(
        req, caller_agent_id="acme::connector",
        caller_cert_thumbprint="a" * 64,
    )

    assert out is None
    assert current_on_behalf_of_user() is None


async def test_principal_header_mismatch_refuses_to_stamp(proxy_db):
    await _seed_session(session_id="sess-pmatch", thumbprint="a" * 64)
    req = _make_request({
        "X-Cullis-Session-Token": "sess-pmatch",
        # Header claims a different principal than the session row.
        "X-Cullis-On-Behalf-Of-User": "acme::user::eve-cafebabe",
    })

    out = await maybe_stamp_user_session(
        req, caller_agent_id="acme::connector",
        caller_cert_thumbprint="a" * 64,
    )

    assert out is None
    assert current_on_behalf_of_user() is None
