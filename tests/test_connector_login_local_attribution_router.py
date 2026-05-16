"""ADR-025 Phase 5 / F4 R3 — ``POST /v1/principals/connector-login-local-attribution``.

Companion to ``test_connector_login_endpoint.py``: same fixtures, same
schema invariants, but the local-auth attribution path. The Connector
has already verified bcrypt against ``cullis_connector/identity/users.py``
and the Mastio mints the user_sessions row without touching a password
(per migration 0028_revert_user_password).
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

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import text

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.models import TokenPayload


pytestmark = pytest.mark.asyncio


def _fake_agent(
    *, org: str = "acme", agent_id: str = "acme::connector",
) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{agent_id}",
        agent_id=agent_id,
        org=org,
        exp=9_999_999_999,
        iat=0,
        jti=f"jti-{agent_id}",
        scope=[],
        cnf={"jkt": "fake-jkt"},
        principal_type="agent",
    )


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "attribution.db"
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


@pytest.fixture
def app_client(proxy_db):
    from mcp_proxy.main import app

    app.dependency_overrides[get_authenticated_agent] = lambda: _fake_agent()
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.pop(get_authenticated_agent, None)


def _body(**overrides):
    base = {
        "local_subject": "alice",
        "display_name": "Alice Smith",
        "device_cert_thumbprint": "a" * 64,
        "auth_mode": "local",
    }
    base.update(overrides)
    return base


async def test_attribution_creates_session_and_local_principal(app_client):
    resp = app_client.post(
        "/v1/principals/connector-login-local-attribution", json=_body(),
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()

    user_id = data["user_id"]
    assert user_id == "acme::user::alice"
    assert isinstance(data["session_token"], str) and len(data["session_token"]) > 16
    assert data["expires_at"]

    async with get_db() as conn:
        sess = (await conn.execute(
            text("SELECT * FROM user_sessions WHERE session_id = :sid"),
            {"sid": data["session_token"]},
        )).mappings().first()
        assert sess is not None
        assert sess["principal_id"] == user_id
        # Local-auth marker: idp_issuer == "local", sso_subject is
        # synthesised so a SQL "cluster by source" query still works.
        assert sess["idp_issuer"] == "local"
        assert sess["sso_subject"] == "local:alice"
        assert sess["agent_cert_thumbprint"] == "a" * 64
        assert sess["revoked_at"] is None

        principal = (await conn.execute(
            text(
                "SELECT principal_id, user_name, sso_subject, idp_issuer "
                "FROM local_user_principals WHERE principal_id = :pid"
            ),
            {"pid": user_id},
        )).mappings().first()
        assert principal is not None
        assert principal["user_name"] == "alice"
        # Local-auth rows leave sso_subject/idp_issuer NULL — the
        # presence of those NULLs is itself the "this principal came
        # from the local-auth path" marker on disk.
        assert principal["sso_subject"] is None
        assert principal["idp_issuer"] is None


async def test_attribution_idempotent_same_subject(app_client):
    r1 = app_client.post(
        "/v1/principals/connector-login-local-attribution", json=_body(),
    )
    r2 = app_client.post(
        "/v1/principals/connector-login-local-attribution", json=_body(),
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    # Re-login mints a fresh session.
    assert r1.json()["session_token"] != r2.json()["session_token"]
    # Stable principal_id across re-logins (no nonce/timing in the slug).
    assert r1.json()["user_id"] == r2.json()["user_id"]

    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT principal_id FROM local_user_principals "
                "WHERE principal_id = :pid"
            ),
            {"pid": r1.json()["user_id"]},
        )).all()
        assert len(rows) == 1


async def test_attribution_rejects_invalid_local_subject(app_client):
    """Username regex closes the SQL/SPIFFE-injection vector."""
    resp = app_client.post(
        "/v1/principals/connector-login-local-attribution",
        json=_body(local_subject="bob;DROP TABLE users"),
    )
    # Either pydantic max_length or the inner regex catches it.
    assert resp.status_code in {400, 422}, resp.text


async def test_attribution_rejects_too_long_local_subject(app_client):
    resp = app_client.post(
        "/v1/principals/connector-login-local-attribution",
        json=_body(local_subject="a" * 65),
    )
    assert resp.status_code == 422, resp.text


async def test_attribution_principal_id_lowercased(app_client):
    """user_name is lowercased so case-variant logins collapse to one row."""
    r1 = app_client.post(
        "/v1/principals/connector-login-local-attribution",
        json=_body(local_subject="Alice"),
    )
    r2 = app_client.post(
        "/v1/principals/connector-login-local-attribution",
        json=_body(local_subject="alice"),
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["user_id"] == r2.json()["user_id"] == "acme::user::alice"


async def test_attribution_does_not_share_principal_with_sso_login(app_client):
    """Local-auth and SSO logins land on distinct principals even when
    the local_subject matches the SSO email's local-part. The SSO
    sibling appends a stable hash suffix; local-auth does not. Both
    paths are safe because the principal_id prefix is the only thing
    routed by policy.
    """
    local = app_client.post(
        "/v1/principals/connector-login-local-attribution",
        json=_body(local_subject="alice"),
    )
    sso = app_client.post(
        "/v1/principals/connector-login",
        json={
            "user_subject_sso": "alice@acme.com",
            "display_name": "Alice Smith",
            "idp_issuer": "https://idp.example.com",
            "device_cert_thumbprint": "a" * 64,
        },
    )
    assert local.status_code == 201
    assert sso.status_code == 201
    assert local.json()["user_id"] != sso.json()["user_id"]
    # SSO carries the hash suffix; local-auth does not.
    assert local.json()["user_id"] == "acme::user::alice"
    assert sso.json()["user_id"].startswith("acme::user::alice-")


async def test_attribution_persists_session_ttl(app_client):
    """expires_at honours the configured TTL (~1h default)."""
    from datetime import datetime, timezone
    resp = app_client.post(
        "/v1/principals/connector-login-local-attribution", json=_body(),
    )
    assert resp.status_code == 201
    expires_at = datetime.fromisoformat(
        resp.json()["expires_at"].replace("Z", "+00:00"),
    )
    now = datetime.now(timezone.utc)
    delta = (expires_at - now).total_seconds()
    # Allow generous slack so a slow CI doesn't flap the assertion.
    assert 60 <= delta <= 3 * 3600
