"""ADR-032 Layer 2 — Mastio ``POST/DELETE /v1/principals/connector-login``.

Covers the happy path of binding a user identity to an enrolled
Connector and the parallel logout / revoke path. Schema invariants
(``user_sessions`` row shape, ``local_user_principals`` SSO columns)
are checked directly against the test sqlite so a future migration
that drops a column trips a test, not a customer report.
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


def _fake_agent(*, org: str = "acme", agent_id: str = "acme::connector") -> TokenPayload:
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
    db_file = tmp_path / "connector_login.db"
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
        "user_subject_sso": "alice@acme.com",
        "display_name": "Alice Smith",
        "idp_issuer": "https://idp.example.com",
        "device_cert_thumbprint": "a" * 64,
    }
    base.update(overrides)
    return base


async def test_connector_login_creates_session_and_user_row(app_client):
    resp = app_client.post("/v1/principals/connector-login", json=_body())
    assert resp.status_code == 201, resp.text
    data = resp.json()

    assert data["user_id"] == "acme::user::alice"
    assert isinstance(data["session_token"], str) and len(data["session_token"]) > 16
    assert data["expires_at"]

    async with get_db() as conn:
        sess = (await conn.execute(
            text("SELECT * FROM user_sessions WHERE session_id = :sid"),
            {"sid": data["session_token"]},
        )).mappings().first()
        assert sess is not None
        assert sess["principal_id"] == "acme::user::alice"
        assert sess["sso_subject"] == "alice@acme.com"
        assert sess["idp_issuer"] == "https://idp.example.com"
        assert sess["agent_cert_thumbprint"] == "a" * 64
        assert sess["revoked_at"] is None

        user = (await conn.execute(
            text(
                "SELECT principal_id, user_name, sso_subject, idp_issuer "
                "FROM local_user_principals WHERE principal_id = :pid"
            ),
            {"pid": "acme::user::alice"},
        )).mappings().first()
        assert user is not None
        assert user["user_name"] == "alice"
        assert user["sso_subject"] == "alice@acme.com"
        assert user["idp_issuer"] == "https://idp.example.com"


async def test_connector_login_idempotent_on_same_user(app_client):
    r1 = app_client.post("/v1/principals/connector-login", json=_body())
    r2 = app_client.post("/v1/principals/connector-login", json=_body())
    assert r1.status_code == 201
    assert r2.status_code == 201
    # Each call mints a fresh session — semantically a re-login.
    assert r1.json()["session_token"] != r2.json()["session_token"]
    # The user row stays single.
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT principal_id FROM local_user_principals "
                "WHERE principal_id = :pid"
            ),
            {"pid": "acme::user::alice"},
        )).all()
        assert len(rows) == 1


async def test_connector_login_slug_strips_email_domain(app_client):
    resp = app_client.post(
        "/v1/principals/connector-login",
        json=_body(user_subject_sso="Bob.Tanaka@acme.com"),
    )
    assert resp.status_code == 201
    assert resp.json()["user_id"] == "acme::user::bob.tanaka"


async def test_connector_logout_revokes_session(app_client):
    login = app_client.post("/v1/principals/connector-login", json=_body())
    token = login.json()["session_token"]

    out = app_client.delete(
        "/v1/principals/connector-login",
        headers={"X-Cullis-Session-Token": token},
    )
    assert out.status_code == 204, out.text

    async with get_db() as conn:
        sess = (await conn.execute(
            text("SELECT revoked_at FROM user_sessions WHERE session_id = :sid"),
            {"sid": token},
        )).mappings().first()
        assert sess is not None
        assert sess["revoked_at"] is not None


async def test_connector_logout_without_token_is_204_noop(app_client):
    out = app_client.delete("/v1/principals/connector-login")
    assert out.status_code == 204
