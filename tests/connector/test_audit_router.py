"""Tests for cullis_connector.admin.audit_router — GET /admin/audit."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cullis_connector.admin.audit_router import (
    ADMIN_SECRET_ENV,
    ADMIN_SECRET_HEADER,
    router,
)
from cullis_connector.identity.audit import (
    log_admin_action,
    log_login_attempt,
    log_password_change,
    reset_engine_cache_for_tests,
)


@pytest.fixture(autouse=True)
def _clean_engine_cache():
    reset_engine_cache_for_tests()
    yield
    reset_engine_cache_for_tests()


@pytest.fixture
def admin_secret(monkeypatch) -> str:
    secret = "audit-router-test-secret"
    monkeypatch.setenv(ADMIN_SECRET_ENV, secret)
    return secret


@pytest.fixture
def app(tmp_path: Path) -> FastAPI:
    app = FastAPI()
    app.state.connector_config_dir = str(tmp_path)
    app.include_router(router)
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# ── Happy path ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_audit_returns_entries(
    tmp_path: Path,
    client: TestClient,
    admin_secret: str,
):
    await log_login_attempt(
        tmp_path, ip="10.0.0.5", user_name="mario", status="ok"
    )
    await log_password_change(tmp_path, user_name="mario")

    resp = client.get(
        "/admin/audit",
        headers={ADMIN_SECRET_HEADER: admin_secret},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert len(body["entries"]) == 2
    actions = {e["action"] for e in body["entries"]}
    assert actions == {"login.attempt", "pw.change"}


@pytest.mark.asyncio
async def test_get_audit_empty_returns_200(
    client: TestClient, admin_secret: str
):
    resp = client.get(
        "/admin/audit",
        headers={ADMIN_SECRET_HEADER: admin_secret},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"entries": [], "total": 0}


# ── Auth gate ──────────────────────────────────────────────────────────────


def test_missing_admin_secret_returns_403(client: TestClient, admin_secret: str):
    resp = client.get("/admin/audit")
    assert resp.status_code == 403


def test_wrong_admin_secret_returns_403(client: TestClient, admin_secret: str):
    resp = client.get(
        "/admin/audit",
        headers={ADMIN_SECRET_HEADER: "wrong-secret"},
    )
    assert resp.status_code == 403


def test_admin_secret_not_configured_returns_403(
    monkeypatch, client: TestClient
):
    # Explicitly remove the env var so the dep treats the deployment as
    # un-configured and refuses every request.
    monkeypatch.delenv(ADMIN_SECRET_ENV, raising=False)
    resp = client.get(
        "/admin/audit",
        headers={ADMIN_SECRET_HEADER: "anything"},
    )
    assert resp.status_code == 403


# ── Filters ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_filter_by_user_name_query_param(
    tmp_path: Path,
    client: TestClient,
    admin_secret: str,
):
    await log_login_attempt(tmp_path, ip="1.1.1.1", user_name="mario", status="ok")
    await log_login_attempt(tmp_path, ip="1.1.1.2", user_name="lucia", status="ok")

    resp = client.get(
        "/admin/audit",
        params={"user_name": "mario"},
        headers={ADMIN_SECRET_HEADER: admin_secret},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["entries"][0]["user_name"] == "mario"


@pytest.mark.asyncio
async def test_filter_by_action_query_param(
    tmp_path: Path,
    client: TestClient,
    admin_secret: str,
):
    await log_login_attempt(tmp_path, ip="1.1.1.1", user_name="mario", status="ok")
    await log_password_change(tmp_path, user_name="mario")

    resp = client.get(
        "/admin/audit",
        params={"action": "pw.change"},
        headers={ADMIN_SECRET_HEADER: admin_secret},
    )
    body = resp.json()
    assert body["total"] == 1
    assert body["entries"][0]["action"] == "pw.change"


def test_invalid_since_returns_400(client: TestClient, admin_secret: str):
    resp = client.get(
        "/admin/audit",
        params={"since": "not-a-date"},
        headers={ADMIN_SECRET_HEADER: admin_secret},
    )
    assert resp.status_code == 400


def test_invalid_limit_returns_422(client: TestClient, admin_secret: str):
    resp = client.get(
        "/admin/audit",
        params={"limit": 0},
        headers={ADMIN_SECRET_HEADER: admin_secret},
    )
    # FastAPI Query(ge=1) rejects with 422 (validation error) before
    # the handler runs — that's the expected behaviour.
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_admin_action_audit_visible_via_router(
    tmp_path: Path,
    client: TestClient,
    admin_secret: str,
):
    from cullis_connector.identity.audit import hash_admin_secret

    await log_admin_action(
        tmp_path,
        action="admin.user.create",
        target="lucia",
        actor_secret_hash=hash_admin_secret(admin_secret),
    )
    resp = client.get(
        "/admin/audit",
        headers={ADMIN_SECRET_HEADER: admin_secret},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["entries"][0]["action"] == "admin.user.create"
    # Sanity: the plain admin secret never appears in the response.
    raw = resp.text
    assert admin_secret not in raw
