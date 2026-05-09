"""HTTP integration tests for /admin/users — ADR-025 Phase 1.

Drives ``cullis_connector.web.build_app`` via fastapi.testclient and
asserts the admin API contracts: 201/400/404/409/403 paths, list
filter, delete idempotency, and reset-password flipping
``must_change_password`` back to True.

Each test gets a fresh ``tmp_path`` so the per-test users.db is fully
isolated (no shared engine state across tests).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.web import build_app

# Local AsyncEngine cache — flushed between tests so each test sees
# a fresh users.db at its own tmp_path.
from cullis_connector.identity.users_db import dispose_users_engines

ADMIN_SECRET = "test-admin-secret-not-default"


@pytest.fixture(autouse=True)
async def _cleanup_engines():
    yield
    await dispose_users_engines()


@pytest.fixture
def connector_config(tmp_path):
    cfg = ConnectorConfig(
        config_dir=tmp_path / "connector",
        site_url="http://mastio.test",
        verify_tls=False,
    )
    cfg.config_dir.mkdir(parents=True, exist_ok=True)
    return cfg


@pytest.fixture
def client(connector_config, monkeypatch):
    monkeypatch.setenv("CULLIS_CONNECTOR_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AUTH_MODE", "local")
    app = build_app(connector_config)
    tc = TestClient(app)
    # CSRF guard expects same-origin Origin on state-changing requests
    # for non-/admin paths; admin is exempt but TestClient uses
    # http://testserver as default base URL anyway.
    tc.headers["Origin"] = "http://testserver"
    return tc


def _admin_headers() -> dict[str, str]:
    return {"X-Admin-Secret": ADMIN_SECRET}


# ── auth ────────────────────────────────────────────────────────────────


def test_create_user_403_without_admin_secret(client):
    r = client.post(
        "/admin/users",
        json={"user_name": "mario", "password": "longpassword"},
    )
    # Pydantic missing-header → 422; FastAPI Header(...) without alias
    # would be 422 too, but we use Header(..., alias="X-Admin-Secret"),
    # so a missing header is also 422 from FastAPI before our 403
    # check runs. Either way, the route is not creating the user.
    assert r.status_code in (403, 422)


def test_create_user_403_with_wrong_admin_secret(client):
    r = client.post(
        "/admin/users",
        headers={"X-Admin-Secret": "wrong-secret"},
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert r.status_code == 403


def test_admin_secret_env_unset_returns_403(connector_config, monkeypatch):
    monkeypatch.delenv("CULLIS_CONNECTOR_ADMIN_SECRET", raising=False)
    monkeypatch.setenv("AUTH_MODE", "local")
    app = build_app(connector_config)
    tc = TestClient(app)
    r = tc.post(
        "/admin/users",
        headers={"X-Admin-Secret": "anything"},
        json={"user_name": "mario", "password": "longpassword"},
    )
    assert r.status_code == 403


# ── create ─────────────────────────────────────────────────────────────


def test_create_user_201_happy_path(client):
    r = client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "mario",
            "password": "temp123!secure",
            "must_change_password": True,
            "display_name": "Mario Rossi",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["user_name"] == "mario"
    assert body["display_name"] == "Mario Rossi"
    assert body["must_change_password"] is True
    assert body["disabled"] is False
    assert body["password_changed_at"] is None
    assert body["created_at"]
    assert "password" not in body
    assert "password_hash" not in body


def test_create_user_400_bad_username_regex(client):
    r = client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "mario rossi",  # space → invalid
            "password": "longpassword",
        },
    )
    # Pydantic field-level pattern reject → 422
    assert r.status_code in (400, 422)


def test_create_user_400_password_too_short(client):
    r = client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "mario",
            "password": "short",  # < 8 chars
        },
    )
    assert r.status_code in (400, 422)


def test_create_user_409_on_duplicate(client):
    payload = {"user_name": "mario", "password": "longpassword"}
    r1 = client.post(
        "/admin/users", headers=_admin_headers(), json=payload,
    )
    assert r1.status_code == 201
    r2 = client.post(
        "/admin/users", headers=_admin_headers(), json=payload,
    )
    assert r2.status_code == 409


# ── list ───────────────────────────────────────────────────────────────


def test_list_users_returns_created_rows(client):
    for name in ("alice", "bob", "carol"):
        client.post(
            "/admin/users",
            headers=_admin_headers(),
            json={"user_name": name, "password": "longpassword"},
        )
    r = client.get("/admin/users", headers=_admin_headers())
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert {u["user_name"] for u in body["users"]} == {"alice", "bob", "carol"}


def test_list_users_filter_by_q(client):
    client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "mario",
            "password": "longpassword",
            "display_name": "Mario Rossi",
        },
    )
    client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "lucia",
            "password": "longpassword",
            "display_name": "Lucia Bianchi",
        },
    )
    r = client.get("/admin/users?q=lucia", headers=_admin_headers())
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["users"][0]["user_name"] == "lucia"


# ── delete ─────────────────────────────────────────────────────────────


def test_delete_user_204_then_404(client):
    client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={"user_name": "todel", "password": "longpassword"},
    )
    r1 = client.delete("/admin/users/todel", headers=_admin_headers())
    assert r1.status_code == 204
    r2 = client.delete("/admin/users/todel", headers=_admin_headers())
    assert r2.status_code == 404


def test_delete_user_404_for_unknown(client):
    r = client.delete("/admin/users/ghost", headers=_admin_headers())
    assert r.status_code == 404


# ── reset password ─────────────────────────────────────────────────────


def test_reset_password_200_and_must_change_true(client):
    client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={
            "user_name": "resetme",
            "password": "old-password",
            "must_change_password": False,
        },
    )
    r = client.post(
        "/admin/users/resetme/reset-password",
        headers=_admin_headers(),
        json={"new_password": "fresh-temp-pwd"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_name"] == "resetme"
    assert body["must_change_password"] is True


def test_reset_password_404_for_unknown_user(client):
    r = client.post(
        "/admin/users/ghost/reset-password",
        headers=_admin_headers(),
        json={"new_password": "fresh-temp-pwd"},
    )
    assert r.status_code == 404


def test_reset_password_400_when_too_short(client):
    client.post(
        "/admin/users",
        headers=_admin_headers(),
        json={"user_name": "short", "password": "longpassword"},
    )
    r = client.post(
        "/admin/users/short/reset-password",
        headers=_admin_headers(),
        json={"new_password": "no"},  # < 8 chars
    )
    assert r.status_code in (400, 422)


# ── AUTH_MODE gating ───────────────────────────────────────────────────


def test_admin_users_not_mounted_when_auth_mode_oidc(connector_config, monkeypatch):
    monkeypatch.setenv("CULLIS_CONNECTOR_ADMIN_SECRET", ADMIN_SECRET)
    monkeypatch.setenv("AUTH_MODE", "oidc")
    app = build_app(connector_config)
    tc = TestClient(app)
    tc.headers["Origin"] = "http://testserver"

    r = tc.post(
        "/admin/users",
        headers=_admin_headers(),
        json={"user_name": "mario", "password": "longpassword"},
    )
    # Router not mounted → 404 from FastAPI (no matching route).
    assert r.status_code == 404
