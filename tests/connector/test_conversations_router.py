"""Sprint 1 Step 6 PR-A, Connector conversations REST.

Covers the new ``/v1/conversations`` surface that backs the SPA's
sidebar history. Each test exercises one CRUD primitive against a
fresh ConnectorConfig + in-memory-style on-disk SQLite (the fixture
points at tmp_path so each test sees its own database file).

The fake CullisClient from ``test_ambassador_router`` is reused so
the ambassador mounts cleanly without a real Mastio.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.web import build_app
from tests.connector.test_ambassador_router import (
    FakeCullisClient,
    _seed_identity,
)


# ── fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _patch_sdk(monkeypatch):
    FakeCullisClient.reset()
    monkeypatch.setattr("cullis_sdk.CullisClient", FakeCullisClient)
    yield
    FakeCullisClient.reset()


@pytest.fixture
def app(tmp_path: Path):
    _seed_identity(tmp_path)
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://mastio.test",
        verify_tls=False,
    )
    cfg.ambassador.require_local_only = False
    return build_app(cfg)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def bearer(client, tmp_path: Path) -> str:
    return (tmp_path / "local.token").read_text(encoding="utf-8").strip()


@pytest.fixture
def auth(bearer):
    return {"Authorization": f"Bearer {bearer}"}


# ── tests ───────────────────────────────────────────────────────────


def test_create_returns_id_and_empty_title(client, auth):
    r = client.post("/v1/conversations", headers=auth)
    assert r.status_code == 201
    body = r.json()
    assert body["id"]
    assert body["title"] is None
    assert "created_at" in body
    assert "updated_at" in body


def test_list_empty_then_lists_created(client, auth):
    r0 = client.get("/v1/conversations", headers=auth)
    assert r0.status_code == 200
    assert r0.json() == []

    r1 = client.post("/v1/conversations", headers=auth)
    conv_id = r1.json()["id"]

    r2 = client.get("/v1/conversations", headers=auth)
    assert r2.status_code == 200
    ids = [c["id"] for c in r2.json()]
    assert conv_id in ids


def test_rename_updates_title_and_updated_at(client, auth):
    conv_id = client.post("/v1/conversations", headers=auth).json()["id"]
    r = client.patch(
        f"/v1/conversations/{conv_id}",
        headers=auth,
        json={"title": "GDPR check on Anna"},
    )
    assert r.status_code == 200
    assert r.json()["title"] == "GDPR check on Anna"

    detail = client.get(f"/v1/conversations/{conv_id}", headers=auth).json()
    assert detail["title"] == "GDPR check on Anna"


def test_append_messages_persists_and_lists_in_order(client, auth):
    conv_id = client.post("/v1/conversations", headers=auth).json()["id"]
    client.post(
        f"/v1/conversations/{conv_id}/messages",
        headers=auth,
        json={"role": "user", "content": "hi"},
    )
    client.post(
        f"/v1/conversations/{conv_id}/messages",
        headers=auth,
        json={
            "role": "assistant",
            "content": "ciao",
            "tool_calls": [{"name": "postgres.query", "latency_ms": 286}],
            "trace_id": "t_xyz",
        },
    )

    detail = client.get(f"/v1/conversations/{conv_id}", headers=auth).json()
    assert [m["role"] for m in detail["messages"]] == ["user", "assistant"]
    assert detail["messages"][1]["content"] == "ciao"
    assert detail["messages"][1]["tool_calls"][0]["name"] == "postgres.query"
    assert detail["messages"][1]["trace_id"] == "t_xyz"


def test_append_rejects_invalid_role(client, auth):
    conv_id = client.post("/v1/conversations", headers=auth).json()["id"]
    r = client.post(
        f"/v1/conversations/{conv_id}/messages",
        headers=auth,
        json={"role": "hacker", "content": "x"},
    )
    assert r.status_code == 400


def test_delete_soft_removes_from_list(client, auth):
    conv_id = client.post("/v1/conversations", headers=auth).json()["id"]
    r = client.delete(f"/v1/conversations/{conv_id}", headers=auth)
    assert r.status_code == 204

    listing = client.get("/v1/conversations", headers=auth).json()
    assert conv_id not in [c["id"] for c in listing]
    # And direct fetch returns 404 (don't leak existence).
    assert client.get(f"/v1/conversations/{conv_id}", headers=auth).status_code == 404


def test_unknown_id_returns_404(client, auth):
    r = client.get("/v1/conversations/does-not-exist", headers=auth)
    assert r.status_code == 404
    r2 = client.patch(
        "/v1/conversations/does-not-exist",
        headers=auth,
        json={"title": "x"},
    )
    assert r2.status_code == 404
    r3 = client.delete("/v1/conversations/does-not-exist", headers=auth)
    assert r3.status_code == 404


def test_missing_bearer_rejected(client):
    r = client.post("/v1/conversations")
    assert r.status_code == 401


def test_list_pagination_bounds_validated(client, auth):
    assert client.get("/v1/conversations?limit=0", headers=auth).status_code == 400
    assert client.get("/v1/conversations?limit=101", headers=auth).status_code == 400
    assert client.get("/v1/conversations?offset=-1", headers=auth).status_code == 400
