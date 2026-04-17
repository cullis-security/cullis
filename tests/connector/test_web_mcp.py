"""Connector dashboard MCP resource registration screen (ADR-009 sandbox).

Drives the Connector FastAPI app against a mocked Mastio (httpx
MockTransport) so the web-layer tests don't need a real broker.
"""
from __future__ import annotations

import datetime as _dt
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.identity.store import IdentityBundle, IdentityMetadata
from cullis_connector.web import build_app


@pytest.fixture
def connector_dir(tmp_path):
    d = tmp_path / "connector"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def connector_client(connector_dir, monkeypatch):
    """Boot a Connector app with a fake enrolled identity, no disk writes."""
    meta = IdentityMetadata(
        agent_id="demo-org::alice",
        capabilities=["oneshot.message"],
        site_url="http://mastio.test",
        issued_at=_dt.datetime.now(_dt.timezone.utc).isoformat(),
    )
    bundle = IdentityBundle(
        private_key=None,
        cert=None,
        cert_pem="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        ca_chain_pem=None,
        metadata=meta,
    )
    import cullis_connector.web as _web
    monkeypatch.setattr(_web, "has_identity", lambda _: True)
    monkeypatch.setattr(_web, "load_identity", lambda _: bundle)
    _web._set_admin_secret(None)

    cfg = ConnectorConfig(
        config_dir=connector_dir,
        site_url="http://mastio.test",
        verify_tls=False,
    )
    app = build_app(cfg)
    return TestClient(app)


def _mount_mastio(monkeypatch, handler):
    """Patch httpx.Client inside web.py so every call goes to ``handler``."""
    import cullis_connector.web as _web

    original = _web.httpx.Client

    def _factory(*args, **kwargs):
        kwargs.setdefault("transport", httpx.MockTransport(handler))
        return original(*args, **kwargs)

    monkeypatch.setattr(_web.httpx, "Client", _factory)


# ── admin secret gating ────────────────────────────────────────────────

def test_mcp_screen_prompts_for_admin_secret(connector_client):
    r = connector_client.get("/mcp")
    assert r.status_code == 200
    assert "Mastio admin secret" in r.text


def test_mcp_screen_shows_unlocked_after_secret_set(connector_client, monkeypatch):
    captured_requests: list[httpx.Request] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        captured_requests.append(req)
        if req.url.path == "/v1/admin/mcp-resources" and req.method == "GET":
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    _mount_mastio(monkeypatch, _handler)

    r = connector_client.post(
        "/mcp/admin-secret",
        data={"admin_secret": "demo-proxy-admin"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    r = connector_client.get("/mcp")
    assert r.status_code == 200
    assert "Admin mode unlocked" in r.text
    assert any(
        "x-admin-secret" in dict(req.headers)
        for req in captured_requests
    )


# ── register resource ──────────────────────────────────────────────────

def test_register_resource_round_trip(connector_client, monkeypatch):
    recorded: list[tuple[str, dict]] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/v1/admin/mcp-resources":
            body = json.loads(req.content)
            recorded.append(("POST", body))
            return httpx.Response(
                201,
                json={
                    "resource_id": "fake-uuid-1",
                    "name": body["name"],
                    "endpoint_url": body["endpoint_url"],
                    "description": body.get("description"),
                    "auth_type": "none",
                    "required_capability": body.get("required_capability"),
                    "enabled": True,
                    "org_id": body.get("org_id"),
                    "created_at": "2026-04-17T00:00:00+00:00",
                },
            )
        if req.method == "GET" and req.url.path == "/v1/admin/mcp-resources":
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    _mount_mastio(monkeypatch, _handler)

    connector_client.post(
        "/mcp/admin-secret", data={"admin_secret": "demo"},
    )
    r = connector_client.post(
        "/mcp/register",
        data={
            "name": "catalog",
            "endpoint_url": "http://mcp-catalog:9300/",
            "description": "Catalog",
            "required_capability": "",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303

    assert recorded, "POST to Mastio was not issued"
    _, body = recorded[0]
    assert body["name"] == "catalog"
    assert body["endpoint_url"] == "http://mcp-catalog:9300/"
    # agent_id is demo-org::alice so org_id derives as "demo-org"
    assert body.get("org_id") == "demo-org"


def test_register_without_admin_secret_redirects_with_error(
    connector_client, monkeypatch,
):
    r = connector_client.post(
        "/mcp/register",
        data={"name": "x", "endpoint_url": "http://x/"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "error=admin" in r.headers["location"]


def test_register_forwards_409_conflict(connector_client, monkeypatch):
    def _handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path == "/v1/admin/mcp-resources":
            return httpx.Response(409, json={"detail": "exists"})
        return httpx.Response(200, json=[])

    _mount_mastio(monkeypatch, _handler)
    connector_client.post("/mcp/admin-secret", data={"admin_secret": "demo"})
    r = connector_client.post(
        "/mcp/register",
        data={"name": "dup", "endpoint_url": "http://x/"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "already+exists" in r.headers["location"]


# ── bind-self ─────────────────────────────────────────────────────────

def test_bind_self_sends_agent_id(connector_client, monkeypatch):
    recorded: list[dict] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        if (req.method == "POST"
                and req.url.path == "/v1/admin/mcp-resources/bindings"):
            recorded.append(json.loads(req.content))
            return httpx.Response(
                201,
                json={
                    "binding_id": "b1",
                    "agent_id": json.loads(req.content)["agent_id"],
                    "resource_id": json.loads(req.content)["resource_id"],
                    "org_id": "demo-org",
                    "granted_at": "now",
                    "revoked_at": None,
                },
            )
        return httpx.Response(200, json=[])

    _mount_mastio(monkeypatch, _handler)
    connector_client.post("/mcp/admin-secret", data={"admin_secret": "demo"})
    r = connector_client.post(
        "/mcp/fake-uuid-1/bind-self", follow_redirects=False,
    )
    assert r.status_code == 303
    assert recorded
    assert recorded[0]["agent_id"] == "demo-org::alice"
    assert recorded[0]["resource_id"] == "fake-uuid-1"
