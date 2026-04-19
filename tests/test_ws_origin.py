"""Audit F-B-13 — WebSocket origin must not accept the wildcard.

The legacy /broker/ws handler had an allow-list branch that let ``*``
through as "allow everything" on the upgrade. CORSMiddleware does not
cover the WS handshake, so a cross-site page could open a ws:// to the
broker and replay the user's auth (no CORS, no SameSite help here).
The fix enumerates explicit origins, refuses wildcard, and lets only
localhost in dev when no allow-list is configured.

Also exercises ``validate_config`` production refusal on ``ALLOWED_ORIGINS=*``.
"""
from __future__ import annotations

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.broker.router import _is_localhost_origin
from app.config import Settings, validate_config


# ── Unit: _is_localhost_origin ────────────────────────────────────────


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost",
        "http://localhost:8000",
        "https://localhost:8443",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "https://127.0.0.1:9443",
    ],
)
def test_is_localhost_origin_accepts_localhost_variants(origin):
    assert _is_localhost_origin(origin) is True


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "*",
        "http://evil.com",
        "https://evil.com:443",
        "http://localhost.evil.com",  # suffix-attack
        "http://127.0.0.1.evil.com",
        "http://[::1]",               # IPv6 not in the narrow exemption
        "file:///tmp/x",
        "null",
        "localhost",                  # no scheme
        "http://127.0.0.2",
    ],
)
def test_is_localhost_origin_rejects_everything_else(origin):
    assert _is_localhost_origin(origin) is False


# ── Integration: /v1/broker/ws closes 1008 on bad origin ──────────────


def _connect_and_expect_close(client: TestClient, origin: str | None):
    """Open /v1/broker/ws with the given Origin. Return True iff the
    server closed before we could send the auth frame."""
    headers = {"origin": origin} if origin is not None else {}
    try:
        with client.websocket_connect(
            "/v1/broker/ws", headers=headers,
        ) as ws:
            # If we get here, the server accepted the socket. Try a send
            # — if it was immediately closed we'll hit WebSocketDisconnect.
            try:
                ws.send_json({"type": "auth", "token": "x"})
                ws.receive_json(timeout=1)
                return False  # server accepted and kept it open
            except WebSocketDisconnect:
                return True
    except WebSocketDisconnect:
        # Server closed before even entering the context manager.
        return True


def test_ws_rejects_wildcard_origin_explicit(monkeypatch):
    """Even if an operator stuffs ``ALLOWED_ORIGINS=*`` into prod by
    accident, the WS handler closes the socket without reaching auth."""
    from app.config import get_settings
    monkeypatch.setenv("ALLOWED_ORIGINS", "*")
    monkeypatch.setenv("ENVIRONMENT", "development")  # so validate_config
                                                      # doesn't kill boot
    get_settings.cache_clear()
    try:
        from app.main import app
        with TestClient(app) as client:
            # "Any" origin — wildcard in the allow-list means the handler
            # should reject regardless.
            assert _connect_and_expect_close(client, "https://evil.example") is True
    finally:
        get_settings.cache_clear()


def test_ws_rejects_unknown_origin_when_allowlist_set(monkeypatch):
    from app.config import get_settings
    monkeypatch.setenv(
        "ALLOWED_ORIGINS", "https://console.example.com,https://broker.example.com",
    )
    monkeypatch.setenv("ENVIRONMENT", "development")
    get_settings.cache_clear()
    try:
        from app.main import app
        with TestClient(app) as client:
            assert _connect_and_expect_close(client, "https://evil.example") is True
    finally:
        get_settings.cache_clear()


def test_ws_rejects_unknown_origin_dev_no_allowlist(monkeypatch):
    """Dev mode + no allow-list + non-localhost origin → rejected."""
    from app.config import get_settings
    monkeypatch.setenv("ALLOWED_ORIGINS", "")
    monkeypatch.setenv("ENVIRONMENT", "development")
    get_settings.cache_clear()
    try:
        from app.main import app
        with TestClient(app) as client:
            assert _connect_and_expect_close(client, "https://evil.example") is True
    finally:
        get_settings.cache_clear()


def test_ws_accepts_localhost_origin_dev_no_allowlist(monkeypatch):
    """Dev + no allow-list + localhost origin → upgrade proceeds.

    The handshake reaches the auth step (which of course fails with our
    dummy token); we just want to prove the origin gate let us through.
    """
    from app.config import get_settings
    monkeypatch.setenv("ALLOWED_ORIGINS", "")
    monkeypatch.setenv("ENVIRONMENT", "development")
    get_settings.cache_clear()
    try:
        from app.main import app
        with TestClient(app) as client:
            with client.websocket_connect(
                "/v1/broker/ws",
                headers={"origin": "http://localhost:8080"},
            ) as ws:
                # Server is waiting for the auth frame. Send garbage; we
                # should get a JSON auth_error reply back (not a raw
                # close), which proves we got past the origin gate.
                ws.send_json({"type": "auth", "token": "bogus"})
                data = ws.receive_json()
                assert data.get("type") == "auth_error"
    finally:
        get_settings.cache_clear()


# ── validate_config: prod refuses wildcard ────────────────────────────


def _prod_settings(**overrides) -> Settings:
    base = dict(
        environment="production",
        admin_secret="strong-random-admin-secret",
        database_url="postgresql+asyncpg://u:p@db/cullis",
        broker_ca_key_path="certs/broker-ca-key.pem",
        dashboard_signing_key="strong-signing-key",
        redis_url="redis://redis:6379/0",
        kms_backend="vault",
    )
    base.update(overrides)
    return Settings(**base)


def test_validate_config_prod_refuses_wildcard_allowed_origins(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_settings(
        allowed_origins="*",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_prod_refuses_wildcard_mixed_in_list(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_settings(
        allowed_origins="https://legit.example.com,*",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_prod_accepts_explicit_allowed_origins(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_settings(
        allowed_origins="https://console.example.com,https://broker.example.com",
        broker_ca_key_path=str(ca_key),
    )
    # Must not raise.
    validate_config(settings)


def test_validate_config_dev_allows_wildcard_with_warning(tmp_path, caplog):
    settings = Settings(
        environment="development",
        admin_secret="strong-random-admin-secret",
        allowed_origins="*",
    )
    # Dev keeps the legacy warning, doesn't refuse.
    validate_config(settings)


# ── Proxy: validate_config analogue ───────────────────────────────────


def test_proxy_validate_config_prod_refuses_wildcard_allowed_origins():
    from mcp_proxy.config import ProxySettings, validate_config as proxy_validate_config

    settings = ProxySettings(
        environment="production",
        admin_secret="strong-random-admin-secret",
        broker_jwks_url="https://broker.example.com/.well-known/jwks.json",
        secret_backend="vault",
        vault_verify_tls=True,
        dashboard_signing_key="strong-signing-key",
        allowed_origins="*",
    )
    with pytest.raises(SystemExit):
        proxy_validate_config(settings)
