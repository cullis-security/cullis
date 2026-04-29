"""Tests for the /status/inbox + /status/inbox/seen routes.

These exercise the dashboard FastAPI app with a stubbed dispatcher
in app.state — we don't need the real poller wired up because the
endpoint just reads a snapshot from the dispatcher object.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.statusline_token import read_statusline_token
from cullis_connector.web import build_app


@pytest.fixture
def app(tmp_path):
    cfg = ConnectorConfig(
        site_url="http://mastio.test",
        config_dir=tmp_path,
        verify_tls=False,
        request_timeout_s=2.0,
    )
    app = build_app(cfg)
    return app


def _auth_headers(app) -> dict[str, str]:
    """Pull the token the lifespan seeded so each test can authorise."""
    token = app.state.statusline_token
    return {"Authorization": f"Bearer {token}"}


def test_status_inbox_returns_zero_state_without_dispatcher(app):
    """Pre-enrolment dashboards have no dispatcher yet — endpoint
    must still return a stable shape for the statusline poller."""
    with TestClient(app) as client:
        # TestClient triggers lifespan; with no identity on disk the
        # dispatcher stays None.
        r = client.get("/status/inbox", headers=_auth_headers(app))
    assert r.status_code == 200
    body = r.json()
    assert body == {
        "unread": 0,
        "last_sender": None,
        "last_preview": None,
        "last_received_at": None,
        "total_seen": 0,
    }


def test_status_inbox_returns_dispatcher_snapshot(app):
    """Inject a fake dispatcher and verify the endpoint surfaces
    its status_snapshot() verbatim."""
    fake = MagicMock()
    # Lifespan now drains the dispatcher on shutdown via ``await
    # dispatcher.stop()`` (so lazy-spawned ones from /api/status are
    # also cleaned up). Inject an awaitable stop on the fake.
    fake.stop = AsyncMock(return_value=None)
    fake.status_snapshot.return_value = {
        "unread": 3,
        "last_sender": "acme::mario",
        "last_preview": "ciao!",
        "last_received_at": "2026-04-19T11:00:00+00:00",
        "total_seen": 7,
    }

    with TestClient(app) as client:
        # Override after lifespan startup.
        app.state.inbox_dispatcher = fake
        r = client.get("/status/inbox", headers=_auth_headers(app))

    assert r.status_code == 200
    assert r.json() == fake.status_snapshot.return_value


def test_status_inbox_seen_calls_ack_when_dispatcher_present(app):
    fake = MagicMock()
    fake.stop = AsyncMock(return_value=None)
    with TestClient(app) as client:
        app.state.inbox_dispatcher = fake
        r = client.post("/status/inbox/seen", headers=_auth_headers(app))
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    fake.ack.assert_called_once()


def test_status_inbox_seen_no_op_without_dispatcher(app):
    """Statusline scripts may call /seen before the dashboard has
    booted the dispatcher — must not 500."""
    with TestClient(app) as client:
        r = client.post("/status/inbox/seen", headers=_auth_headers(app))
    assert r.status_code == 200
    assert r.json() == {"ok": True}


# ── Auth guard tests (NEW #1 – statusline bearer token) ─────────────────


def test_status_inbox_rejects_missing_auth(app):
    with TestClient(app) as client:
        r = client.get("/status/inbox")
    assert r.status_code == 401


def test_status_inbox_rejects_wrong_token(app):
    with TestClient(app) as client:
        r = client.get(
            "/status/inbox",
            headers={"Authorization": "Bearer not-the-right-token"},
        )
    assert r.status_code == 401


def test_status_inbox_seen_rejects_missing_auth_cannot_reset_counter(app):
    """Without auth, a local attacker must NOT be able to ack the
    dispatcher and hide unread messages from the user."""
    fake = MagicMock()
    fake.stop = AsyncMock(return_value=None)
    with TestClient(app) as client:
        app.state.inbox_dispatcher = fake
        r = client.post("/status/inbox/seen")
    assert r.status_code == 401
    fake.ack.assert_not_called()


def test_statusline_token_persisted_chmod_0600(tmp_path, app):
    """The token file must land at <identity>/statusline.token 0600."""
    import stat

    with TestClient(app):
        pass  # trigger lifespan

    token = read_statusline_token(tmp_path)
    assert token
    token_path = tmp_path / "identity" / "statusline.token"
    assert token_path.exists()
    mode = stat.S_IMODE(token_path.stat().st_mode)
    assert mode & 0o077 == 0, f"statusline.token must be owner-only, got {oct(mode)}"


def test_statusline_token_stable_across_restarts(tmp_path):
    """Two build_app() runs over the same config_dir reuse the token."""
    cfg = ConnectorConfig(
        site_url="http://mastio.test",
        config_dir=tmp_path,
        verify_tls=False,
        request_timeout_s=2.0,
    )
    app1 = build_app(cfg)
    with TestClient(app1):
        t1 = app1.state.statusline_token

    app2 = build_app(cfg)
    with TestClient(app2):
        t2 = app2.state.statusline_token

    assert t1 == t2
