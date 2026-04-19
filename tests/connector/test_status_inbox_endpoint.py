"""Tests for the /status/inbox + /status/inbox/seen routes.

These exercise the dashboard FastAPI app with a stubbed dispatcher
in app.state — we don't need the real poller wired up because the
endpoint just reads a snapshot from the dispatcher object.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
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


def test_status_inbox_returns_zero_state_without_dispatcher(app):
    """Pre-enrolment dashboards have no dispatcher yet — endpoint
    must still return a stable shape for the statusline poller."""
    with TestClient(app) as client:
        # TestClient triggers lifespan; with no identity on disk the
        # dispatcher stays None.
        r = client.get("/status/inbox")
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
        r = client.get("/status/inbox")

    assert r.status_code == 200
    assert r.json() == fake.status_snapshot.return_value


def test_status_inbox_seen_calls_ack_when_dispatcher_present(app):
    fake = MagicMock()
    with TestClient(app) as client:
        app.state.inbox_dispatcher = fake
        r = client.post("/status/inbox/seen")
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    fake.ack.assert_called_once()


def test_status_inbox_seen_no_op_without_dispatcher(app):
    """Statusline scripts may call /seen before the dashboard has
    booted the dispatcher — must not 500."""
    with TestClient(app) as client:
        r = client.post("/status/inbox/seen")
    assert r.status_code == 200
    assert r.json() == {"ok": True}
