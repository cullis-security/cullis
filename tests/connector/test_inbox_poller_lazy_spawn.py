"""Tests for the lazy inbox-poller spawn (dogfood bug fix).

Reproduces the dogfood scenario:

  1. Operator runs ``cullis-connector dashboard`` while
     ``~/.cullis/profiles/<X>/identity/`` is still empty (e.g. first
     boot, or right after deleting the profile to redo enrollment).
  2. Lifespan calls ``_start_inbox_poller`` which sees no identity
     and returns ``None`` — ``app.state.inbox_poller`` stays ``None``.
  3. Operator completes enrollment in the browser; ``api_status``
     hits the approved branch, ``save_identity`` writes the cert.
  4. **Pre-fix**: poller stays ``None`` for the rest of the
     dashboard's life. No notifications arrive even though oneshots
     keep landing on the Mastio side. Operator has to kill+restart
     the dashboard to get notifications.
  5. **Post-fix**: ``api_status`` calls
     ``_ensure_inbox_poller_running`` which lazy-spawns the poller +
     dispatcher. Idempotent, so the next /api/status poll doesn't
     stack a second one.

These tests verify the helper's idempotence + the lifespan/handler
wiring without spinning up real poller threads (we monkey-patch
``_start_inbox_poller`` to return a fake instance).
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import cullis_connector.web as _web
from cullis_connector.config import ConnectorConfig
from cullis_connector.web import (
    _ensure_inbox_poller_running,
    build_app,
)


@pytest.fixture
def cfg(tmp_path) -> ConnectorConfig:
    return ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://fake-mastio.test:9443",
        verify_tls=False,
    )


@pytest.fixture
def fake_poller_factory(monkeypatch):
    """Replace ``_start_inbox_poller`` with a knob a test can flip
    so the same fixture covers both ``no-identity`` and
    ``identity-now-present``. Captures every fake poller for
    inspection."""
    state = {"identity_present": False, "spawned": []}

    def _factory(_config):
        if not state["identity_present"]:
            return None
        fake = MagicMock(name="DashboardInboxPoller")
        fake.start = MagicMock()
        fake.stop = MagicMock(return_value=None)
        state["spawned"].append(fake)
        return fake

    monkeypatch.setattr(_web, "_start_inbox_poller", _factory)
    # InboxDispatcher also gets faked because instantiating it would
    # try to read the poller's queue; we don't care about its
    # behaviour for this test, only that it gets started.
    fake_dispatcher_cls = MagicMock(name="InboxDispatcher")
    fake_dispatcher_cls.return_value.start = MagicMock()

    async def _stop(*a, **kw):
        return None

    fake_dispatcher_cls.return_value.stop = _stop
    monkeypatch.setattr(_web, "InboxDispatcher", fake_dispatcher_cls)
    # build_notifier shouldn't try to find notify-send during a unit
    # test; stub it out so we don't depend on the test runner's host.
    monkeypatch.setattr(_web, "build_notifier", lambda: MagicMock(name="Notifier"))
    return state


# ── _ensure_inbox_poller_running — idempotence + behaviour ──────────


def test_ensure_returns_false_when_no_identity(cfg, fake_poller_factory):
    """Pre-enrollment: helper must report ``False`` and leave
    ``inbox_poller`` as ``None`` so the next call can retry."""
    fake_poller_factory["identity_present"] = False
    app = build_app(cfg)
    # Lifespan didn't run in this unit-test path, so seed the state
    # the lifespan would have set to None.
    app.state.inbox_poller = None
    app.state.inbox_dispatcher = None
    assert _ensure_inbox_poller_running(app) is False
    assert app.state.inbox_poller is None
    assert app.state.inbox_dispatcher is None


def test_ensure_spawns_when_identity_appears(cfg, fake_poller_factory):
    """The dogfood scenario: identity arrives between dashboard boot
    and the next /api/status poll. Helper must build the poller +
    dispatcher and stash references on app.state."""
    app = build_app(cfg)
    app.state.inbox_poller = None
    app.state.inbox_dispatcher = None
    fake_poller_factory["identity_present"] = True
    assert _ensure_inbox_poller_running(app) is True
    assert app.state.inbox_poller is not None
    assert app.state.inbox_dispatcher is not None
    # The poller's start() hook must have been called exactly once.
    app.state.inbox_poller.start.assert_called_once()


def test_ensure_is_idempotent(cfg, fake_poller_factory):
    """Repeated calls (every /api/status poll once enrollment
    succeeds) must NOT stack a second poller — the LRU dedupe in the
    dispatcher would mostly absorb double events, but spawning extra
    background tasks every 3s would still be a leak."""
    app = build_app(cfg)
    app.state.inbox_poller = None
    app.state.inbox_dispatcher = None
    fake_poller_factory["identity_present"] = True
    assert _ensure_inbox_poller_running(app) is True
    first = app.state.inbox_poller
    assert _ensure_inbox_poller_running(app) is True
    assert app.state.inbox_poller is first
    # _start_inbox_poller called only once — second call short-
    # circuits before going to the factory again.
    assert len(fake_poller_factory["spawned"]) == 1


def test_ensure_returns_false_when_notifications_disabled(
    cfg, fake_poller_factory, monkeypatch,
):
    """Operators on headless / test boxes set
    ``CULLIS_CONNECTOR_NOTIFICATIONS=off``. The lazy spawn must
    respect that — otherwise we'd silently re-enable a thing the
    operator turned off."""
    monkeypatch.setenv("CULLIS_CONNECTOR_NOTIFICATIONS", "off")
    app = build_app(cfg)
    app.state.inbox_poller = None
    app.state.inbox_dispatcher = None
    fake_poller_factory["identity_present"] = True
    assert _ensure_inbox_poller_running(app) is False
    assert app.state.inbox_poller is None


# ── api_status integration — the wire-up that closes the bug ───────


def test_api_status_lazy_spawns_when_identity_already_on_disk(
    cfg, fake_poller_factory, monkeypatch,
):
    """Identity already saved (e.g. operator reloaded the page after
    enrollment) → /api/status hits the has_identity short-circuit
    AND lazy-spawns the poller. Pre-fix, that branch returned without
    touching app.state, leaving the poller dead forever."""
    monkeypatch.setattr(_web, "has_identity", lambda _: True)
    fake_poller_factory["identity_present"] = True
    client = TestClient(build_app(cfg))
    resp = client.get("/api/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"
    # The TestClient app instance is what got mutated — fetch it
    # back via app reference. ``client.app`` is the FastAPI app.
    assert client.app.state.inbox_poller is not None
    client.app.state.inbox_poller.start.assert_called_once()
