"""Tests for the /waiting dashboard page.

Pinning behaviour the dogfood Finding #4 cared about: the user who
just submitted an enrollment request must see a discoverable link to
``<site>/proxy/enrollments`` so they (or their admin colleague) know
where to go to approve. Before this fix the page only displayed an
opaque enroll URL and the operator had to hunt for the admin UI by
hand.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

import cullis_connector.web as _web
from cullis_connector.config import ConnectorConfig
from cullis_connector.enrollment import RequesterInfo
from cullis_connector.web import _Pending, build_app


@pytest.fixture
def cfg(tmp_path) -> ConnectorConfig:
    return ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://fake-mastio.test:9443",
        verify_tls=True,
    )


@pytest.fixture
def client(cfg, monkeypatch) -> TestClient:
    monkeypatch.setattr(_web, "has_identity", lambda _: False)
    return TestClient(build_app(cfg))


@pytest.fixture
def with_pending(monkeypatch):
    """Inject a fake _pending so /waiting renders instead of redirecting."""
    pending = _Pending(
        session_id="abcdef0123456789",
        enroll_url="https://fake-mastio.test:9443/v1/enrollment/abcdef0123456789",
        site_url="https://fake-mastio.test:9443",
        verify_tls=True,
        private_key=ec.generate_private_key(ec.SECP256R1()),
        requester=RequesterInfo(name="alice", email="alice@example.test"),
    )
    monkeypatch.setattr(_web, "_pending", pending)
    return pending


def test_waiting_page_shows_admin_enrollments_link(client, with_pending):
    """The waiting page must surface the absolute admin URL so the
    operator doesn't need to guess where pending enrollments live."""
    resp = client.get("/waiting")
    assert resp.status_code == 200
    body = resp.text
    assert "https://fake-mastio.test:9443/proxy/enrollments" in body
    # Hyperlink, not raw text — the operator has to be able to click it.
    assert 'id="admin-enrollments-link"' in body
    assert 'href="https://fake-mastio.test:9443/proxy/enrollments"' in body


def test_waiting_page_strips_trailing_slash_on_site_url(monkeypatch, client):
    """Operators paste site URLs with or without a trailing slash; the
    deep-link must not produce ``//proxy/enrollments``."""
    pending = _Pending(
        session_id="abcdef0123456789",
        enroll_url="https://fake-mastio.test:9443/v1/enrollment/abcdef0123456789",
        site_url="https://fake-mastio.test:9443/",  # trailing slash
        verify_tls=True,
        private_key=ec.generate_private_key(ec.SECP256R1()),
        requester=RequesterInfo(name="alice", email="alice@example.test"),
    )
    monkeypatch.setattr(_web, "_pending", pending)
    resp = client.get("/waiting")
    assert resp.status_code == 200
    assert "https://fake-mastio.test:9443/proxy/enrollments" in resp.text
    assert "9443//proxy" not in resp.text
