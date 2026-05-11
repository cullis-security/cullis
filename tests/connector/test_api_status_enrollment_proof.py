"""Regression test for the dashboard /api/status poll header.

Pre-fix, the FastAPI dashboard's ``/api/status`` polling endpoint
called Mastio's ``/v1/enrollment/{ticket}/status`` WITHOUT the
``X-Enrollment-Proof`` header. The CLI poll path
(``cullis_connector.enrollment``) had always sent it. Mastio's
M-onb-1 audit hardening gates ``cert_pem`` / ``agent_id`` /
``capabilities`` behind the proof, so the dashboard-driven enrollment
got stuck reporting "Approved enrollment is missing cert_pem." even
after the admin had approved the ticket — customer-path SPA chat
never came online.

These tests pin the contract: when ``_pending`` is set,
``/api/status`` MUST include ``X-Enrollment-Proof``, and the proof
must verify against the pending keypair so a future refactor that
changes the canonical string also re-aligns the verifier.
"""
from __future__ import annotations

import base64
import time

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from cullis_connector import web as connector_web
from cullis_connector.config import ConnectorConfig
from cullis_connector.web import RequesterInfo, build_app


@pytest.fixture
def app(tmp_path):
    cfg = ConnectorConfig(
        site_url="https://mastio.test",
        config_dir=tmp_path,
        verify_tls=False,
        request_timeout_s=2.0,
    )
    return build_app(cfg)


@pytest.fixture
def pending_session():
    """Install a ``_Pending`` module-global as if the wizard had just
    submitted the enrollment request."""
    key = ec.generate_private_key(ec.SECP256R1())
    prev = connector_web._pending
    connector_web._pending = connector_web._Pending(
        session_id="ticket-abc-123",
        enroll_url="https://mastio.test/v1/enrollment/ticket-abc-123",
        site_url="https://mastio.test",
        verify_tls=False,
        private_key=key,
        requester=RequesterInfo(name="demo", email="demo@cullis.local", reason="t"),
        started_at=time.time(),
    )
    yield connector_web._pending
    connector_web._pending = prev


def _intercept_httpx_get(monkeypatch, body: dict):
    """Replace ``cullis_connector.web.httpx.get`` with a stub that captures
    the call and returns ``body`` as JSON. Returns the captured-call dict.

    ``headers`` is wrapped in :class:`httpx.Headers` so the test can do
    case-insensitive lookups (HTTP headers are case-insensitive on the
    wire; the production code passes a plain dict with ``X-...`` casing
    and we want either ``X-Enrollment-Proof`` or ``x-enrollment-proof``
    to match in assertions)."""
    captured: dict = {}

    def _fake_get(url, *, headers=None, verify=None, timeout=None, **kwargs):
        captured["url"] = url
        captured["headers"] = httpx.Headers(headers or {})
        return httpx.Response(200, json=body, request=httpx.Request("GET", url))

    monkeypatch.setattr(connector_web.httpx, "get", _fake_get)
    return captured


def test_api_status_sends_enrollment_proof_header(monkeypatch, app, pending_session):
    """Mastio gets the PoP header on every dashboard poll. This is the
    direct regression test for Bug #5 — pre-fix the header was missing
    and Mastio withheld ``cert_pem``."""
    captured = _intercept_httpx_get(
        monkeypatch,
        body={"session_id": pending_session.session_id, "status": "pending"},
    )

    with TestClient(app) as client:
        resp = client.get("/api/status")

    assert resp.status_code == 200
    assert captured["url"].endswith(
        f"/v1/enrollment/{pending_session.session_id}/status",
    )
    proof = captured["headers"].get("x-enrollment-proof")
    assert proof, (
        "/api/status MUST send X-Enrollment-Proof; without it Mastio "
        "withholds cert_pem and the dashboard loops forever on "
        "'Approved enrollment is missing cert_pem' (Bug #5)"
    )
    assert len(proof) >= 32


def test_api_status_proof_verifies_against_pending_pubkey(
    monkeypatch, app, pending_session,
):
    """The proof we send must be the same shape Mastio's
    ``_verify_enrollment_proof`` accepts: P-256 ECDSA, base64url-encoded,
    over ``enrollment-status:v1|{session_id}``. Round-trip verify the
    signature so future refactors to the canonical string fail loud."""
    captured = _intercept_httpx_get(
        monkeypatch,
        body={"session_id": pending_session.session_id, "status": "pending"},
    )

    with TestClient(app) as client:
        client.get("/api/status")

    proof_b64 = captured["headers"].get("x-enrollment-proof", "")
    # base64url with optional padding.
    pad = "=" * (-len(proof_b64) % 4)
    sig = base64.urlsafe_b64decode(proof_b64 + pad)
    canonical = f"enrollment-status:v1|{pending_session.session_id}".encode()
    pubkey = pending_session.private_key.public_key()
    pubkey.verify(sig, canonical, ec.ECDSA(hashes.SHA256()))


def test_api_status_approved_path_persists_identity(
    monkeypatch, app, pending_session,
):
    """When Mastio returns the approved record with ``cert_pem``
    (which it only does when the proof verifies), the dashboard
    writes the identity to disk and the endpoint flips to
    ``status=approved``. Pre-fix, ``cert_pem`` came back null forever
    and the endpoint surfaced the 'missing cert_pem' error string."""
    cert_pem = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkDCCATagAwIBAgIUf+pVLzc8H9DZbm6FvCnD+sUEMcMwCgYIKoZIzj0EAwIw\n"
        "-----END CERTIFICATE-----\n"
    )
    _intercept_httpx_get(
        monkeypatch,
        body={
            "session_id": pending_session.session_id,
            "status": "approved",
            "agent_id": "test-org::test-agent",
            "cert_pem": cert_pem,
            "capabilities": ["chat.query"],
        },
    )

    with TestClient(app) as client:
        resp = client.get("/api/status")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "approved", body
    # ``_pending`` is cleared once the identity hits disk.
    assert connector_web._pending is None
