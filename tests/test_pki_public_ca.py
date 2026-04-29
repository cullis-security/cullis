"""Tests for ``GET /pki/ca.crt`` — the anonymous Org CA endpoint
used by Connector first-contact for TOFU pinning.
"""
from __future__ import annotations

import hashlib
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter
from mcp_proxy.pki.public import router as pki_router


_FAKE_CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBcjCCARigAwIBAgIUDummyCAforTOFUtestNotARealCert\n"
    "-----END CERTIFICATE-----\n"
)


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Each test starts with a clean rate-limit window — otherwise a
    burst test below would inherit counters from earlier tests."""
    reset_agent_rate_limiter()
    yield
    reset_agent_rate_limiter()


def _client_with_ca(pem: str | None) -> TestClient:
    app = FastAPI()
    app.include_router(pki_router)
    # Patch ``get_config`` at import location — the router resolved
    # the symbol at module-load, so we monkey-patch where it's called.
    async def _fake_get_config(key: str) -> str | None:
        assert key == "org_ca_cert"
        return pem
    patcher = patch("mcp_proxy.pki.public.get_config", _fake_get_config)
    patcher.start()
    app.state._patcher = patcher  # keep alive for the test client lifetime
    return TestClient(app)


def test_returns_pem_when_ca_configured():
    """Happy path: org_ca_cert in config → 200 with the PEM body and
    PEM media type."""
    with _client_with_ca(_FAKE_CA_PEM) as client:
        resp = client.get("/pki/ca.crt")
        assert resp.status_code == 200
        assert resp.text == _FAKE_CA_PEM
        assert resp.headers["content-type"].startswith("application/x-pem-file")
        assert "Cache-Control" in resp.headers
        assert "max-age=300" in resp.headers["Cache-Control"]


def test_returns_404_when_no_ca_configured():
    """Pre-setup state: caller knows to retry after operator finishes
    first-boot rather than receiving a stale-looking empty 200."""
    with _client_with_ca(None) as client:
        resp = client.get("/pki/ca.crt")
        assert resp.status_code == 404


def test_etag_strong_matches_returns_304():
    """Well-behaved client caches body, polls with If-None-Match,
    expects 304 Not Modified — saves bandwidth on stable CA."""
    with _client_with_ca(_FAKE_CA_PEM) as client:
        first = client.get("/pki/ca.crt")
        assert first.status_code == 200
        etag = first.headers["ETag"]

        second = client.get("/pki/ca.crt", headers={"If-None-Match": etag})
        assert second.status_code == 304
        # 304 responses MUST NOT include a body per RFC 7232.
        assert second.content == b""


def test_etag_changes_when_pem_changes():
    """Different CA PEM → different ETag (strong validator). A rotation
    on the server must invalidate every cached client."""
    with _client_with_ca(_FAKE_CA_PEM) as c1:
        etag_a = c1.get("/pki/ca.crt").headers["ETag"]
    different = _FAKE_CA_PEM.replace("Dummy", "Rotated")
    with _client_with_ca(different) as c2:
        etag_b = c2.get("/pki/ca.crt").headers["ETag"]
    assert etag_a != etag_b


def test_endpoint_is_anonymous():
    """No auth header, no client cert, no session cookie — request
    must succeed. This is the whole point of the bootstrap endpoint."""
    with _client_with_ca(_FAKE_CA_PEM) as client:
        # Explicitly verify no auth-related state on the request.
        resp = client.get("/pki/ca.crt")
        assert resp.status_code == 200


def test_etag_is_sha256_of_pem():
    """Defence in depth: the ETag must be derived from the PEM bytes,
    not from a server-side counter that could collide on rotation."""
    with _client_with_ca(_FAKE_CA_PEM) as client:
        resp = client.get("/pki/ca.crt")
        digest = hashlib.sha256(_FAKE_CA_PEM.encode()).hexdigest()[:32]
        assert resp.headers["ETag"] == f'"{digest}"'
