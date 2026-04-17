"""
mTLS binding check at /auth/token (RFC 8705 §3).

Covers the four operational modes of settings.mtls_binding via the full
/v1/auth/token endpoint, so routing, rate-limit, DPoP, and check #13
interact exactly as in production.
"""
from __future__ import annotations

import urllib.parse

import pytest
from cryptography.hazmat.primitives import serialization
from httpx import AsyncClient

from app.config import get_settings
from tests.cert_factory import (
    get_org_ca_pem,
    make_agent_cert,
    make_assertion,
)
from tests.conftest import ADMIN_HEADERS, seed_court_agent


async def _prime_nonce(client: AsyncClient, dpop) -> None:
    """First request surfaces a DPoP-Nonce 401; capture it for the real call."""
    proof = dpop.proof("POST", "/v1/auth/token")
    await client.post("/v1/auth/token", json={"client_assertion": "x"},
                      headers={"DPoP": proof})


async def _register_agent(client: AsyncClient, agent_id: str, org_id: str) -> None:
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=['test.read'],
    )
    resp = await client.post(
        "/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(
        f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )


def _agent_cert_pem(agent_id: str, org_id: str) -> str:
    _, cert = make_agent_cert(agent_id, org_id)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _escape_pem(pem: str) -> str:
    """Mimic nginx $ssl_client_escaped_cert encoding (percent-encoded PEM)."""
    return urllib.parse.quote(pem, safe="")


@pytest.fixture
def mtls_mode(monkeypatch):
    """Set MTLS_BINDING for a single test; reset the settings cache so the
    new value is picked up by verify_client_assertion."""
    def _set(mode: str, header: str = "X-SSL-Client-Cert") -> None:
        monkeypatch.setenv("MTLS_BINDING", mode)
        monkeypatch.setenv("MTLS_CLIENT_CERT_HEADER", header)
        get_settings.cache_clear()
    yield _set
    get_settings.cache_clear()


async def _issue(client, dpop, agent_id, org_id, extra_headers=None):
    assertion = make_assertion(agent_id, org_id)
    proof = dpop.proof("POST", "/v1/auth/token")
    headers = {"DPoP": proof}
    if extra_headers:
        headers.update(extra_headers)
    return await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers=headers,
    )


async def test_mtls_off_ignores_mismatched_header(client, dpop, mtls_mode):
    mtls_mode("off")
    await _prime_nonce(client, dpop)
    await _register_agent(client, "mtls-off::a1", "mtls-off")
    resp = await _issue(client, dpop, "mtls-off::a1", "mtls-off",
                        extra_headers={"X-SSL-Client-Cert": "garbage"})
    assert resp.status_code == 200, resp.text


async def test_mtls_optional_without_header_allowed(client, dpop, mtls_mode):
    mtls_mode("optional")
    await _prime_nonce(client, dpop)
    await _register_agent(client, "mtls-opt-none::a1", "mtls-opt-none")
    resp = await _issue(client, dpop, "mtls-opt-none::a1", "mtls-opt-none")
    assert resp.status_code == 200, resp.text


async def test_mtls_optional_with_matching_header_allowed(client, dpop, mtls_mode):
    mtls_mode("optional")
    await _prime_nonce(client, dpop)
    await _register_agent(client, "mtls-opt-match::a1", "mtls-opt-match")
    cert_pem = _agent_cert_pem("mtls-opt-match::a1", "mtls-opt-match")
    resp = await _issue(
        client, dpop, "mtls-opt-match::a1", "mtls-opt-match",
        extra_headers={"X-SSL-Client-Cert": _escape_pem(cert_pem)},
    )
    assert resp.status_code == 200, resp.text


async def test_mtls_optional_with_mismatched_header_rejected(client, dpop, mtls_mode):
    mtls_mode("optional")
    await _prime_nonce(client, dpop)
    await _register_agent(client, "mtls-opt-mis::a1", "mtls-opt-mis")
    # A valid cert issued by the SAME org CA, but for a different agent.
    other_pem = _agent_cert_pem("mtls-opt-mis::a2", "mtls-opt-mis")
    resp = await _issue(
        client, dpop, "mtls-opt-mis::a1", "mtls-opt-mis",
        extra_headers={"X-SSL-Client-Cert": _escape_pem(other_pem)},
    )
    assert resp.status_code == 401
    assert "mTLS cert does not match" in resp.text


async def test_mtls_required_without_header_rejected(client, dpop, mtls_mode):
    mtls_mode("required")
    await _prime_nonce(client, dpop)
    await _register_agent(client, "mtls-req-none::a1", "mtls-req-none")
    resp = await _issue(client, dpop, "mtls-req-none::a1", "mtls-req-none")
    assert resp.status_code == 401
    assert "mTLS binding required" in resp.text


async def test_mtls_optional_malformed_header_rejected(client, dpop, mtls_mode):
    mtls_mode("optional")
    await _prime_nonce(client, dpop)
    await _register_agent(client, "mtls-opt-bad::a1", "mtls-opt-bad")
    resp = await _issue(
        client, dpop, "mtls-opt-bad::a1", "mtls-opt-bad",
        extra_headers={"X-SSL-Client-Cert": "not%20a%20real%20pem"},
    )
    assert resp.status_code == 401
    assert "malformed" in resp.text
