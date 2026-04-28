"""ADR-014 PR-B — unit tests for ``get_agent_from_client_cert``.

Drives the auth path that nginx in front of the Mastio feeds via
``X-SSL-Client-Cert`` + ``X-SSL-Client-Verify``. Most of the existing
egress / agents tests exercise this dep transitively via the FastAPI
routes; this file pins the contract directly so future refactors of
the parsing or pinning logic don't silently break.
"""
from __future__ import annotations

import urllib.parse
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient

from tests._mtls_helpers import (
    _build_test_ca,
    mint_agent_cert,
    mtls_headers,
    provision_internal_agent,
)


# ─────────────────────────────────────────────────────────────────────────────
# App fixture (matches the shape of the rest of the proxy unit tests)
# ─────────────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")
    monkeypatch.delenv("PROXY_TRANSPORT_INTRA_ORG", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


# ─────────────────────────────────────────────────────────────────────────────
# Direct dep tests — exercising ``get_agent_from_client_cert``
# ─────────────────────────────────────────────────────────────────────────────


def _request_with_headers(headers: dict[str, str]):
    """Stub a starlette Request with just ``.headers`` and ``.url`` — the
    cert dep only reads those, so we don't need the full ASGI surface."""
    request = MagicMock()
    request.headers = headers
    request.url.path = "/v1/egress/peers"
    return request


@pytest.mark.asyncio
async def test_happy_path_authenticates(proxy_app):
    headers = await provision_internal_agent("alice")
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_rejects_missing_verify_header(proxy_app):
    """Defence-in-depth: even with a parseable cert, a missing/wrong
    ``X-SSL-Client-Verify`` is rejected. nginx never reaches mcp-proxy
    without the SUCCESS marker on mTLS-required locations, but a caller
    that bypasses nginx (internal docker net) would skip it."""
    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="alice")
    headers = {
        "X-SSL-Client-Cert": urllib.parse.quote(cert_pem, safe=""),
        # Verify header deliberately missing.
    }
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    assert "verified" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rejects_missing_cert_header(proxy_app):
    headers = {"X-SSL-Client-Verify": "SUCCESS"}
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rejects_garbage_pem(proxy_app):
    headers = {
        "X-SSL-Client-Cert": "not-a-pem",
        "X-SSL-Client-Verify": "SUCCESS",
    }
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    assert "PEM" in resp.json()["detail"] or "valid" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rejects_unknown_agent(proxy_app):
    """Cert parses fine, SAN says ``acme::stranger``, but no row exists."""
    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="stranger")
    headers = mtls_headers(cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    assert "unknown" in resp.json()["detail"].lower() or "inactive" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_rejects_inactive_agent(proxy_app):
    headers = await provision_internal_agent("retired", is_active=False)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rejects_org_mismatch(proxy_app):
    """Mastio's org_id is ``acme``; a cert claiming ``foreign`` is denied
    even if it parses cleanly. Closes the cross-tenant impersonation
    risk a future shared-CA deploy could open."""
    cert_pem, _ = mint_agent_cert(org_id="foreign", agent_name="alice")
    headers = mtls_headers(cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rejects_cert_pin_mismatch(proxy_app):
    """A cert that chains to the Org CA but isn't the one stored in the
    DB row fails the leaf-DER pin even when the SPIFFE identity matches.
    Mirror of the rotated-cert / off-band-mint defence."""
    # Provision under one cert, then mint a NEW cert with the same SAN
    # but a different keypair — the row's stored cert_pem stays stale.
    real_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="alice")
    fake_cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="alice")
    # Insert with the real cert so the row exists.
    from mcp_proxy.db import create_agent
    await create_agent(
        agent_id="acme::alice",
        display_name="alice",
        capabilities=["cap.read"],
        cert_pem=real_cert_pem,
    )
    # Authenticate with the second cert that was never stored.
    headers = mtls_headers(fake_cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 401
    assert "match" in resp.json()["detail"].lower() or "registered" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_cn_fallback_when_san_missing(proxy_app, monkeypatch):
    """Legacy certs without the SPIFFE SAN extension fall back to the
    canonical CN ``<org>::<name>``. Exercise the CN-only branch by
    minting a cert without the SAN extension."""
    ca_key, ca_cert = _build_test_ca()
    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "acme::legacy"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "acme"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        # No SubjectAlternativeName extension → forces the CN fallback.
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    # Insert the matching row.
    from mcp_proxy.db import create_agent
    await create_agent(
        agent_id="acme::legacy",
        display_name="legacy",
        capabilities=["cap.read"],
        cert_pem=cert_pem,
    )
    headers = mtls_headers(cert_pem)
    _, client = proxy_app
    resp = await client.get("/v1/egress/peers", headers=headers)
    assert resp.status_code == 200, resp.text
