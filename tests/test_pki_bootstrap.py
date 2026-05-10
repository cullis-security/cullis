"""Tests for ``GET /.well-known/cullis/connector-bootstrap`` — the
anonymous metadata endpoint a Frontdesk Connector probes against
candidate Mastio URLs during its first-boot setup wizard.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.auth.rate_limit import reset_agent_rate_limiter
from mcp_proxy.pki.bootstrap import router as bootstrap_router


def _self_signed_pem() -> tuple[str, str]:
    """Build a throwaway self-signed cert and return ``(pem, fingerprint_hex)``.

    A real cert is required because the endpoint computes the
    SHA-256 fingerprint by parsing the DER body — a fake "PEM"
    string would fail at ``x509.load_pem_x509_certificate``.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test-ca-bootstrap")],
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return pem, fingerprint


@pytest.fixture(autouse=True)
def _reset_limiter():
    reset_agent_rate_limiter()
    yield
    reset_agent_rate_limiter()


def _client(
    *,
    org_id: str | None = "acme",
    ca_pem: str | None = None,
    trust_domain: str = "acme.cullis.local",
) -> TestClient:
    """Build a FastAPI test app with bootstrap router mounted and the
    config layer + settings + app.state stubbed.

    ``org_id`` and ``ca_pem`` together drive the ``mode`` field:
    both present → ``configured``; either missing → ``setup``.
    """
    app = FastAPI()
    app.include_router(bootstrap_router)
    app.state.org_id = org_id or ""

    async def _fake_get_config(key: str) -> str | None:
        if key == "org_id":
            return org_id
        if key == "org_ca_cert":
            return ca_pem
        return None

    fake_settings = SimpleNamespace(trust_domain=trust_domain)

    cfg_patch = patch("mcp_proxy.pki.bootstrap.get_config", _fake_get_config)
    settings_patch = patch(
        "mcp_proxy.pki.bootstrap.get_settings", lambda: fake_settings,
    )
    cfg_patch.start()
    settings_patch.start()
    app.state._patches = (cfg_patch, settings_patch)
    return TestClient(app)


def test_configured_mode_returns_full_payload():
    pem, fingerprint = _self_signed_pem()
    with _client(org_id="acme", ca_pem=pem) as client:
        resp = client.get("/.well-known/cullis/connector-bootstrap")
        assert resp.status_code == 200
        body = resp.json()
        assert body["version"] == 1
        assert body["mode"] == "configured"
        assert body["org_id"] == "acme"
        assert body["trust_domain"] == "acme.cullis.local"
        assert body["ca_fingerprint_sha256"] == fingerprint
        urls = body["urls"]
        assert urls["ca"] == "/pki/ca.crt"
        assert urls["enrollment_start"] == "/v1/enrollment/start"
        assert urls["enrollment_status_template"].endswith(
            "/{session_id}/status",
        )
        assert urls["jwks"] == "/.well-known/jwks-local.json"


def test_setup_mode_when_no_org_id_and_no_ca():
    """Fresh Mastio that hasn't completed first-boot — wizard must be
    able to tell this apart from "no Mastio at all" (which surfaces
    as a connection error, never as a malformed payload)."""
    with _client(org_id=None, ca_pem=None) as client:
        resp = client.get("/.well-known/cullis/connector-bootstrap")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "setup"
        assert body["org_id"] is None
        assert body["ca_fingerprint_sha256"] is None


def test_setup_mode_when_org_id_present_but_ca_missing():
    """Half-configured Mastio: ``org_id`` set via env, CA not yet
    generated. Still ``setup`` because the wizard can't pin a
    fingerprint without a CA to anchor on."""
    with _client(org_id="acme", ca_pem=None) as client:
        resp = client.get("/.well-known/cullis/connector-bootstrap")
        body = resp.json()
        assert body["mode"] == "setup"
        assert body["org_id"] == "acme"
        assert body["ca_fingerprint_sha256"] is None


def test_setup_mode_when_ca_present_but_org_id_missing():
    pem, _ = _self_signed_pem()
    with _client(org_id=None, ca_pem=pem) as client:
        resp = client.get("/.well-known/cullis/connector-bootstrap")
        body = resp.json()
        assert body["mode"] == "setup"
        assert body["org_id"] is None
        # We still expose the fingerprint so a wizard could pin
        # what's there for a future re-check, even if it can't
        # complete enrollment yet.
        assert body["ca_fingerprint_sha256"] is not None


def test_urls_are_relative_paths():
    """Gotcha: returning absolute URLs would force us to know the
    operator-facing hostname, which conflicts with the dual
    semantics of ``MCP_PROXY_PROXY_PUBLIC_URL`` (htu vs OIDC
    redirect). Wizard concatenates with the base URL it probed."""
    pem, _ = _self_signed_pem()
    with _client(org_id="acme", ca_pem=pem) as client:
        body = client.get("/.well-known/cullis/connector-bootstrap").json()
        for value in body["urls"].values():
            assert value.startswith("/"), (
                f"expected relative path, got absolute URL: {value}"
            )


def test_etag_strong_match_returns_304():
    pem, _ = _self_signed_pem()
    with _client(org_id="acme", ca_pem=pem) as client:
        first = client.get("/.well-known/cullis/connector-bootstrap")
        etag = first.headers["ETag"]
        second = client.get(
            "/.well-known/cullis/connector-bootstrap",
            headers={"If-None-Match": etag},
        )
        assert second.status_code == 304
        assert second.content == b""


def test_endpoint_is_anonymous():
    pem, _ = _self_signed_pem()
    with _client(org_id="acme", ca_pem=pem) as client:
        # No auth header, cookie, or client cert — same shape as
        # /pki/ca.crt and /.well-known/jwks-local.json.
        resp = client.get("/.well-known/cullis/connector-bootstrap")
        assert resp.status_code == 200


def test_payload_is_valid_json_with_known_keys():
    """Minimal contract test: third-party setup wizards (or our own
    Connector after a refactor) rely on the keys being stable."""
    pem, _ = _self_signed_pem()
    with _client(org_id="acme", ca_pem=pem) as client:
        resp = client.get("/.well-known/cullis/connector-bootstrap")
        body = json.loads(resp.text)
        assert set(body.keys()) == {
            "version", "mode", "org_id", "trust_domain",
            "ca_fingerprint_sha256", "urls",
        }
        assert resp.headers["content-type"].startswith("application/json")
