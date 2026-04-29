"""Tests for the Connector dashboard TOFU CA-pinning endpoints.

The dashboard fetches the anonymous ``/pki/ca.crt`` from the Site,
shows the SHA-256 fingerprint, and on operator confirmation pins the
PEM into the profile so subsequent httpx clients verify against it.
We mock the upstream httpx call so these tests never touch the
network.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.web import build_app


def _make_self_signed_pem() -> tuple[str, str]:
    """Generate a real self-signed cert so the dashboard's
    ``cert_fingerprint`` runs against actual DER bytes — this catches
    bugs that a hand-crafted PEM blob would mask."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "fake-test-ca"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(Encoding.PEM).decode()
    fingerprint = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    return pem, fingerprint


@pytest.fixture
def cfg(tmp_path) -> ConnectorConfig:
    return ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://fake-mastio.test:9443",
        verify_tls=True,
    )


@pytest.fixture
def client(cfg, monkeypatch) -> TestClient:
    import cullis_connector.web as _web
    monkeypatch.setattr(_web, "has_identity", lambda _: False)
    return TestClient(build_app(cfg))


def _patch_pki_endpoint(monkeypatch, status_code: int, body: str) -> list[str]:
    """Capture URLs called and return the configured response.

    We intercept httpx.get at the module level used inside web.py —
    the same import path the runtime uses, so the patch is sound.
    """
    calls: list[str] = []

    def _fake_get(url, *, verify, timeout):
        calls.append(url)
        return httpx.Response(status_code, text=body, request=httpx.Request("GET", url))

    monkeypatch.setattr("cullis_connector.web.httpx.get", _fake_get)
    return calls


def test_preview_ca_returns_fingerprint(client, monkeypatch):
    """Happy path: anonymous /pki/ca.crt returns the PEM, dashboard
    computes the SHA-256, hands the operator both the hex digest and
    a colon-separated short form for visual comparison."""
    pem, expected_fp = _make_self_signed_pem()
    calls = _patch_pki_endpoint(monkeypatch, 200, pem)

    resp = client.post(
        "/setup/preview-ca",
        data={"site_url": "https://fake-mastio.test:9443"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["fingerprint_sha256"] == expected_fp
    # Short form is 64 hex chars + 31 separators = 95 chars total.
    assert len(body["fingerprint_short"]) == 95
    assert body["fingerprint_short"].count(":") == 31
    assert body["ca_pem"] == pem

    # Confirm we hit the right path on the right host.
    assert calls == ["https://fake-mastio.test:9443/pki/ca.crt"]


def test_preview_ca_404_when_site_has_no_ca(client, monkeypatch):
    """Pre-setup Mastio: /pki/ca.crt returns 404 → operator sees an
    actionable error instead of a confusing TLS failure."""
    _patch_pki_endpoint(monkeypatch, 404, "")
    resp = client.post(
        "/setup/preview-ca",
        data={"site_url": "https://fake-mastio.test:9443"},
    )
    assert resp.status_code == 400
    assert "no org ca configured" in resp.json()["error"].lower()


def test_pin_ca_writes_to_profile(client, cfg, monkeypatch):
    """Pin happy path: dashboard re-fetches, fingerprint still
    matches, PEM lands in ``<profile>/identity/ca-chain.pem`` and the
    file is exactly the bytes the Mastio served."""
    pem, expected_fp = _make_self_signed_pem()
    _patch_pki_endpoint(monkeypatch, 200, pem)

    resp = client.post(
        "/setup/pin-ca",
        data={
            "site_url": "https://fake-mastio.test:9443",
            "fingerprint_expected": expected_fp,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["pinned"] is True

    pinned = cfg.ca_chain_path
    assert pinned.exists()
    assert pinned.read_text() == pem


def test_pin_ca_rejects_fingerprint_mismatch(client, cfg, monkeypatch):
    """Pin re-fetches the CA to close TOCTOU. If the fingerprint
    changed since preview, refuse to pin and report the new value
    so the operator can investigate (admin rotation? attacker?)."""
    pem, real_fp = _make_self_signed_pem()
    _patch_pki_endpoint(monkeypatch, 200, pem)

    resp = client.post(
        "/setup/pin-ca",
        data={
            "site_url": "https://fake-mastio.test:9443",
            "fingerprint_expected": "0" * 64,  # nonsense, will not match
        },
    )
    assert resp.status_code == 409
    body = resp.json()
    assert "fingerprint changed" in body["error"].lower()
    assert body["fingerprint_now"] == real_fp
    # File must NOT be created on mismatch.
    assert not cfg.ca_chain_path.exists()


def test_pin_ca_accepts_colon_separated_fingerprint(client, cfg, monkeypatch):
    """Operators may copy the colon-separated short form back from the
    UI verbatim. Server normalises before comparing."""
    pem, expected_fp = _make_self_signed_pem()
    _patch_pki_endpoint(monkeypatch, 200, pem)

    short_fp = ":".join(
        expected_fp[i:i+2] for i in range(0, len(expected_fp), 2)
    )
    resp = client.post(
        "/setup/pin-ca",
        data={
            "site_url": "https://fake-mastio.test:9443",
            "fingerprint_expected": short_fp,
        },
    )
    assert resp.status_code == 200
    assert cfg.ca_chain_path.exists()


def test_pin_ca_makes_verify_arg_return_path(cfg, monkeypatch):
    """Integration with verify_arg: once the dashboard pins, a fresh
    ``ConnectorConfig.verify_arg`` resolves to the pinned path —
    confirming B.3 and B.2 are wired together."""
    pem, _ = _make_self_signed_pem()
    cfg.ca_chain_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.ca_chain_path.write_text(pem)

    # Same instance — property re-reads filesystem state on access.
    assert cfg.verify_arg == str(cfg.ca_chain_path)
