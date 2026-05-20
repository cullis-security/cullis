"""Tests for Wave 3 U4 — bidirectional mTLS verify-if-present.

Covers ``app.auth.mastio_mtls`` extract + verify functions. Real TLS
handshake validation is out of scope for unit tests (requires uvicorn
with ssl_cert_reqs=optional and a live socket); those land in the
sandbox smoke pre-merge gate.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException, Request

from app.auth.mastio_mtls import (
    PASS_THROUGH_HEADER,
    extract_mastio_cert,
    verify_mastio_cert_pubkey,
    enforce_if_present,
    enforce_if_required,
)


# ─── Fixtures ────────────────────────────────────────────────────────

def _mint_pair(now: datetime | None = None):
    """Mint an EC P-256 keypair + self-signed cert for the test."""
    now = now or datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-mastio"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pubkey_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key, cert, pubkey_pem, cert_pem


def _request_with_header(value: str | None) -> Request:
    """Build a minimal Request whose only relevant input is one header."""
    headers = []
    if value is not None:
        headers.append((PASS_THROUGH_HEADER.lower().encode(), value.encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/federation/publish-agent",
        "headers": headers,
        "query_string": b"",
        # F-A-101 fix: pass-through path requires the peer host fall inside
        # MASTIO_MTLS_TRUSTED_PROXY_CIDRS. The autouse fixture below pins
        # 127.0.0.0/8 so this loopback stub matches.
        "client": ("127.0.0.1", 12345),
        # No "transport" key — extract should fall through to the header.
    }
    return Request(scope=scope)


def _request_with_transport_cert(cert_der: bytes | None) -> Request:
    """Build a Request whose ``scope['transport']`` returns ``cert_der``."""
    transport = MagicMock()
    ssl_obj = MagicMock()
    ssl_obj.getpeercert = MagicMock(return_value=cert_der)
    transport.get_extra_info = MagicMock(
        side_effect=lambda key: ssl_obj if key == "ssl_object" else None,
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/federation/publish-agent",
        "headers": [],
        "query_string": b"",
        "transport": transport,
        # F-A-101 fix: header-fallthrough path needs trusted-peer CIDR
        # match if the transport branch returns no cert.
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope=scope)


@pytest.fixture(autouse=True)
def _trust_loopback_proxy(monkeypatch):
    """PR #1 audit 2026-05-20: F-A-101 fix made empty CIDR allowlist
    fail-closed at the runtime _peer_is_trusted_proxy boundary.
    Pre-fix these tests relied on the default empty allowlist
    accepting any peer. Pin 127.0.0.0/8 so the loopback stub host
    used by _request_with_header / _request_with_transport_cert
    matches and the pass-through path stays exercised."""
    from app.config import get_settings
    monkeypatch.setattr(
        get_settings(), "mastio_mtls_trusted_proxy_cidrs", "127.0.0.0/8",
    )


# ─── extract_mastio_cert ─────────────────────────────────────────────

def test_extract_returns_none_when_no_cert():
    req = _request_with_header(None)
    assert extract_mastio_cert(req) is None


def test_extract_via_header_pass_through():
    _, cert, _, cert_pem = _mint_pair()
    encoded = quote(cert_pem)
    req = _request_with_header(encoded)
    parsed = extract_mastio_cert(req)
    assert parsed is not None
    assert parsed.subject == cert.subject


def test_extract_via_header_malformed_returns_none():
    req = _request_with_header(quote("not a certificate"))
    assert extract_mastio_cert(req) is None


def test_extract_via_header_garbled_pem_returns_none():
    pem_garbled = "-----BEGIN CERTIFICATE-----\nbm90LWFjdHVhbA==\n-----END CERTIFICATE-----"
    req = _request_with_header(quote(pem_garbled))
    assert extract_mastio_cert(req) is None


def test_extract_via_transport():
    _, cert, _, _ = _mint_pair()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    req = _request_with_transport_cert(cert_der)
    parsed = extract_mastio_cert(req)
    assert parsed is not None
    assert parsed.subject == cert.subject


def test_extract_transport_no_peer_cert_falls_through_to_header():
    """If the transport reports no peer cert, the header path still runs."""
    _, cert, _, cert_pem = _mint_pair()
    transport = MagicMock()
    ssl_obj = MagicMock()
    ssl_obj.getpeercert = MagicMock(return_value=b"")  # no peer cert
    transport.get_extra_info = MagicMock(
        side_effect=lambda key: ssl_obj if key == "ssl_object" else None,
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/x",
        "headers": [
            (PASS_THROUGH_HEADER.lower().encode(), quote(cert_pem).encode()),
        ],
        "query_string": b"",
        "transport": transport,
        # F-A-101 fix: header pass-through requires trusted-peer CIDR match.
        "client": ("127.0.0.1", 12345),
    }
    req = Request(scope=scope)
    parsed = extract_mastio_cert(req)
    assert parsed is not None
    assert parsed.subject == cert.subject


# ─── verify_mastio_cert_pubkey ───────────────────────────────────────

def test_verify_match_no_raise():
    _, cert, pubkey_pem, _ = _mint_pair()
    verify_mastio_cert_pubkey(cert, pubkey_pem)  # no raise


def test_verify_mismatch_raises_403():
    _, cert, _, _ = _mint_pair()
    _, _, other_pubkey_pem, _ = _mint_pair()  # different key
    with pytest.raises(HTTPException) as exc:
        verify_mastio_cert_pubkey(cert, other_pubkey_pem)
    assert exc.value.status_code == 403


def test_verify_unreadable_pinned_pem_raises_500():
    _, cert, _, _ = _mint_pair()
    with pytest.raises(HTTPException) as exc:
        verify_mastio_cert_pubkey(cert, "-----BEGIN GARBAGE-----\nx\n-----END GARBAGE-----")
    assert exc.value.status_code == 500


# ─── enforce_if_present ──────────────────────────────────────────────

def test_enforce_no_cert_returns_false():
    _, _, pubkey_pem, _ = _mint_pair()
    req = _request_with_header(None)
    assert enforce_if_present(req, pubkey_pem) is False


def test_enforce_cert_match_returns_true():
    _, _, pubkey_pem, cert_pem = _mint_pair()
    req = _request_with_header(quote(cert_pem))
    assert enforce_if_present(req, pubkey_pem) is True


def test_enforce_cert_mismatch_raises_403():
    _, _, _, cert_pem = _mint_pair()
    _, _, other_pubkey_pem, _ = _mint_pair()
    req = _request_with_header(quote(cert_pem))
    with pytest.raises(HTTPException) as exc:
        enforce_if_present(req, other_pubkey_pem)
    assert exc.value.status_code == 403


# ─── enforce_if_required (Phase 2) ───────────────────────────────────

def test_enforce_required_no_cert_raises_403():
    _, _, pubkey_pem, _ = _mint_pair()
    req = _request_with_header(None)
    with pytest.raises(HTTPException) as exc:
        enforce_if_required(req, pubkey_pem, require=True)
    assert exc.value.status_code == 403
    assert "no peer certificate" in exc.value.detail


def test_enforce_required_no_cert_no_require_returns_false():
    """require=False keeps the verify-if-present behavior."""
    _, _, pubkey_pem, _ = _mint_pair()
    req = _request_with_header(None)
    assert enforce_if_required(req, pubkey_pem, require=False) is False


def test_enforce_required_cert_match_returns_true():
    _, _, pubkey_pem, cert_pem = _mint_pair()
    req = _request_with_header(quote(cert_pem))
    assert enforce_if_required(req, pubkey_pem, require=True) is True


def test_enforce_required_cert_mismatch_raises_403_regardless_of_require():
    """Mismatch is fatal whether require is True or False."""
    _, _, _, cert_pem = _mint_pair()
    _, _, other_pubkey_pem, _ = _mint_pair()
    req = _request_with_header(quote(cert_pem))
    for require in (True, False):
        with pytest.raises(HTTPException) as exc:
            enforce_if_required(req, other_pubkey_pem, require=require)
        assert exc.value.status_code == 403
