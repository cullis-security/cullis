"""Unit tests for cullis_sdk.spiffe — SPIFFE Workload API integration."""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cullis_sdk.spiffe import (
    SpiffeSvid,
    _to_pem_bundle,
    default_agent_id,
    fetch_x509_svid,
    parse_spiffe_id,
)


# ── Helpers: build a fake SVID that mimics pyspiffe's object shape ──

def _mint_cert(subject_cn: str, spiffe_uri: str) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-ca")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


@dataclass
class _FakeTrustDomain:
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass
class _FakeSpiffeId:
    uri: str
    trust_domain: _FakeTrustDomain

    def __str__(self) -> str:
        return self.uri


@dataclass
class _FakeSvid:
    spiffe_id: _FakeSpiffeId
    cert_chain: list
    private_key: object


@dataclass
class _FakeBundle:
    x509_authorities: list


@dataclass
class _FakeBundleSet:
    bundle: _FakeBundle

    def get_bundle_for_trust_domain(self, td):
        return self.bundle


# ── parse_spiffe_id ──────────────────────────────────────────────────

def test_parse_spiffe_id_simple():
    assert parse_spiffe_id("spiffe://orga.sandbox/agent-a") == (
        "orga.sandbox", "agent-a",
    )


def test_parse_spiffe_id_nested_path():
    assert parse_spiffe_id("spiffe://orga.sandbox/prod/api") == (
        "orga.sandbox", "prod/api",
    )


def test_parse_spiffe_id_rejects_non_spiffe():
    with pytest.raises(ValueError, match="Not a SPIFFE ID"):
        parse_spiffe_id("https://example.com/foo")


def test_parse_spiffe_id_rejects_missing_path():
    with pytest.raises(ValueError, match="no path"):
        parse_spiffe_id("spiffe://orga.sandbox")


# ── default_agent_id ─────────────────────────────────────────────────

def test_default_agent_id_uses_last_segment():
    assert default_agent_id("spiffe://orga.sandbox/agent-a", "orga") == "orga::agent-a"


def test_default_agent_id_strips_intermediate_path():
    assert default_agent_id("spiffe://orga.sandbox/prod/api", "orga") == "orga::api"


# ── _to_pem_bundle ───────────────────────────────────────────────────

def test_to_pem_bundle_roundtrip():
    leaf, key = _mint_cert("agent-a", "spiffe://orga.sandbox/agent-a")
    root, _ = _mint_cert("fake-ca", "spiffe://orga.sandbox")
    td = _FakeTrustDomain("orga.sandbox")
    svid = _FakeSvid(
        spiffe_id=_FakeSpiffeId("spiffe://orga.sandbox/agent-a", td),
        cert_chain=[leaf],
        private_key=key,
    )
    bundle_set = _FakeBundleSet(_FakeBundle([root]))

    result = _to_pem_bundle(svid, bundle_set)

    assert isinstance(result, SpiffeSvid)
    assert result.spiffe_id == "spiffe://orga.sandbox/agent-a"
    assert "BEGIN CERTIFICATE" in result.cert_pem
    assert "BEGIN PRIVATE KEY" in result.key_pem
    assert "BEGIN CERTIFICATE" in result.trust_bundle_pem
    # Key re-parses cleanly
    serialization.load_pem_private_key(result.key_pem.encode(), password=None)
    # Cert re-parses cleanly
    parsed = x509.load_pem_x509_certificate(result.cert_pem.encode())
    san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    uris = [str(u) for u in san.value.get_values_for_type(x509.UniformResourceIdentifier)]
    assert "spiffe://orga.sandbox/agent-a" in uris


# ── fetch_x509_svid — ImportError path ───────────────────────────────

def test_fetch_x509_svid_without_extra_raises_importerror():
    """If pyspiffe isn't installed, the error must be actionable."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "spiffe" or name.startswith("spiffe."):
            raise ImportError("no spiffe")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(ImportError, match=r"pip install cullis-agent-sdk\[spiffe\]"):
            fetch_x509_svid("/tmp/bogus.sock")


def test_fetch_x509_svid_without_socket_raises():
    """Missing socket + no env var → clear RuntimeError."""
    # Need spiffe importable for the ImportError check to pass; if not
    # installed in the dev env, this test is equivalent to the ImportError
    # path above. Skip cleanly when missing.
    pytest.importorskip("spiffe")
    import os
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SPIFFE_ENDPOINT_SOCKET", None)
        with pytest.raises(RuntimeError, match="No Workload API socket"):
            fetch_x509_svid(None)
