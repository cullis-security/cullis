"""Tests for the Mastio CSR signing endpoint (ADR-021 PR4a).

Two layers:
  - Unit tests on ``sign_user_csr()`` in ``app/registry/principals_csr.py``
  - HTTP tests on ``POST /v1/principals/csr`` with auth dependency
    overridden (same pattern as PR2).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.main import app
from app.registry.principals_csr import (
    CsrValidationError,
    parse_principal_id_to_spiffe,
    sign_user_csr,
)

pytestmark = pytest.mark.asyncio


# ── helpers ────────────────────────────────────────────────────────


def _make_csr(
    spiffe_uri: str | None,
    *,
    cn: str = "principal",
    key_type: str = "ec",
    key_size: int = 256,
    extra_uris: list[str] | None = None,
) -> tuple[x509.CertificateSigningRequest, str]:
    """Build a CSR + return PEM. ``spiffe_uri`` None = no SAN extension."""
    if key_type == "ec":
        if key_size == 256:
            curve = ec.SECP256R1()
        elif key_size == 384:
            curve = ec.SECP384R1()
        elif key_size == 192:
            curve = ec.SECT163K1()  # weak curve sentinel for negative test
        else:
            raise ValueError("test only ships ec 192/256/384")
        priv = ec.generate_private_key(curve)
        sig_alg = hashes.SHA256()
    elif key_type == "rsa":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        sig_alg = hashes.SHA256()
    else:
        raise ValueError(key_type)

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]),
    )

    sans: list[x509.GeneralName] = []
    if spiffe_uri is not None:
        sans.append(x509.UniformResourceIdentifier(spiffe_uri))
    if extra_uris:
        sans.extend(x509.UniformResourceIdentifier(u) for u in extra_uris)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False,
        )

    csr = builder.sign(priv, sig_alg)
    pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return csr, pem


# ── parse_principal_id_to_spiffe (4 tests) ─────────────────────────


def test_parse_principal_id_happy():
    spiffe, org = parse_principal_id_to_spiffe("acme.test/acme/user/mario")
    assert spiffe == "spiffe://acme.test/acme/user/mario"
    assert org == "acme"


def test_parse_principal_id_wrong_segment_count_raises():
    with pytest.raises(ValueError, match="4 path components"):
        parse_principal_id_to_spiffe("acme.test/acme/mario")


def test_parse_principal_id_empty_segment_raises():
    with pytest.raises(ValueError, match="empty component"):
        parse_principal_id_to_spiffe("acme.test//user/mario")


def test_parse_principal_id_unknown_type_raises():
    with pytest.raises(ValueError, match="user/agent/workload"):
        parse_principal_id_to_spiffe("acme.test/acme/badtype/mario")


# ── sign_user_csr unit (8 tests) ───────────────────────────────────


async def test_sign_user_csr_happy_ec_p256():
    _, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    cert_pem, thumbprint, not_after = await sign_user_csr(
        csr_pem, "acme.test/acme/user/mario",
    )
    assert "BEGIN CERTIFICATE" in cert_pem
    assert len(thumbprint) == 64  # sha256 hex
    assert not_after > datetime.now(timezone.utc)
    # Parse the returned cert and check its SAN.
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    uris = [u.value for u in san if isinstance(u, x509.UniformResourceIdentifier)]
    assert uris == ["spiffe://acme.test/acme/user/mario"]
    # Cert is not a CA
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    # Issuer organisation is the org_id
    issuer_org = next(
        a.value for a in cert.issuer if a.oid == NameOID.ORGANIZATION_NAME
    )
    assert issuer_org == "acme"


async def test_sign_user_csr_happy_rsa_2048():
    _, csr_pem = _make_csr(
        "spiffe://acme.test/acme/user/mario", key_type="rsa", key_size=2048,
    )
    cert_pem, thumbprint, _ = await sign_user_csr(
        csr_pem, "acme.test/acme/user/mario",
    )
    assert "BEGIN CERTIFICATE" in cert_pem
    assert len(thumbprint) == 64


async def test_sign_user_csr_wrong_principal_id_raises():
    """CSR has SAN for mario, caller asks signing for anna → reject."""
    _, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    with pytest.raises(CsrValidationError, match="does not match"):
        await sign_user_csr(csr_pem, "acme.test/acme/user/anna")


async def test_sign_user_csr_no_san_raises():
    _, csr_pem = _make_csr(spiffe_uri=None)  # no SAN extension at all
    with pytest.raises(CsrValidationError, match="missing the SubjectAlternativeName"):
        await sign_user_csr(csr_pem, "acme.test/acme/user/mario")


async def test_sign_user_csr_multiple_uri_sans_raises():
    _, csr_pem = _make_csr(
        "spiffe://acme.test/acme/user/mario",
        extra_uris=["spiffe://acme.test/acme/agent/extra"],
    )
    with pytest.raises(CsrValidationError, match="exactly one URI"):
        await sign_user_csr(csr_pem, "acme.test/acme/user/mario")


async def test_sign_user_csr_non_spiffe_uri_raises():
    _, csr_pem = _make_csr("https://attacker.example/")
    with pytest.raises(CsrValidationError, match="SPIFFE id"):
        await sign_user_csr(csr_pem, "acme.test/acme/user/mario")


async def test_sign_user_csr_weak_rsa_raises():
    _, csr_pem = _make_csr(
        "spiffe://acme.test/acme/user/mario", key_type="rsa", key_size=1024,
    )
    with pytest.raises(CsrValidationError, match="too small"):
        await sign_user_csr(csr_pem, "acme.test/acme/user/mario")


async def test_sign_user_csr_malformed_pem_raises():
    with pytest.raises(CsrValidationError, match="could not parse"):
        await sign_user_csr("not a pem", "acme.test/acme/user/mario")


# ── /v1/principals/csr endpoint (5 tests) ──────────────────────────


def _override_token(*, agent_id: str, org: str) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{org}/agent/{agent_id.split('::', 1)[-1]}",
        agent_id=agent_id,
        org=org,
        exp=2_000_000_000,
        iat=1_700_000_000,
        jti="test-jti",
        scope=[],
        cnf={"jkt": "x" * 43},
    )


@pytest_asyncio.fixture
async def auth_as_acme():
    app.dependency_overrides[get_current_agent] = (
        lambda: _override_token(agent_id="acme::frontdesk", org="acme")
    )
    yield
    app.dependency_overrides.pop(get_current_agent, None)


@pytest_asyncio.fixture
async def auth_as_globex():
    app.dependency_overrides[get_current_agent] = (
        lambda: _override_token(agent_id="globex::frontdesk", org="globex")
    )
    yield
    app.dependency_overrides.pop(get_current_agent, None)


async def test_csr_endpoint_201(client, auth_as_acme):
    _, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/user/mario",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert "BEGIN CERTIFICATE" in body["cert_pem"]
    assert len(body["cert_thumbprint"]) == 64


async def test_csr_endpoint_400_malformed_csr(client, auth_as_acme):
    # Padded so the body passes Pydantic min_length=128 and the
    # malformed-PEM check happens in the handler, returning 400.
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/user/mario",
            "csr_pem": (
                "-----BEGIN CERTIFICATE REQUEST-----\n"
                + ("garbageQ" * 16) + "\n"
                + "-----END CERTIFICATE REQUEST-----\n"
            ),
        },
    )
    assert r.status_code == 400, r.text
    detail = r.json()["detail"].lower()
    assert "csr" in detail or "parse" in detail


async def test_csr_endpoint_400_principal_id_malformed(client, auth_as_acme):
    _, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/badtype/mario",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code == 400


async def test_csr_endpoint_403_cross_org(client, auth_as_globex):
    _, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/user/mario",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code == 403


async def test_csr_endpoint_400_san_mismatch(client, auth_as_acme):
    _, csr_pem = _make_csr("spiffe://acme.test/acme/user/anna")
    r = await client.post(
        "/v1/principals/csr",
        json={
            "principal_id": "acme.test/acme/user/mario",
            "csr_pem": csr_pem,
        },
    )
    assert r.status_code == 400
    assert "does not match" in r.json()["detail"]
