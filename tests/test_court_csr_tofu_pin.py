"""PR #3 audit 2026-05-20: F-A-201 Court CSR TOFU pubkey pin (CRITICAL).

The Mastio sister endpoint already enforces this (PR #730/CRIT-1
audit). Court was the missing leg — any compromised workload token in
the org could mint a 1h user-principal cert keyed to its OWN keypair,
then present it at /v1/auth/token with principal_type=user and bypass
the ADR-009 counter-signature gate plus the mTLS gate.

These tests pin the TOFU semantics so the gap cannot regress:
- First CSR signs and persists the SPKI thumbprint
- Second CSR with the SAME keypair is accepted (rotation case)
- Second CSR with a DIFFERENT keypair for the same principal_id is
  refused (the attack F-A-201 describes)
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.registry.principals_csr import (
    CsrValidationError,
    pubkey_thumbprint_sha256,
    sign_user_csr,
)


def _make_csr(spiffe_uri: str, *, key_type: str = "ec"):
    if key_type == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(spiffe_uri)]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return key, csr_pem


# ─── pubkey_thumbprint_sha256 unit ────────────────────────────────────


def test_pubkey_thumbprint_stable_across_csrs_same_key():
    """Same keypair → same SPKI digest regardless of CSR shape."""
    key = ec.generate_private_key(ec.SECP256R1())
    thumb1 = pubkey_thumbprint_sha256(key.public_key())
    thumb2 = pubkey_thumbprint_sha256(key.public_key())
    assert thumb1 == thumb2
    assert len(thumb1) == 64


def test_pubkey_thumbprint_differs_across_keys():
    """Different keypairs → different SPKI digest."""
    key_a = ec.generate_private_key(ec.SECP256R1())
    key_b = ec.generate_private_key(ec.SECP256R1())
    assert pubkey_thumbprint_sha256(key_a.public_key()) != \
        pubkey_thumbprint_sha256(key_b.public_key())


# ─── sign_user_csr returns 4-tuple including SPKI digest ─────────────


@pytest.mark.asyncio
async def test_sign_user_csr_returns_pubkey_thumbprint():
    """F-A-201: signed cert response carries the SPKI digest so the
    caller can persist it via attach_pubkey_thumbprint."""
    key, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    cert_pem, cert_thumb, pubkey_thumb, _ = await sign_user_csr(
        csr_pem, "acme.test/acme/user/mario",
    )
    expected = pubkey_thumbprint_sha256(key.public_key())
    assert pubkey_thumb == expected
    assert "BEGIN CERTIFICATE" in cert_pem


# ─── TOFU refusal on key mismatch (the F-A-201 attack) ───────────────


@pytest.mark.asyncio
async def test_csr_with_different_key_refused_when_thumbprint_pinned(
    monkeypatch,
):
    """F-A-201 attack chain: a workload token mints a cert for
    <org>::user::mario using key K_attacker. With a pinned SPKI digest
    that doesn't match K_attacker, sign_user_csr must refuse."""
    _, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")

    # Stub: pretend a different SPKI is already pinned for this principal.
    pinned_thumb = "0" * 64
    async def _stub_lookup(session, short_pid):
        assert short_pid == "acme::user::mario"
        return (True, pinned_thumb)

    monkeypatch.setattr(
        "app.registry.user_principals.get_pubkey_thumbprint",
        _stub_lookup,
    )

    with pytest.raises(CsrValidationError, match="TOFU mismatch"):
        await sign_user_csr(csr_pem, "acme.test/acme/user/mario")


@pytest.mark.asyncio
async def test_csr_with_same_key_accepted_when_thumbprint_pinned(monkeypatch):
    """F-A-201 counter-test: cert rotation (same keypair, new CSR)
    must succeed because the SPKI digest matches the pinned value."""
    key, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")
    pinned_thumb = pubkey_thumbprint_sha256(key.public_key())

    async def _stub_lookup(session, short_pid):
        return (True, pinned_thumb)

    monkeypatch.setattr(
        "app.registry.user_principals.get_pubkey_thumbprint",
        _stub_lookup,
    )

    cert_pem, _, pubkey_thumb, _ = await sign_user_csr(
        csr_pem, "acme.test/acme/user/mario",
    )
    assert pubkey_thumb == pinned_thumb
    assert "BEGIN CERTIFICATE" in cert_pem


@pytest.mark.asyncio
async def test_csr_first_touch_accepted_when_no_pin_yet(monkeypatch):
    """F-A-201 first-touch path: no pinned thumbprint for this
    principal yet — sign and return the SPKI digest to be persisted
    by the router."""
    key, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")

    async def _stub_lookup(session, short_pid):
        # Row exists but no pubkey pinned yet (the migration-legacy case).
        return (True, None)

    monkeypatch.setattr(
        "app.registry.user_principals.get_pubkey_thumbprint",
        _stub_lookup,
    )

    _, _, pubkey_thumb, _ = await sign_user_csr(
        csr_pem, "acme.test/acme/user/mario",
    )
    assert pubkey_thumb == pubkey_thumbprint_sha256(key.public_key())


@pytest.mark.asyncio
async def test_csr_no_principal_row_accepted_first_touch(monkeypatch):
    """F-A-201 first-touch path: principal row does not exist yet
    (admin has not pre-created via /v1/admin/users). The signer still
    accepts and returns the SPKI digest so the router can lazy-create."""
    key, csr_pem = _make_csr("spiffe://acme.test/acme/user/mario")

    async def _stub_lookup(session, short_pid):
        return (False, None)

    monkeypatch.setattr(
        "app.registry.user_principals.get_pubkey_thumbprint",
        _stub_lookup,
    )

    _, _, pubkey_thumb, _ = await sign_user_csr(
        csr_pem, "acme.test/acme/user/mario",
    )
    assert pubkey_thumb == pubkey_thumbprint_sha256(key.public_key())
