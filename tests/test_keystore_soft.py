"""Smoke tests for the soft :class:`KeyStore` (ADR-032 F3).

Covers the three constructor paths (in-memory ephemeral, persist-on-disk,
load-from-disk), the signature round-trip with the EC P-256 public key,
and the contract that the soft backend never emits an attestation claim.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cullis_connector.keystore.base import KeyStoreUnavailable
from cullis_connector.keystore.soft import SoftKeyStore


def test_ephemeral_keystore_signs_verifiably():
    ks = SoftKeyStore()
    msg = b"cullis-attestation-test"
    sig = ks.sign(msg)

    pub = serialization.load_pem_public_key(ks.public_key_pem().encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    # Round-trip; raises if the signature does not verify.
    pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))


def test_persist_then_reload_yields_same_pubkey(tmp_path):
    path = tmp_path / "soft.key.pem"
    ks1 = SoftKeyStore(private_key_path=path)
    pem1 = ks1.public_key_pem()
    assert path.exists()
    if path.stat().st_mode & 0o777 not in (0o600, 0o400):
        # ``chmod 600`` is best-effort on POSIX, but on Windows the bits
        # vary. Don't fail the test on non-POSIX hosts.
        import os

        if os.name == "posix":
            pytest.fail(f"expected 0o600 on POSIX, got {oct(path.stat().st_mode & 0o777)}")

    ks2 = SoftKeyStore(private_key_path=path)
    assert ks2.public_key_pem() == pem1


def test_attestation_claim_is_none_for_soft():
    ks = SoftKeyStore()
    assert ks.attestation_claim() is None
    assert ks.attestation_strength() == "soft_only"


def test_generate_aik_quote_default_returns_none():
    ks = SoftKeyStore()
    # Soft backend never owns an AIK; calling the helper must yield
    # ``None`` so the enrollment flow can treat it uniformly.
    assert ks.generate_aik_quote(b"nonce") is None


def test_keystore_unavailable_is_an_exception():
    # Sanity; KeyStoreUnavailable is importable and is a real Exception.
    assert issubclass(KeyStoreUnavailable, Exception)
