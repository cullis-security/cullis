"""F-A-102 (audit 2026-05-20, CWE-326) regression for the proxy-side
CSR public-key validator.

The proxy hosts a sister copy of ``app/registry/principals_csr.py`` at
``mcp_proxy/registry/principals_csr.py``. Before this finding both
copies validated EC public keys with a numeric ``key_size >= 256``
heuristic, which accepted SECP256K1 (Bitcoin) and BrainpoolP256R1 —
neither of which the downstream verifier in
``app/auth/x509_verifier.py`` will accept on the resulting token.

The fix mirrors ``_ALLOWED_EC_CURVES = (SECP256R1, SECP384R1, SECP521R1)``
from the broker x509 verifier into both CSR signers.
"""
from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mcp_proxy.registry.principals_csr import (
    CsrValidationError,
    _validate_public_key,
)


def _build_csr(curve: ec.EllipticCurve) -> x509.CertificateSigningRequest:
    priv = ec.generate_private_key(curve)
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]),
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier(
                "spiffe://acme.test/acme/user/mario",
            )],
        ),
        critical=False,
    )
    return builder.sign(priv, hashes.SHA256())


@pytest.mark.parametrize(
    "curve_factory",
    [ec.SECP256K1, ec.BrainpoolP256R1],
    ids=["secp256k1", "brainpoolp256r1"],
)
def test_validate_public_key_rejects_non_nist_curves(curve_factory):
    csr = _build_csr(curve_factory())
    with pytest.raises(CsrValidationError, match="not allowed"):
        _validate_public_key(csr)


@pytest.mark.parametrize(
    "curve_factory",
    [ec.SECP256R1, ec.SECP384R1, ec.SECP521R1],
    ids=["p256", "p384", "p521"],
)
def test_validate_public_key_accepts_nist_curves(curve_factory):
    csr = _build_csr(curve_factory())
    # Must not raise.
    _validate_public_key(csr)


def test_validate_public_key_csr_pem_roundtrip_rejects_secp256k1():
    """Belt-and-suspenders: load the CSR from PEM (what the HTTP path
    actually does) and check the validator still rejects."""
    csr = _build_csr(ec.SECP256K1())
    pem = csr.public_bytes(serialization.Encoding.PEM)
    parsed = x509.load_pem_x509_csr(pem)
    with pytest.raises(CsrValidationError, match="not allowed"):
        _validate_public_key(parsed)
