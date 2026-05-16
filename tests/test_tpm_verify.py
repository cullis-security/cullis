"""Mastio-side TPM quote verifier (mcp_proxy.attestation.tpm_verify).

The unit suite stays pure-Python: the envelope packer mirrors the one in
``cullis_connector.keystore.tpm_linux`` but uses a software EC P-256 key
in place of the chip so we can exercise the verifier end-to-end without
a TPM.
"""
from __future__ import annotations

import hashlib
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from mcp_proxy.attestation import compute_effective_tier
from mcp_proxy.attestation.tpm_verify import (
    TPM_MANUFACTURER_WHITELIST,
    verify_tpm_quote,
)


_QUOTE_MAGIC = b"CULLIS-Q1"


def _pack(quote: bytes, sig: bytes, nonce: bytes) -> bytes:
    out = bytearray()
    out += _QUOTE_MAGIC
    out += len(nonce).to_bytes(2, "big")
    out += nonce
    out += len(quote).to_bytes(4, "big")
    out += quote
    out += len(sig).to_bytes(4, "big")
    out += sig
    return bytes(out)


def _fake_quote(nonce: bytes, private_key: ec.EllipticCurvePrivateKey) -> tuple[bytes, str]:
    """Build a software-signed envelope shaped like the TPM packer."""
    quote_body = b"mocked-TPMS_ATTEST||" + nonce
    digest = hashlib.sha256(quote_body).digest()
    sig = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return _pack(quote_body, sig, nonce), pem


def test_verify_valid_quote_with_whitelisted_manufacturer_marks_hw_attested():
    nonce = secrets.token_bytes(32)
    key = ec.generate_private_key(ec.SECP256R1())
    envelope, pem = _fake_quote(nonce, key)

    valid, claim = verify_tpm_quote(
        envelope,
        pem,
        nonce,
        manufacturer="Infineon",
        ek_cert_present=True,
    )
    assert valid is True
    assert claim["hardware"] == "tpm_2.0"
    assert claim["strength"] == "hw_attested"
    assert claim["manufacturer"] == "Infineon"
    assert "pcr_digest_sha256" in claim


def test_unknown_manufacturer_downgrades_to_hw_isolated():
    nonce = secrets.token_bytes(32)
    key = ec.generate_private_key(ec.SECP256R1())
    envelope, pem = _fake_quote(nonce, key)

    valid, claim = verify_tpm_quote(
        envelope, pem, nonce, manufacturer="OffBrand", ek_cert_present=True,
    )
    assert valid is True
    assert claim["strength"] == "hw_isolated"


def test_no_ek_cert_downgrades_to_hw_isolated():
    nonce = secrets.token_bytes(32)
    key = ec.generate_private_key(ec.SECP256R1())
    envelope, pem = _fake_quote(nonce, key)

    valid, claim = verify_tpm_quote(
        envelope, pem, nonce, manufacturer="Infineon", ek_cert_present=False,
    )
    assert valid is True
    assert claim["strength"] == "hw_isolated"


def test_nonce_mismatch_fails_verification():
    nonce = secrets.token_bytes(32)
    bad_nonce = secrets.token_bytes(32)
    key = ec.generate_private_key(ec.SECP256R1())
    envelope, pem = _fake_quote(nonce, key)

    valid, claim = verify_tpm_quote(envelope, pem, bad_nonce)
    assert valid is False
    assert claim["strength"] == "soft_only"


def test_tampered_signature_fails_verification():
    nonce = secrets.token_bytes(32)
    key = ec.generate_private_key(ec.SECP256R1())
    envelope, pem = _fake_quote(nonce, key)
    tampered = bytearray(envelope)
    tampered[-1] ^= 0xFF  # flip a bit in the signature DER

    valid, _claim = verify_tpm_quote(bytes(tampered), pem, nonce)
    assert valid is False


def test_truncated_envelope_returns_soft_only():
    valid, claim = verify_tpm_quote(b"too-short", "ignored-pem", b"")
    assert valid is False
    assert claim["strength"] == "soft_only"


def test_phase1_whitelist_contains_expected_vendors():
    # If a customer reports a Phase 1 vendor that isn't here, ADR-032
    # Q8 says the bundle needs a refresh; not a silent server upgrade.
    assert {"Infineon", "Microsoft", "ST", "Nuvoton", "Intel"}.issubset(
        TPM_MANUFACTURER_WHITELIST,
    )


def test_effective_tier_algorithm_matches_schema():
    # Locked algorithm from imp/attestation-claim-schema.md sez. 2.
    cases = [
        # (mdm, compliance, strength, expected)
        ("intune", "compliant", "hw_attested", "managed_attested"),
        ("intune", "compliant", "hw_isolated", "managed"),
        ("intune", "compliant", "soft_only", "managed"),
        ("intune", "non_compliant", "hw_attested", "byod_attested"),
        (None, None, "hw_attested", "byod_attested"),
        (None, None, "hw_isolated", "byod_isolated"),
        (None, None, "soft_only", "untrusted"),
        (None, None, None, "untrusted"),
    ]
    def _hardware(strength):
        if strength in ("hw_attested", "hw_isolated"):
            return "tpm_2.0"
        if strength == "soft_only":
            return "soft"
        return None

    for mdm, compliance, strength, expected in cases:
        got = compute_effective_tier(
            mdm=mdm,
            compliance=compliance,
            hardware=_hardware(strength),
            strength=strength,
        )
        assert got == expected, (mdm, compliance, strength, expected, got)
