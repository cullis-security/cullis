"""Tier mapping with the hardware half of the device attestation claim.

Exercises ``compute_effective_tier`` from the server-authoritative side
and the schema field constraints. Mirrors the matrix locked in
``imp/attestation-claim-schema.md`` sez. 2.

The function ships in :mod:`mcp_proxy.attestation.tier` (owned by F2 Intune
spike); F3 adds the hardware-side coverage exercised below.
"""
from __future__ import annotations

import pytest

from mcp_proxy.attestation import compute_effective_tier


def _hardware_for(strength: str | None) -> str | None:
    if strength in ("hw_attested", "hw_isolated"):
        return "tpm_2.0"
    if strength == "soft_only":
        return "soft"
    return None


@pytest.mark.parametrize(
    ("mdm", "compliance", "strength", "expected"),
    [
        # Managed + hw_attested → top tier
        ("intune", "compliant", "hw_attested", "managed_attested"),
        # Managed only; hardware silent
        ("intune", "compliant", "soft_only", "managed"),
        ("intune", "compliant", None, "managed"),
        ("intune", "compliant", "hw_isolated", "managed"),
        # MDM present but non-compliant → BYOD ladder
        ("intune", "non_compliant", "hw_attested", "byod_attested"),
        ("intune", "non_compliant", "hw_isolated", "byod_isolated"),
        ("intune", "non_compliant", "soft_only", "untrusted"),
        # No MDM; pure BYOD
        (None, None, "hw_attested", "byod_attested"),
        (None, None, "hw_isolated", "byod_isolated"),
        (None, None, "soft_only", "untrusted"),
        # Defensive: missing fields are treated as the most permissive
        # downgrade (untrusted), never as silent grants.
        (None, None, None, "untrusted"),
        ("intune", None, "hw_attested", "byod_attested"),  # compliance=None != compliant
        ("intune", "unknown", "hw_attested", "byod_attested"),
    ],
)
def test_effective_tier_matrix(mdm, compliance, strength, expected):
    assert (
        compute_effective_tier(
            mdm=mdm,
            compliance=compliance,
            hardware=_hardware_for(strength),
            strength=strength,
        )
        == expected
    )


def test_hw_attested_alone_does_not_imply_managed():
    """Pure BYOD with TPM ``hw_attested`` MUST remain at ``byod_attested``
    until the F2 MDM half lands. Doc gap explicit in the F3 spike prompt:
    ``managed_attested`` is not reachable without an MDM device id +
    compliance=compliant.
    """
    assert (
        compute_effective_tier(
            mdm=None,
            compliance=None,
            hardware="tpm_2.0",
            strength="hw_attested",
        )
        != "managed_attested"
    )


def test_managed_attested_requires_both_halves():
    # Sanity guard against the schema drifting.
    assert (
        compute_effective_tier(
            mdm="intune",
            compliance="compliant",
            hardware="tpm_2.0",
            strength="hw_attested",
        )
        == "managed_attested"
    )
