"""Effective-tier algorithm coverage (ADR-032 schema sez. 2).

Pure-function tests — no fixtures, no I/O. The algorithm is locked
against the schema doc and any change here means a schema version
bump.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mcp_proxy.attestation.tier import (
    COMPLIANCE_COMPLIANT,
    COMPLIANCE_NON_COMPLIANT,
    COMPLIANCE_UNKNOWN,
    STRENGTH_HW_ATTESTED,
    STRENGTH_HW_ISOLATED,
    STRENGTH_SOFT_ONLY,
    TIER_BYOD_ATTESTED,
    TIER_BYOD_ISOLATED,
    TIER_MANAGED,
    TIER_MANAGED_ATTESTED,
    TIER_UNTRUSTED,
    apply_stale_downgrade,
    build_attestation_claim,
    compute_effective_tier,
    is_stale,
)


# ── 5-tier matrix ──────────────────────────────────────────────────


def test_managed_attested_requires_mdm_compliant_and_hw_attested():
    tier = compute_effective_tier(
        mdm="intune",
        compliance=COMPLIANCE_COMPLIANT,
        hardware="tpm_2.0",
        strength=STRENGTH_HW_ATTESTED,
    )
    assert tier == TIER_MANAGED_ATTESTED


def test_managed_when_mdm_compliant_but_soft_only():
    tier = compute_effective_tier(
        mdm="intune",
        compliance=COMPLIANCE_COMPLIANT,
        hardware=None,
        strength=STRENGTH_SOFT_ONLY,
    )
    assert tier == TIER_MANAGED


def test_byod_attested_when_no_mdm_but_hw_attested():
    tier = compute_effective_tier(
        mdm=None,
        compliance=COMPLIANCE_UNKNOWN,
        hardware="tpm_2.0",
        strength=STRENGTH_HW_ATTESTED,
    )
    assert tier == TIER_BYOD_ATTESTED


def test_byod_isolated_when_no_mdm_but_hw_isolated():
    tier = compute_effective_tier(
        mdm=None,
        compliance=COMPLIANCE_UNKNOWN,
        hardware=None,
        strength=STRENGTH_HW_ISOLATED,
    )
    assert tier == TIER_BYOD_ISOLATED


def test_untrusted_when_no_mdm_and_no_hw():
    tier = compute_effective_tier(
        mdm=None,
        compliance=COMPLIANCE_UNKNOWN,
        hardware=None,
        strength=STRENGTH_SOFT_ONLY,
    )
    assert tier == TIER_UNTRUSTED


# ── Non-compliant MDM degrades to BYOD bucket ──────────────────────


def test_non_compliant_mdm_does_not_grant_managed_tier():
    """Schema sez. 2: ``has_mdm`` only when compliance == compliant."""
    tier = compute_effective_tier(
        mdm="intune",
        compliance=COMPLIANCE_NON_COMPLIANT,
        hardware="tpm_2.0",
        strength=STRENGTH_HW_ATTESTED,
    )
    assert tier == TIER_BYOD_ATTESTED  # NOT managed_attested


def test_unknown_compliance_does_not_grant_managed_tier():
    tier = compute_effective_tier(
        mdm="intune",
        compliance=COMPLIANCE_UNKNOWN,
        hardware=None,
        strength=STRENGTH_SOFT_ONLY,
    )
    assert tier == TIER_UNTRUSTED


# ── is_stale ───────────────────────────────────────────────────────


def test_is_stale_under_threshold():
    assert is_stale(stale_seconds=100, threshold_seconds=900) is False


def test_is_stale_over_threshold():
    assert is_stale(stale_seconds=901, threshold_seconds=900) is True


def test_is_stale_disabled_when_threshold_zero():
    assert is_stale(stale_seconds=10_000, threshold_seconds=0) is False


def test_is_stale_negative_threshold_treated_as_disabled():
    assert is_stale(stale_seconds=10_000, threshold_seconds=-1) is False


def test_is_stale_invalid_input_treated_as_fresh():
    """Server is authoritative on stale_seconds; defensive only."""
    assert is_stale(stale_seconds="bogus", threshold_seconds=900) is False  # type: ignore[arg-type]


# ── build_attestation_claim ────────────────────────────────────────


def test_build_claim_shape_matches_schema():
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    verified_at = now - timedelta(seconds=300)
    claim = build_attestation_claim(
        mdm="intune",
        device_id="61b8d3f4-aef1",
        compliance=COMPLIANCE_COMPLIANT,
        manufacturer="Infineon",
        verified_at=verified_at,
        now=now,
        hardware="tpm_2.0",
        strength=STRENGTH_HW_ATTESTED,
    )
    inner = claim["device_attestation"]
    assert inner["mdm"] == "intune"
    assert inner["device_id"] == "61b8d3f4-aef1"
    assert inner["compliance"] == "compliant"
    assert inner["hardware"] == "tpm_2.0"
    assert inner["strength"] == "hw_attested"
    assert inner["manufacturer"] == "Infineon"
    assert inner["verified_at"] == "2026-05-17T11:55:00Z"
    assert inner["stale_seconds"] == 300
    assert claim["effective_tier"] == TIER_MANAGED_ATTESTED


def test_build_claim_normalises_naive_datetime_to_utc():
    now = datetime(2026, 5, 17, 12, 0, 0)  # naive
    verified_at = datetime(2026, 5, 17, 11, 59, 0)  # naive
    claim = build_attestation_claim(
        mdm=None,
        device_id=None,
        compliance=COMPLIANCE_UNKNOWN,
        manufacturer=None,
        verified_at=verified_at,
        now=now,
    )
    # 60 seconds difference; stale_seconds is int(non-negative)
    assert claim["device_attestation"]["stale_seconds"] == 60
    assert claim["device_attestation"]["verified_at"].endswith("Z")


def test_build_claim_clamps_negative_stale_to_zero():
    """Clock skew between MDM cache and Mastio shouldn't go negative."""
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    future_verified = now + timedelta(seconds=30)
    claim = build_attestation_claim(
        mdm=None, device_id=None,
        compliance=COMPLIANCE_UNKNOWN, manufacturer=None,
        verified_at=future_verified, now=now,
    )
    assert claim["device_attestation"]["stale_seconds"] == 0


# ── apply_stale_downgrade ──────────────────────────────────────────


def test_apply_stale_downgrade_unchanged_when_fresh():
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    fresh = build_attestation_claim(
        mdm="intune", device_id="x",
        compliance=COMPLIANCE_COMPLIANT, manufacturer=None,
        verified_at=now - timedelta(seconds=120), now=now,
    )
    result = apply_stale_downgrade(fresh, threshold_seconds=900)
    assert result["device_attestation"]["compliance"] == "compliant"
    assert result["effective_tier"] == TIER_MANAGED


def test_apply_stale_downgrade_forces_unknown_when_stale():
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    stale = build_attestation_claim(
        mdm="intune", device_id="x",
        compliance=COMPLIANCE_COMPLIANT, manufacturer=None,
        verified_at=now - timedelta(seconds=1200), now=now,
    )
    # Pre-downgrade should still be 'compliant' even though stale_seconds
    # exceeds the threshold — the claim builder doesn't apply policy.
    assert stale["device_attestation"]["compliance"] == "compliant"
    assert stale["effective_tier"] == TIER_MANAGED

    result = apply_stale_downgrade(stale, threshold_seconds=900)
    assert result["device_attestation"]["compliance"] == "unknown"
    # No MDM-compliant → falls through to untrusted (no hw).
    assert result["effective_tier"] == TIER_UNTRUSTED


def test_apply_stale_downgrade_returns_new_dict():
    """The pre-downgrade claim is preserved for audit."""
    now = datetime(2026, 5, 17, 12, 0, 0, tzinfo=timezone.utc)
    stale = build_attestation_claim(
        mdm="intune", device_id="x",
        compliance=COMPLIANCE_COMPLIANT, manufacturer=None,
        verified_at=now - timedelta(seconds=1200), now=now,
    )
    pre = dict(stale["device_attestation"])
    _ = apply_stale_downgrade(stale, threshold_seconds=900)
    # Original input untouched.
    assert stale["device_attestation"] == pre
