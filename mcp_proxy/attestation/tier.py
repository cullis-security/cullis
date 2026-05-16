"""Effective-tier algorithm + claim builder.

Locked against ``imp/attestation-claim-schema.md`` v1.0 sez. 2 + sez. 5.
Any change to the algorithm requires a schema version bump (sez. 8)
and a coordinated update in the Connector (which computes the same
function for UX purposes).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Tier values. Ordered low-to-high so future code can do "compare
# tiers" by index without re-encoding the matrix.
TIER_UNTRUSTED = "untrusted"
TIER_BYOD_ISOLATED = "byod_isolated"
TIER_BYOD_ATTESTED = "byod_attested"
TIER_MANAGED = "managed"
TIER_MANAGED_ATTESTED = "managed_attested"

# Strength values per schema sez. 1.
STRENGTH_HW_ATTESTED = "hw_attested"
STRENGTH_HW_ISOLATED = "hw_isolated"
STRENGTH_SOFT_ONLY = "soft_only"

# Compliance values per schema sez. 1.
COMPLIANCE_COMPLIANT = "compliant"
COMPLIANCE_NON_COMPLIANT = "non_compliant"
COMPLIANCE_UNKNOWN = "unknown"


def compute_effective_tier(
    mdm: str | None,
    compliance: str,
    hardware: str | None,
    strength: str,
) -> str:
    """Return the effective tier per schema sez. 2.

    Inputs are tolerated as ``None`` / unknown strings for forward
    compatibility — any value outside the schema enum collapses into
    the most restrictive bucket. The algorithm is intentionally
    branchless once normalised so a tampered claim cannot push the
    tier above what the actual inputs justify.
    """
    has_mdm = mdm is not None and compliance == COMPLIANCE_COMPLIANT

    if has_mdm and strength == STRENGTH_HW_ATTESTED:
        return TIER_MANAGED_ATTESTED
    if has_mdm:
        return TIER_MANAGED
    if strength == STRENGTH_HW_ATTESTED:
        return TIER_BYOD_ATTESTED
    if strength == STRENGTH_HW_ISOLATED:
        return TIER_BYOD_ISOLATED
    return TIER_UNTRUSTED


def is_stale(stale_seconds: int, threshold_seconds: int) -> bool:
    """True when the claim age exceeds the operator-configured threshold.

    Threshold ≤ 0 disables the staleness check (tests + dev only).
    A negative or non-int ``stale_seconds`` is treated as fresh; the
    server is authoritative for ``stale_seconds`` (computed from
    ``verified_at`` at evaluation time) so a tampered value can only
    push the claim toward more-fresh, not more-stale.
    """
    if threshold_seconds <= 0:
        return False
    try:
        return int(stale_seconds) > threshold_seconds
    except (TypeError, ValueError):
        return False


def build_attestation_claim(
    *,
    mdm: str | None,
    device_id: str | None,
    compliance: str,
    manufacturer: str | None,
    verified_at: datetime,
    now: datetime | None = None,
    hardware: str | None = None,
    strength: str = STRENGTH_SOFT_ONLY,
) -> dict[str, Any]:
    """Assemble the canonical claim dict (schema sez. 1).

    ``effective_tier`` is recomputed here so the caller cannot pass
    a forged value through. ``stale_seconds`` is derived from
    ``now - verified_at`` for the same reason.
    """
    now = now or datetime.now(timezone.utc)
    if verified_at.tzinfo is None:
        verified_at = verified_at.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    stale_seconds = max(0, int((now - verified_at).total_seconds()))

    return {
        "device_attestation": {
            "mdm": mdm,
            "device_id": device_id,
            "compliance": compliance,
            "hardware": hardware,
            "strength": strength,
            "manufacturer": manufacturer,
            # The schema asks for ``YYYY-MM-DDThh:mm:ssZ`` (no
            # microseconds, trailing Z). ``isoformat`` would give
            # ``+00:00`` and microseconds; format explicitly.
            "verified_at": verified_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ",
            ),
            "stale_seconds": stale_seconds,
        },
        "effective_tier": compute_effective_tier(
            mdm=mdm, compliance=compliance,
            hardware=hardware, strength=strength,
        ),
    }


def apply_stale_downgrade(
    claim: dict[str, Any], threshold_seconds: int,
) -> dict[str, Any]:
    """Force ``compliance=unknown`` + recompute tier when stale.

    Operates on a claim returned by :func:`build_attestation_claim`.
    Returns a NEW dict; the input is not mutated so callers can keep
    the pre-downgrade claim for audit ("we saw it as compliant 17
    minutes ago, now treating as unknown").
    """
    inner = dict(claim.get("device_attestation") or {})
    stale_s = int(inner.get("stale_seconds") or 0)
    if not is_stale(stale_s, threshold_seconds):
        return claim

    inner["compliance"] = COMPLIANCE_UNKNOWN
    return {
        "device_attestation": inner,
        "effective_tier": compute_effective_tier(
            mdm=inner.get("mdm"),
            compliance=inner.get("compliance") or COMPLIANCE_UNKNOWN,
            hardware=inner.get("hardware"),
            strength=inner.get("strength") or STRENGTH_SOFT_ONLY,
        ),
    }
