"""Device attestation claim — server-side authoritative compute.

See ``imp/attestation-claim-schema.md`` v1.0 for the canonical claim
shape, tier algorithm, and stale-window policy. This package is the
implementation of sections 1 + 2 + 5 of that doc on the Mastio side.

Exports:

* :func:`compute_effective_tier` — pure function over the four input
  fields the schema names. Used by the enrollment hook to stamp the
  initial tier, and (later, F5) by the policy decision point.
* :func:`is_stale` — true when ``stale_seconds`` exceeds the
  configured threshold; callers must downgrade ``compliance`` to
  ``unknown`` before re-evaluating the tier.
* :func:`build_attestation_claim` — assembles the JSON shape sez. 1.
  Convenience wrapper; the enrollment hook composes the dict
  directly with the device row, this helper exists so future call
  sites (admin re-attestation endpoint, dashboard preview) get the
  same canonical shape without duplication.
"""
from mcp_proxy.attestation.tier import (
    build_attestation_claim,
    compute_effective_tier,
    is_stale,
)

__all__ = ["build_attestation_claim", "compute_effective_tier", "is_stale"]
