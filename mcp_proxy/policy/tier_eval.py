"""Server-authoritative effective-tier resolution for a principal.

ADR-032 Decision E / F5. The Connector emits an attestation claim on
every MCP envelope (R2 wire-up), but that claim is advisory — the
Mastio is the authoritative source for ``effective_tier`` because
*it* enforces the capability gate. This module owns the read path:

* Look up ``internal_agents.last_attestation`` (TEXT NULL, JSON-
  serialised claim, populated by F2 enrollment hook).
* Parse the JSON; bail to ``untrusted`` on any decode failure.
* Apply the stale-window downgrade per schema sez. 5 so a fresh
  customer-incompliance signal forces the tier to drop without
  waiting for the next Intune polling cycle.
* Return the recomputed ``effective_tier`` (not the claim's stored
  value — schema sez. 7: server recomputes from inputs so a
  tampered claim can only lower, never raise).

The helper is intentionally synchronous in spirit (no DB session
needed beyond ``get_agent``) and async in shape so callers can
``await`` without restructuring.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from mcp_proxy.attestation.tier import (
    TIER_UNTRUSTED,
    apply_stale_downgrade,
    compute_effective_tier,
)
from mcp_proxy.db import get_agent

_log = logging.getLogger("mcp_proxy.policy.tier_eval")

# Stale threshold in seconds. Default 15 min per schema-doc sez. 5
# (Intune polling cycle). Configurable via env so an operator can
# tighten the window for a high-trust deployment without rebuilding
# the bundle.
ENV_STALE_THRESHOLD = "MCP_PROXY_ATTESTATION_STALE_THRESHOLD_SECONDS"
DEFAULT_STALE_THRESHOLD_SECONDS = 900


def _resolve_stale_threshold() -> int:
    """Read the configured stale threshold. Falls back to the default
    when the env var is missing or malformed."""
    raw = os.environ.get(ENV_STALE_THRESHOLD)
    if not raw:
        return DEFAULT_STALE_THRESHOLD_SECONDS
    try:
        value = int(raw)
    except (TypeError, ValueError):
        _log.warning(
            "%s=%s is not an int — using default %ds",
            ENV_STALE_THRESHOLD, raw, DEFAULT_STALE_THRESHOLD_SECONDS,
        )
        return DEFAULT_STALE_THRESHOLD_SECONDS
    if value < 0:
        _log.warning(
            "%s=%d is negative — using default %ds",
            ENV_STALE_THRESHOLD, value, DEFAULT_STALE_THRESHOLD_SECONDS,
        )
        return DEFAULT_STALE_THRESHOLD_SECONDS
    return value


def _safe_parse_attestation(raw: Any) -> dict | None:
    """JSON-decode ``raw`` into a dict; return ``None`` on any failure.

    Tolerates ``None`` (no claim recorded yet) + ``""`` (empty TEXT
    column) + malformed JSON without raising. The caller treats a
    ``None`` return as "no claim, default to untrusted".
    """
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _recompute_tier_from_claim(claim: dict) -> str:
    """Run the server-side tier function over the claim's inner block.

    Schema sez. 7: the server NEVER trusts the claim's stored
    ``effective_tier`` value. We pull the input fields out and
    recompute, so a forged claim that claims ``managed_attested``
    while carrying ``strength=soft_only`` collapses back to its
    real tier on every check.
    """
    inner = claim.get("device_attestation") or {}
    return compute_effective_tier(
        mdm=inner.get("mdm"),
        compliance=inner.get("compliance") or "unknown",
        hardware=inner.get("hardware"),
        strength=inner.get("strength") or "soft_only",
    )


async def resolve_effective_tier(agent_id: str) -> tuple[str, dict | None]:
    """Return ``(effective_tier, raw_claim)`` for ``agent_id``.

    * ``effective_tier`` is the server-recomputed value (always one
      of the five canonical tier strings). Never ``None`` — callers
      can use it directly in a comparison.
    * ``raw_claim`` is the JSON-decoded claim dict, or ``None`` when
      the agent has no claim on record. Audit emitters embed it
      under ``device_attestation_ref`` so a forensic query sees the
      exact bytes the gate evaluated against.

    Failure modes (every one collapses to ``untrusted`` so a missing
    claim defaults to the most restrictive bucket):

    * agent row not found → ``("untrusted", None)``
    * ``last_attestation`` is NULL / empty → ``("untrusted", None)``
    * JSON malformed → ``("untrusted", None)``, WARN log
    """
    try:
        agent_row = await get_agent(agent_id)
    except Exception as exc:  # noqa: BLE001 — DB outage must not crash gate
        _log.warning(
            "tier resolution: get_agent(%s) raised %s — defaulting to untrusted",
            agent_id, exc,
        )
        return TIER_UNTRUSTED, None
    if agent_row is None:
        return TIER_UNTRUSTED, None

    claim = _safe_parse_attestation(agent_row.get("last_attestation"))
    if claim is None:
        return TIER_UNTRUSTED, None

    threshold = _resolve_stale_threshold()
    claim = apply_stale_downgrade(claim, threshold_seconds=threshold)
    tier = _recompute_tier_from_claim(claim)
    return tier, claim


__all__ = [
    "DEFAULT_STALE_THRESHOLD_SECONDS",
    "ENV_STALE_THRESHOLD",
    "resolve_effective_tier",
]
