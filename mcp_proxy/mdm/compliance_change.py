"""Diff fresh MDM state against the cache + react to compliance flips.

This module owns the F6 reconcile step: every polling tick the
poller hands the freshly-projected device rows to
:func:`reconcile_devices_and_revoke`, which:

1. Loads the cached compliance value for ``(mdm, device_id)``.
2. If the cached value is ``compliant`` and the fresh value is
   ``non_compliant``, finds every agent in ``internal_agents`` whose
   ``last_attestation`` claim is anchored to that device, revokes
   each cert (via :func:`mcp_proxy.registry.revoke_cert.revoke_agent_cert`),
   updates ``last_attestation`` with the new (downgraded) claim, and
   emits a ``device_attestation`` audit row with subtype ``revoked``.
3. If the cached value is ``non_compliant`` and the fresh value is
   ``compliant``, emits a ``device_attestation`` audit row with
   subtype ``verified``. Re-enabling the cert is intentionally NOT
   automatic — the Connector has to re-enroll explicitly so the
   operator stays in the loop (see runbook).
4. Other transitions (any → ``unknown``, ``unknown`` → known) are
   logged but do not revoke; ``unknown`` is the conservative bucket
   the schema reserves for transient state.

The function runs INSIDE the same transaction the poller's upsert
loop uses. Audit emission stays on that connection via the raw-SQL
path in :mod:`mcp_proxy.attestation.audit_events`, matching the
deadlock-avoidance pattern the enrollment hook established.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from mcp_proxy.attestation.audit_events import log_device_attestation_change
from mcp_proxy.attestation.tier import (
    STRENGTH_SOFT_ONLY,
    apply_stale_downgrade,
    build_attestation_claim,
)
from mcp_proxy.config import get_settings
from mcp_proxy.mdm.intune import project_device_row
from mcp_proxy.registry.revoke_cert import (
    REASON_INSUFFICIENT_COMPLIANCE,
    revoke_agent_cert,
)

_log = logging.getLogger("mcp_proxy.mdm.compliance_change")


@dataclass(frozen=True)
class ComplianceChange:
    """One observed device-state transition."""

    mdm: str
    device_id: str
    previous: str
    current: str
    affected_agents: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class ReconcileSummary:
    """Per-tick counters surfaced to the poller for logging."""

    devices_checked: int = 0
    transitions: int = 0
    revocations: int = 0
    reverifications: int = 0


async def _load_cached_compliance(
    conn: AsyncConnection, mdm: str, device_id: str,
) -> str | None:
    """Return the cached ``compliance`` for a device, or ``None`` if absent."""
    row = (await conn.execute(
        text(
            "SELECT compliance FROM mdm_device_state "
            "WHERE mdm = :mdm AND device_id = :did"
        ),
        {"mdm": mdm, "did": device_id},
    )).first()
    if row is None:
        return None
    return str(row[0]) if row[0] is not None else None


async def _find_agents_bound_to_device(
    conn: AsyncConnection, mdm: str, device_id: str,
) -> list[dict[str, Any]]:
    """Return the agent rows whose ``last_attestation`` matches the device.

    Schema decision (see ``imp/attestation-claim-schema.md`` sez. 4.1):
    the bridge from MDM device to agent is ``internal_agents.last_attestation``
    (JSON). There is no dedicated index; for a Mastio with O(hundreds)
    of agents the full scan is comfortably under 10ms. If a customer
    grows beyond that, the indexed alternative is a generated column
    on the JSON path — a P3 follow-up, not blocking F6.

    Returns a list of ``{agent_id, last_attestation, cert_pem,
    is_active, revoked_at}`` rows. Inactive / already-revoked agents
    are filtered downstream by :func:`revoke_agent_cert` (idempotent
    no-op).
    """
    rows = (await conn.execute(
        text(
            "SELECT agent_id, last_attestation, cert_pem, is_active, "
            "       revoked_at "
            "  FROM internal_agents "
            " WHERE last_attestation IS NOT NULL"
        ),
    )).mappings().all()

    matched: list[dict[str, Any]] = []
    for row in rows:
        claim_json = row.get("last_attestation")
        if not claim_json:
            continue
        try:
            claim = json.loads(claim_json)
        except (TypeError, ValueError):
            _log.warning(
                "agent %s has unparseable last_attestation — skipping",
                row.get("agent_id"),
            )
            continue
        attestation = claim.get("device_attestation") or {}
        if (
            attestation.get("mdm") == mdm
            and attestation.get("device_id") == device_id
        ):
            matched.append(dict(row))
    return matched


async def _update_agent_attestation(
    conn: AsyncConnection,
    agent_id: str,
    fresh_claim: Mapping[str, Any],
) -> None:
    """Rewrite ``internal_agents.last_attestation`` with the fresh claim."""
    claim_json = json.dumps(
        dict(fresh_claim), separators=(",", ":"),
        sort_keys=True, default=str,
    )
    await conn.execute(
        text(
            "UPDATE internal_agents SET last_attestation = :claim "
            "WHERE agent_id = :aid"
        ),
        {"claim": claim_json, "aid": agent_id},
    )


def _build_fresh_claim(
    *,
    mdm: str,
    device_id: str,
    compliance: str,
    manufacturer: str | None,
    now: datetime,
    hardware: str | None,
    strength: str,
    threshold_seconds: int,
) -> dict[str, Any]:
    """Build + downgrade a fresh claim for the reconciler.

    ``verified_at`` is the polling timestamp — the cache row's
    ``last_seen_at`` is functionally the same value (we just upserted
    it with ``now``), and using ``now`` keeps the call site free of an
    extra SELECT.
    """
    claim = build_attestation_claim(
        mdm=mdm,
        device_id=device_id,
        compliance=compliance,
        manufacturer=manufacturer,
        verified_at=now,
        now=now,
        hardware=hardware,
        strength=strength,
    )
    return apply_stale_downgrade(claim, threshold_seconds)


async def reconcile_devices_and_revoke(
    conn: AsyncConnection,
    *,
    fresh_devices: Iterable[Mapping[str, Any]],
    mdm: str = "intune",
    now: datetime | None = None,
) -> ReconcileSummary:
    """For each freshly-polled device, diff against the cache + react.

    Called by the poller AFTER ``upsert_device_rows`` so the cached
    value we read here is still the pre-upsert one (the upsert ran on
    a different connection / transaction in the F2 path).

    NOTE: in the current F2 implementation, :func:`upsert_device_rows`
    opens its own ``get_db`` connection block. F6 wires the reconciler
    BEFORE the upsert, on its own connection, so the pre-upsert
    compliance value is observable. The poller helper handles the
    ordering — this function just trusts that the connection passed
    in still sees the prior cached state.
    """
    now = now or datetime.now(timezone.utc)
    settings = get_settings()
    threshold_seconds = settings.attestation_stale_threshold_seconds

    summary = ReconcileSummary()
    transitions: list[ComplianceChange] = []

    for graph_device in fresh_devices:
        projected = project_device_row(graph_device)
        device_id = projected["device_id"]
        if not device_id:
            continue

        summary.devices_checked += 1
        fresh_compliance = projected["compliance"]
        previous_compliance = await _load_cached_compliance(
            conn, mdm, device_id,
        )

        if previous_compliance == fresh_compliance:
            continue
        if previous_compliance is None:
            # First time we see this device — no prior state to flip
            # from, so the F2 enrollment path will stamp the claim if
            # an agent later enrolls against it.
            continue

        summary.transitions += 1
        change = ComplianceChange(
            mdm=mdm,
            device_id=device_id,
            previous=previous_compliance,
            current=fresh_compliance,
        )

        if (
            previous_compliance == "compliant"
            and fresh_compliance == "non_compliant"
        ):
            agents = await _find_agents_bound_to_device(
                conn, mdm, device_id,
            )
            revoked_agent_ids: list[str] = []
            for agent in agents:
                fresh_claim = _build_fresh_claim(
                    mdm=mdm,
                    device_id=device_id,
                    compliance="non_compliant",
                    manufacturer=projected.get("manufacturer"),
                    now=now,
                    hardware=None,
                    strength=STRENGTH_SOFT_ONLY,
                    threshold_seconds=threshold_seconds,
                )
                transitioned = await revoke_agent_cert(
                    agent["agent_id"],
                    reason_code=REASON_INSUFFICIENT_COMPLIANCE,
                    reason_detail=(
                        f"Intune device {device_id} flipped to "
                        f"non_compliant; cert pinned to this device "
                        f"is no longer trusted."
                    ),
                    mdm=mdm,
                    conn=conn,
                    now=now,
                )
                # Gate attestation update + audit emission on
                # ``transitioned`` so a persistently non_compliant
                # device doesn't re-stamp the agent claim or emit a
                # redundant ``revoked`` audit row on every poll tick
                # (#749 follow-up). ``revoke_agent_cert`` stays
                # outside the guard: it is idempotent and its own
                # metric/audit are already gated on transition.
                if transitioned:
                    await _update_agent_attestation(
                        conn, agent["agent_id"], fresh_claim,
                    )
                    await log_device_attestation_change(
                        conn,
                        agent_id=agent["agent_id"],
                        event_subtype="revoked",
                        device_attestation=fresh_claim["device_attestation"],
                        effective_tier=fresh_claim["effective_tier"],
                        previous_compliance=previous_compliance,
                        trigger="polling",
                        now=now,
                    )
                    summary.revocations += 1
                    revoked_agent_ids.append(agent["agent_id"])
            change = ComplianceChange(
                mdm=change.mdm,
                device_id=change.device_id,
                previous=change.previous,
                current=change.current,
                affected_agents=tuple(revoked_agent_ids),
            )

        elif (
            previous_compliance == "non_compliant"
            and fresh_compliance == "compliant"
        ):
            agents = await _find_agents_bound_to_device(
                conn, mdm, device_id,
            )
            for agent in agents:
                fresh_claim = _build_fresh_claim(
                    mdm=mdm,
                    device_id=device_id,
                    compliance="compliant",
                    manufacturer=projected.get("manufacturer"),
                    now=now,
                    hardware=None,
                    strength=STRENGTH_SOFT_ONLY,
                    threshold_seconds=threshold_seconds,
                )
                # NOTE: we deliberately do NOT clear ``revoked_at`` —
                # re-trust requires an explicit Connector re-enrollment
                # so an operator stays in the loop. The audit row
                # records the device's return to compliance; the cert
                # itself stays revoked until re-issued.
                await log_device_attestation_change(
                    conn,
                    agent_id=agent["agent_id"],
                    event_subtype="verified",
                    device_attestation=fresh_claim["device_attestation"],
                    effective_tier=fresh_claim["effective_tier"],
                    previous_compliance=previous_compliance,
                    trigger="polling",
                    now=now,
                )
                summary.reverifications += 1
        else:
            _log.info(
                "Device %s transitioned %s -> %s — no revocation "
                "action (unknown state is the conservative bucket)",
                device_id, previous_compliance, fresh_compliance,
            )

        transitions.append(change)

    if transitions:
        _log.info(
            "MDM compliance reconcile: %d transitions, %d revocations, "
            "%d re-verifications across %d devices",
            summary.transitions, summary.revocations,
            summary.reverifications, summary.devices_checked,
        )
    return summary
