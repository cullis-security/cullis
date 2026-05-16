"""Stale-window watcher (ADR-032 F6 / schema sez. 5).

A background daemon that wakes every
``MCP_PROXY_ATTESTATION_STALE_WATCHER_INTERVAL_SECONDS`` (default 60s),
scans ``internal_agents.last_attestation`` for claims whose
``verified_at`` is older than the configured stale threshold, and
emits a ``device_attestation`` audit row of subtype ``stale`` the
FIRST time an agent crosses the boundary.

Dedupe via ``internal_agents.last_stale_event_at`` (added by
migration ``0037_audit_dev_attest``): the watcher only emits when
``verified_at + threshold < now`` AND ``last_stale_event_at`` is
either ``NULL`` or older than the latest ``verified_at`` (the latter
catches the case where the agent re-attested, then went stale again).

Important non-goals:

* Does NOT revoke the agent. Stale is a "we don't know its current
  posture" signal, not a "we know it's bad" signal. The policy gate
  (F5) downgrades the effective tier on stale claims; that's the
  enforcement surface.
* Does NOT cross-check the MDM cache. If the device cache itself is
  stale (Intune polling down), the breaker in
  :mod:`mcp_proxy.mdm.circuit_breaker` is the right surface to
  signal that condition.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from mcp_proxy._lifespan_log import emit_lifespan_log
from mcp_proxy.attestation.audit_events import emit_device_attestation_change_global
from mcp_proxy.attestation.tier import apply_stale_downgrade
from mcp_proxy.db import get_db
from mcp_proxy.telemetry_metrics import ATTESTATION_STALE_EVENTS

_log = logging.getLogger("mcp_proxy.mdm.stale_watcher")


def _parse_verified_at(raw: str | None) -> datetime | None:
    """Tolerantly parse the ``verified_at`` field from a stored claim."""
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _coerce_dt(value) -> datetime | None:
    """Normalise a ``last_stale_event_at`` value from SQLite/Postgres."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


async def scan_once(*, threshold_seconds: int, now: datetime | None = None) -> int:
    """One sweep over ``internal_agents``. Returns rows audited.

    Walks the whole table; for a Mastio with a few hundred agents
    this is sub-millisecond. The :func:`emit_device_attestation_change_global`
    call routes the audit row through the batched chain (F0.4 /
    ADR-033) when registered, so the per-row write is not a
    bottleneck even on a large tenant.
    """
    now = now or datetime.now(timezone.utc)

    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                "SELECT agent_id, last_attestation, last_stale_event_at "
                "  FROM internal_agents "
                " WHERE last_attestation IS NOT NULL"
            ),
        )).mappings().all()

        audited = 0
        for row in rows:
            agent_id = row["agent_id"]
            claim_json = row["last_attestation"]
            try:
                claim = json.loads(claim_json)
            except (TypeError, ValueError):
                continue
            inner = claim.get("device_attestation") or {}
            verified_at = _parse_verified_at(inner.get("verified_at"))
            if verified_at is None:
                continue

            age = (now - verified_at).total_seconds()
            if age <= threshold_seconds:
                continue

            last_event_at = _coerce_dt(row["last_stale_event_at"])
            if last_event_at is not None and last_event_at >= verified_at:
                # Already emitted a stale event for this attestation
                # epoch; nothing new to report.
                continue

            downgraded = apply_stale_downgrade(claim, threshold_seconds)
            await emit_device_attestation_change_global(
                agent_id=agent_id,
                event_subtype="stale",
                device_attestation=downgraded["device_attestation"],
                effective_tier=downgraded["effective_tier"],
                previous_compliance=inner.get("compliance"),
                trigger="ttl_expired",
            )
            await conn.execute(
                text(
                    "UPDATE internal_agents "
                    "   SET last_stale_event_at = :ts "
                    " WHERE agent_id = :aid"
                ),
                {"ts": now, "aid": agent_id},
            )
            ATTESTATION_STALE_EVENTS.labels(
                mdm=(inner.get("mdm") or "none"),
            ).inc()
            audited += 1

    if audited:
        _log.info(
            "Stale-watcher: emitted %d device_attestation:stale events",
            audited,
        )
    return audited


async def stale_watcher_loop(
    *,
    interval_seconds: int,
    threshold_seconds: int,
    stop_event: asyncio.Event,
) -> None:
    """Long-running daemon. Exits when ``stop_event`` is set.

    Single-iteration errors are isolated; the daemon keeps running.
    The interval/threshold are passed in (not re-read from settings
    each tick) so tests can drive a tight loop without touching env.
    """
    emit_lifespan_log(
        level="INFO",
        logger="mcp_proxy.mdm.stale_watcher",
        message=(
            "Attestation stale-watcher started "
            f"(interval={interval_seconds}s, threshold={threshold_seconds}s)"
        ),
    )
    try:
        while not stop_event.is_set():
            try:
                await scan_once(threshold_seconds=threshold_seconds)
            except Exception as exc:  # noqa: BLE001 — defensive
                _log.exception(
                    "Stale-watcher sweep failed (continuing): %r", exc,
                )
            try:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=interval_seconds,
                )
            except asyncio.TimeoutError:
                pass
    finally:
        emit_lifespan_log(
            level="INFO",
            logger="mcp_proxy.mdm.stale_watcher",
            message="Attestation stale-watcher stopped",
        )
