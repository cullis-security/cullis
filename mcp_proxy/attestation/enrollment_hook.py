"""Bridge between Connector enrollment and the MDM cache.

When the device-code enrollment flow approves a Connector
(``mcp_proxy/enrollment/service.py::approve``), this module looks up
the agent's device hint in ``mdm_device_state`` and, when a match
exists, stamps the canonical attestation claim on
``internal_agents.last_attestation`` plus an audit row of subtype
``device_attestation_verified``.

Hint extraction is best-effort. The Connector ships free-form JSON
in ``device_info``; if it contains an ``azure_ad_device_id`` (or
``intune_device_id`` / ``serial_number``) we use it. Absence is
expected for legacy Connectors and is not an error; the claim
simply doesn't get stamped and the agent operates at
``effective_tier=untrusted`` until re-enrolled.

The function is side-effect-only: caller still returns the
enrollment record verbatim, this module never modifies what the
HTTP response looks like.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from mcp_proxy.attestation.tier import (
    STRENGTH_SOFT_ONLY,
    apply_stale_downgrade,
    build_attestation_claim,
)
from mcp_proxy.config import get_settings

_log = logging.getLogger("mcp_proxy.attestation.enrollment_hook")


def _extract_device_hint(device_info: str | None) -> dict[str, str | None]:
    """Pull MDM lookup hints out of the Connector's ``device_info`` JSON.

    Returns a dict with possibly-empty values:
        - ``azure_ad_device_id`` (preferred — most reliable join key)
        - ``intune_device_id`` (also called ``id`` in Graph)
        - ``serial_number`` (last resort; not unique across vendors)
    Absent / malformed input yields an all-empty dict.
    """
    empty: dict[str, str | None] = {
        "azure_ad_device_id": None,
        "intune_device_id": None,
        "serial_number": None,
    }
    if not device_info:
        return empty
    try:
        parsed = json.loads(device_info)
    except (TypeError, ValueError):
        return empty
    if not isinstance(parsed, Mapping):
        return empty

    def _str_or_none(value: Any) -> str | None:
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    return {
        "azure_ad_device_id": _str_or_none(parsed.get("azure_ad_device_id")),
        "intune_device_id": _str_or_none(parsed.get("intune_device_id"))
            or _str_or_none(parsed.get("device_id")),
        "serial_number": _str_or_none(parsed.get("serial_number")),
    }


async def _lookup_device_row(
    conn: AsyncConnection,
    hints: dict[str, str | None],
) -> dict[str, Any] | None:
    """Find the freshest matching ``mdm_device_state`` row for these hints.

    Try azure_ad_device_id first (the most reliable join — set by
    Intune at MDM enrolment), then intune_device_id (Graph's own
    UUID), then serial_number. Returns ``None`` on no match.
    """
    if hints.get("azure_ad_device_id"):
        row = (await conn.execute(
            text(
                "SELECT mdm, device_id, compliance, manufacturer, "
                "last_seen_at FROM mdm_device_state "
                "WHERE azure_ad_device_id = :v "
                "ORDER BY last_seen_at DESC LIMIT 1"
            ),
            {"v": hints["azure_ad_device_id"]},
        )).mappings().first()
        if row:
            return dict(row)

    if hints.get("intune_device_id"):
        row = (await conn.execute(
            text(
                "SELECT mdm, device_id, compliance, manufacturer, "
                "last_seen_at FROM mdm_device_state "
                "WHERE mdm = 'intune' AND device_id = :v LIMIT 1"
            ),
            {"v": hints["intune_device_id"]},
        )).mappings().first()
        if row:
            return dict(row)

    if hints.get("serial_number"):
        row = (await conn.execute(
            text(
                "SELECT mdm, device_id, compliance, manufacturer, "
                "last_seen_at FROM mdm_device_state "
                "WHERE serial_number = :v "
                "ORDER BY last_seen_at DESC LIMIT 1"
            ),
            {"v": hints["serial_number"]},
        )).mappings().first()
        if row:
            return dict(row)

    return None


async def stamp_attestation_on_enrollment(
    conn: AsyncConnection,
    *,
    agent_id: str,
    device_info: str | None,
    session_id: str,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Look up the MDM cache + stamp the claim on the agent row.

    Called from ``mcp_proxy/enrollment/service.py::approve`` after the
    internal_agents row has been upserted.

    Returns the claim that was stamped (for tests / dashboard
    preview) or ``None`` when no device match was found. Always
    side-effects defensively: any error in the lookup or the
    audit emission is logged and swallowed so the enrollment
    response is unaffected. The Connector should still complete
    enrollment when MDM is offline or the device is BYOD.
    """
    hints = _extract_device_hint(device_info)
    now = now or datetime.now(timezone.utc)

    try:
        row = await _lookup_device_row(conn, hints)
    except Exception as exc:  # noqa: BLE001 — never block enrollment on MDM
        _log.warning(
            "MDM cache lookup failed for agent %s (continuing without "
            "attestation): %s", agent_id, exc,
        )
        return None

    if row is None:
        _log.info(
            "No MDM cache match for agent %s (hints=%s) — "
            "enrolling without device_attestation claim.",
            agent_id, {k: bool(v) for k, v in hints.items()},
        )
        return None

    # Parse last_seen_at. SQLite returns the raw text; Postgres
    # returns datetime. Tolerate both.
    raw_seen = row.get("last_seen_at")
    if isinstance(raw_seen, datetime):
        verified_at = raw_seen if raw_seen.tzinfo else raw_seen.replace(
            tzinfo=timezone.utc,
        )
    else:
        try:
            verified_at = datetime.fromisoformat(str(raw_seen).replace("Z", "+00:00"))
            if verified_at.tzinfo is None:
                verified_at = verified_at.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            verified_at = now

    settings = get_settings()
    claim = build_attestation_claim(
        mdm=row.get("mdm"),
        device_id=row.get("device_id"),
        compliance=row.get("compliance") or "unknown",
        manufacturer=row.get("manufacturer"),
        verified_at=verified_at,
        now=now,
        # F3 will plug in tpm_2.0 / hw_attested. Until then every
        # Intune device is software-attested only — managed but
        # not hardware-bound.
        hardware=None,
        strength=STRENGTH_SOFT_ONLY,
    )
    claim = apply_stale_downgrade(
        claim, settings.attestation_stale_threshold_seconds,
    )

    claim_json = json.dumps(
        claim, separators=(",", ":"), sort_keys=True, default=str,
    )

    try:
        await conn.execute(
            text(
                "UPDATE internal_agents SET last_attestation = :claim "
                "WHERE agent_id = :aid"
            ),
            {"claim": claim_json, "aid": agent_id},
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "Failed to stamp last_attestation on %s (continuing): %s",
            agent_id, exc,
        )
        return None

    # Audit event. Inserted on the SAME connection the caller already
    # holds — log_audit() opens its own connection and would deadlock
    # against the enrollment transaction under SQLite's single-writer
    # model. The hash-chain columns are left NULL; matches the
    # convention the existing approve() inline INSERTs use
    # (verify_audit_chain skips NULL rows). F6 owns the hash-chain
    # extension for device_attestation audit rows.
    audit_detail = json.dumps({
        "event_subtype": "verified",
        "device_attestation": claim["device_attestation"],
        "effective_tier": claim["effective_tier"],
        "trigger": "enrollment",
        "session_id": session_id,
    }, separators=(",", ":"), sort_keys=True, default=str)
    try:
        await conn.execute(
            text(
                """INSERT INTO audit_log
                   (timestamp, agent_id, action, status, detail)
                   VALUES (:ts, :aid, :action, 'success', :detail)"""
            ),
            {
                "ts": now.isoformat(),
                "aid": agent_id,
                "action": "device_attestation",
                "detail": audit_detail,
            },
        )
    except Exception as exc:  # noqa: BLE001 — audit failure shouldn't break enrollment
        _log.warning(
            "Failed to emit device_attestation audit row for %s: %s",
            agent_id, exc,
        )

    return claim
