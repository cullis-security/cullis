"""F6 audit-event helpers for the ``device_attestation`` family.

Schema authority: ``imp/attestation-claim-schema.md`` sez. 4.2. The
formal ``action`` value is ``device_attestation``; the subtype lives
in the ``detail`` JSON under ``event_subtype`` (``verified`` /
``revoked`` / ``stale``).

Two emission paths:

* :func:`log_device_attestation_change` — caller already holds an
  open :class:`AsyncConnection` (typical inside
  :mod:`mcp_proxy.mdm.compliance_change`, which loops over devices
  inside a single transaction). Inserts the audit row via raw SQL on
  that connection, matching the deadlock-avoidance pattern in
  :mod:`mcp_proxy.attestation.enrollment_hook`. The hash-chain columns
  are left NULL — same convention as the F2 enrollment path; the
  verifier skips NULL rows. F6 does NOT chain these rows for the same
  reason: chaining them inside the per-tx INSERT would require either
  promoting the chain lock across transactions or splitting the loop,
  both regressions.

* :func:`emit_device_attestation_change_global` — caller does NOT hold
  a connection. Routes through the normal :func:`mcp_proxy.db.log_audit`
  path so the row picks up the batched chain (F0.4 / ADR-033) when
  enabled. Used by the stale-watcher daemon.

Both paths populate the new ``device_attestation`` + ``effective_tier``
audit columns (migration ``0037_audit_dev_attest``).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_log = logging.getLogger("mcp_proxy.attestation.audit_events")

# Event "action" column value. The schema reserves the slot; the
# subtype lives in the detail JSON so callers can filter without
# proliferating action values.
ACTION_DEVICE_ATTESTATION = "device_attestation"

# Event "action" emitted ONCE on circuit-breaker CLOSED->OPEN transition.
# Distinct from device_attestation because it concerns the integration
# health (Intune unreachable), not a particular device claim.
ACTION_MDM_POLLING_DEGRADED = "mdm_polling_degraded"

_SUBTYPE_VERIFIED = "verified"
_SUBTYPE_REVOKED = "revoked"
_SUBTYPE_STALE = "stale"

ALLOWED_SUBTYPES = frozenset({_SUBTYPE_VERIFIED, _SUBTYPE_REVOKED, _SUBTYPE_STALE})

_VALID_TRIGGERS = frozenset({"enrollment", "polling", "ttl_expired"})


def _build_detail_payload(
    *,
    event_subtype: str,
    device_attestation: Mapping[str, Any],
    effective_tier: str | None,
    previous_compliance: str | None,
    trigger: str,
    extra: Mapping[str, Any] | None = None,
) -> str:
    """Canonical JSON for the ``detail`` audit column.

    Sorts keys so the chain hash is stable across Python versions and
    so equality-style queries on the column work without normalisation.
    """
    payload: dict[str, Any] = {
        "event_subtype": event_subtype,
        "device_attestation": dict(device_attestation),
        "effective_tier": effective_tier,
        "previous_compliance": previous_compliance,
        "trigger": trigger,
    }
    if extra:
        for key, value in extra.items():
            # Caller-supplied keys do not overwrite the canonical
            # subtype / trigger / claim fields — those are the ones
            # downstream forensic queries key on.
            if key in payload:
                continue
            payload[key] = value
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)


async def log_device_attestation_change(
    conn: AsyncConnection,
    *,
    agent_id: str,
    event_subtype: str,
    device_attestation: Mapping[str, Any],
    effective_tier: str | None,
    previous_compliance: str | None,
    trigger: str,
    now: datetime | None = None,
    extra: Mapping[str, Any] | None = None,
) -> None:
    """Emit a ``device_attestation`` audit row on the caller's connection.

    Inputs are validated defensively: an unknown subtype / trigger logs
    a warning and falls back to a safe default, never raises. The
    motivation is the same as enrollment_hook: a transient bug in a
    caller must not break the polling loop or the request that triggered
    the audit. Forensic queries will surface the fallback values.
    """
    if event_subtype not in ALLOWED_SUBTYPES:
        _log.warning(
            "log_device_attestation_change: unknown subtype %r, "
            "falling back to %r",
            event_subtype, _SUBTYPE_VERIFIED,
        )
        event_subtype = _SUBTYPE_VERIFIED
    if trigger not in _VALID_TRIGGERS:
        _log.warning(
            "log_device_attestation_change: unknown trigger %r, "
            "falling back to 'polling'",
            trigger,
        )
        trigger = "polling"

    now = now or datetime.now(timezone.utc)
    detail_json = _build_detail_payload(
        event_subtype=event_subtype,
        device_attestation=device_attestation,
        effective_tier=effective_tier,
        previous_compliance=previous_compliance,
        trigger=trigger,
        extra=extra,
    )
    attestation_col = json.dumps(
        dict(device_attestation), separators=(",", ":"),
        sort_keys=True, default=str,
    )

    try:
        await conn.execute(
            text(
                """INSERT INTO audit_log
                   (timestamp, agent_id, action, status, detail,
                    device_attestation, effective_tier)
                   VALUES
                   (:ts, :aid, :action, :status, :detail,
                    :device_attestation, :effective_tier)"""
            ),
            {
                "ts": now.isoformat(),
                "aid": agent_id,
                "action": ACTION_DEVICE_ATTESTATION,
                "status": "success",
                "detail": detail_json,
                "device_attestation": attestation_col,
                "effective_tier": effective_tier,
            },
        )
    except Exception as exc:  # noqa: BLE001 — never break the caller on audit error
        _log.warning(
            "Failed to insert device_attestation:%s audit row for %s: %s",
            event_subtype, agent_id, exc,
        )


async def emit_device_attestation_change_global(
    *,
    agent_id: str,
    event_subtype: str,
    device_attestation: Mapping[str, Any],
    effective_tier: str | None,
    previous_compliance: str | None,
    trigger: str,
    extra: Mapping[str, Any] | None = None,
) -> None:
    """Emit through :func:`mcp_proxy.db.log_audit` (batched-chain aware).

    Use this from callers that do NOT already hold a transaction —
    notably the stale-watcher daemon, which runs on its own asyncio
    loop and would otherwise open and close a connection just to
    insert one row. The chain path handles the open/close + retries.
    """
    from mcp_proxy.db import log_audit

    if event_subtype not in ALLOWED_SUBTYPES:
        _log.warning(
            "emit_device_attestation_change_global: unknown subtype %r, "
            "falling back to %r",
            event_subtype, _SUBTYPE_VERIFIED,
        )
        event_subtype = _SUBTYPE_VERIFIED
    if trigger not in _VALID_TRIGGERS:
        _log.warning(
            "emit_device_attestation_change_global: unknown trigger %r, "
            "falling back to 'polling'",
            trigger,
        )
        trigger = "polling"

    details: dict[str, Any] = {
        "event_subtype": event_subtype,
        "device_attestation": dict(device_attestation),
        "effective_tier": effective_tier,
        "previous_compliance": previous_compliance,
        "trigger": trigger,
    }
    if extra:
        for key, value in extra.items():
            if key in details:
                continue
            details[key] = value

    try:
        await log_audit(
            agent_id=agent_id,
            action=ACTION_DEVICE_ATTESTATION,
            status="success",
            details=details,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "Failed to emit device_attestation:%s audit row for %s "
            "via log_audit: %s",
            event_subtype, agent_id, exc,
        )


async def emit_polling_degraded(
    *,
    mdm: str,
    consecutive_failures: int,
    last_error_status: int | None,
    last_error_message: str | None,
) -> None:
    """One-shot audit row on circuit-breaker CLOSED->OPEN transition.

    Schema author's intent (memoria ``feedback_h4_convergent_pattern_fallback_insecure_default``):
    when the MDM integration falls over, the operator must hear about
    it — silently downgrading to "compliance unknown" is the failure
    mode customers actually pay for visibility on.
    """
    from mcp_proxy.db import log_audit

    details = {
        "mdm": mdm,
        "consecutive_failures": int(consecutive_failures),
        "last_error_status": last_error_status,
        "last_error_message": last_error_message,
        "remediation": (
            "Check MCP_PROXY_MDM_INTUNE_* credentials and Graph API "
            "throttle headers. The polling loop stays in OPEN for the "
            "configured cooldown before a single probe."
        ),
    }
    try:
        await log_audit(
            agent_id="system",
            action=ACTION_MDM_POLLING_DEGRADED,
            status="failure",
            details=details,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "Failed to emit mdm_polling_degraded audit row for %s: %s",
            mdm, exc,
        )
