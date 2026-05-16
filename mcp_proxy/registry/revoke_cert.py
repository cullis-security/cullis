"""Agent cert revocation helper (ADR-032 F6).

Sits between the F6 polling-driven compliance reconciler and the
existing ``internal_agents`` table. The reconciler decides ``this
agent should lose access right now``; this module is the single
write point so the dashboard, audit, and metrics all agree on the
shape of a revocation.

Mechanics:

* Sets ``is_active=0`` so the next handshake fails at
  :mod:`mcp_proxy.auth.client_cert` (existing pin returns 401 once
  the row is inactive).
* Stamps ``revoked_at`` + ``revoked_reason`` (added by migration
  ``0037_audit_dev_attest``) so the dashboard + forensic queries
  have a fast-path source of truth without having to walk the audit
  log.
* Emits an ``agent.revoked`` audit row with the structured reason.
* Bumps ``federation_revision`` so the federation publisher carries
  the revocation to the Court (same shape as :func:`deactivate_agent`).

Idempotent: if the agent is already revoked the helper is a no-op
and returns ``False``. Callers (notably the per-tick compliance
reconciler in :mod:`mcp_proxy.mdm.compliance_change`) rely on this
so they can call the helper unconditionally on every observed
flip without double-emitting audit rows or skewing metrics.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

import json

from mcp_proxy.db import get_db, log_audit
from mcp_proxy.telemetry_metrics import ATTESTATION_REVOCATIONS

_log = logging.getLogger("mcp_proxy.registry.revoke_cert")

# Stable reason codes — exposed to the dashboard + audit detail. Add
# new codes here rather than free-form strings at the call site so
# customers running compliance reports can filter on a stable enum.
REASON_INSUFFICIENT_COMPLIANCE = "insufficient_compliance"
REASON_ADMIN = "admin_revocation"
REASON_ATTESTATION_FAILED = "attestation_failed"


async def revoke_agent_cert(
    agent_id: str,
    *,
    reason_code: str,
    reason_detail: str | None = None,
    mdm: str | None = None,
    conn: AsyncConnection | None = None,
    now: datetime | None = None,
) -> bool:
    """Mark ``internal_agents.agent_id`` as revoked.

    Args:
        agent_id: The agent to revoke. No-op if the agent does not
            exist; logs a warning so a polling-loop typo surfaces.
        reason_code: Stable enum from this module (e.g.
            :data:`REASON_INSUFFICIENT_COMPLIANCE`). Free-form values
            are accepted but discouraged.
        reason_detail: Optional free-form human-readable detail (e.g.
            the Intune device_id or the policy clause that failed).
            Stored in the audit row's detail JSON; NOT in the
            ``revoked_reason`` column (which holds the stable code).
        mdm: Optional MDM label for the metric counter. Defaults to
            ``"none"`` for admin / non-MDM revocations.
        conn: Optional pre-opened connection. When provided, the
            UPDATE runs on the caller's transaction (used by the
            compliance reconciler so the revocation + audit row land
            atomically with the cache update). When ``None``, the
            helper opens its own connection.
        now: Override timestamp for tests.

    Returns:
        ``True`` if the row transitioned from active to revoked.
        ``False`` if the agent did not exist or was already revoked.
        Metric + audit emission are gated on ``True`` so a redundant
        call doesn't pollute the signal.
    """
    now = now or datetime.now(timezone.utc)

    async def _run(c: AsyncConnection) -> bool:
        existing = (await c.execute(
            text(
                "SELECT is_active, revoked_at FROM internal_agents "
                "WHERE agent_id = :aid"
            ),
            {"aid": agent_id},
        )).mappings().first()

        if existing is None:
            _log.warning(
                "revoke_agent_cert: no internal_agents row for %s — "
                "ignoring revocation request (reason=%s)",
                agent_id, reason_code,
            )
            return False

        if existing.get("revoked_at") is not None:
            # Already revoked. Idempotent path — do not bump revoked_at
            # so the original revocation timestamp remains the audit
            # anchor.
            return False

        # ``is_active=0`` is the load-bearing flag; revoked_at /
        # revoked_reason are forensic decoration. Bumping
        # federation_revision matches the deactivate_agent contract so
        # the Court learns about the revocation via the next publisher
        # tick.
        result = await c.execute(
            text(
                """UPDATE internal_agents
                      SET is_active = 0,
                          revoked_at = :ts,
                          revoked_reason = :reason,
                          federation_revision = federation_revision + 1
                    WHERE agent_id = :aid
                      AND revoked_at IS NULL"""
            ),
            {
                "ts": now,
                "reason": reason_code,
                "aid": agent_id,
            },
        )
        return result.rowcount > 0

    audit_details = {
        "reason_code": reason_code,
        "reason_detail": reason_detail,
        "mdm": mdm,
        "revoked_at": now.isoformat(),
    }

    if conn is not None:
        transitioned = await _run(conn)
        if not transitioned:
            return False
        # Caller holds a transaction — emit the audit row on the same
        # connection via raw SQL. log_audit() opens its own connection
        # and would deadlock against the open writer on SQLite (the
        # same pattern :mod:`mcp_proxy.attestation.enrollment_hook`
        # relies on). Chain columns left NULL; verify_audit_chain
        # skips NULL rows by convention.
        detail_json = json.dumps(
            audit_details, separators=(",", ":"),
            sort_keys=True, default=str,
        )
        try:
            await conn.execute(
                text(
                    """INSERT INTO audit_log
                       (timestamp, agent_id, action, status, detail)
                       VALUES
                       (:ts, :aid, :action, :status, :detail)"""
                ),
                {
                    "ts": now.isoformat(),
                    "aid": agent_id,
                    "action": "agent.revoked",
                    "status": "success",
                    "detail": detail_json,
                },
            )
        except Exception as exc:  # noqa: BLE001 — audit failure must not roll back the revocation
            _log.warning(
                "revoke_agent_cert: agent %s revoked but inline audit "
                "emit failed: %s", agent_id, exc,
            )
    else:
        async with get_db() as c:
            transitioned = await _run(c)
        if not transitioned:
            return False
        # No caller transaction — route through log_audit so the row
        # picks up the batched chain (F0.4 / ADR-033) when enabled.
        try:
            await log_audit(
                agent_id=agent_id,
                action="agent.revoked",
                status="success",
                details=audit_details,
            )
        except Exception as exc:  # noqa: BLE001 — never block revocation on audit
            _log.warning(
                "revoke_agent_cert: agent %s revoked but audit emit "
                "failed: %s", agent_id, exc,
            )

    ATTESTATION_REVOCATIONS.labels(
        mdm=(mdm or "none"), reason=reason_code,
    ).inc()

    _log.info(
        "Revoked agent %s (reason=%s, mdm=%s)",
        agent_id, reason_code, mdm or "none",
    )
    return True
