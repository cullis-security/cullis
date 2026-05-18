"""Background sweep that clears expired agent-cert grace rows.

Wave 2 fix 7+8, Phase 4. The rotation writers stash the old
``cert_pem`` / ``dpop_jkt`` into ``internal_agents.previous_*`` so the
pinning verifiers can fall back during a bounded window. After
``previous_grace_period_expires_at`` passes, those values must be
cleared, otherwise:

* the pinning dep keeps a stale cert / jkt in the "fall back to this"
  pool indefinitely, widening the trust surface beyond the configured
  ``MCP_PROXY_AGENT_CERT_GRACE_PERIOD_HOURS``;
* a future incident response can't tell "freshly rotated, in grace" from
  "rotated a year ago, just never cleaned up".

This loop ticks hourly by default and runs a single UPDATE that resets
all three previous_* columns to NULL where the grace expiry is in the
past. Leader-elected via :func:`mcp_proxy.lifespan.get_leader` so only
one worker runs the sweep in a multi-worker deployment — pattern from
PR #784 (six lifespan tasks leader-elected).

Audit row ``agent.cert_grace_period_expired`` lands once per agent
cleared, so the audit chain records the trust-surface collapse from
"two pins (current + previous)" back to "one pin".
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from sqlalchemy import text

logger = logging.getLogger("mcp_proxy.lifespan.agent_cert_grace_cleanup")

# Match the cadence ``mcp_proxy.config.ProxySettings`` exposes so the
# loop body and the default Settings stay in lock-step. The settings
# field is read at task spawn (lifespan), this constant is only the
# fallback when the task is spawned without an explicit interval.
_DEFAULT_TICK_SECONDS = 3600


async def agent_cert_grace_cleanup_loop(
    *,
    tick_seconds: int = _DEFAULT_TICK_SECONDS,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    """Loop body. Runs ``_sweep_once`` every ``tick_seconds``.

    ``stop_event`` lets the lifespan tear-down signal a prompt return
    so SIGTERM does not have to wait a full hour for the loop to wake
    up. Mirrors the contract of
    :func:`mcp_proxy.lifespan.intermediate_ca_watcher.intermediate_ca_watcher_loop`.
    """
    stop_event = stop_event or asyncio.Event()
    logger.info(
        "agent_cert_grace_cleanup loop starting (tick=%ds)", tick_seconds,
    )

    while not stop_event.is_set():
        try:
            await _sweep_once()
        except Exception as exc:  # noqa: BLE001 — defensive long-running loop
            logger.error(
                "agent_cert_grace_cleanup tick raised %s — continuing",
                exc,
            )

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=tick_seconds)
        except asyncio.TimeoutError:
            pass

    logger.info("agent_cert_grace_cleanup loop stopped")


async def _sweep_once() -> int:
    """Single-tick sweep. Returns the number of rows cleared.

    Two-step inside one transaction:

      1. SELECT the agent_ids with an expired ``previous_grace_period_expires_at``
         so the audit log can name them.
      2. UPDATE those rows, setting all three previous_* columns back
         to NULL.

    Idempotent: a tick that fires twice in a row with no expirations
    in-between updates zero rows and emits zero audit. The
    ``previous_grace_period_expires_at IS NOT NULL`` guard prevents
    cleaning up rows that never had a previous-stash to begin with.
    """
    from mcp_proxy.auth.cert_grace import now_utc_iso
    from mcp_proxy.db import get_db, log_audit

    now = now_utc_iso()

    async with get_db() as conn:
        expired_rows = (await conn.execute(
            text(
                """SELECT agent_id, previous_grace_period_expires_at
                     FROM internal_agents
                    WHERE previous_grace_period_expires_at IS NOT NULL
                      AND previous_grace_period_expires_at < :now"""
            ),
            {"now": now},
        )).mappings().all()

        if not expired_rows:
            return 0

        await conn.execute(
            text(
                """UPDATE internal_agents
                      SET previous_cert_pem = NULL,
                          previous_dpop_jkt = NULL,
                          previous_grace_period_expires_at = NULL
                    WHERE previous_grace_period_expires_at IS NOT NULL
                      AND previous_grace_period_expires_at < :now"""
            ),
            {"now": now},
        )

    # Audit each cleared row outside the cleanup transaction so a
    # downstream audit-chain hiccup doesn't block the sweep. The
    # ordering is "row cleared, then audit emitted" — for a forensic
    # operator, the absence of the audit row + presence of NULL columns
    # is recoverable; the inverse (audit fired, columns still pinned
    # in grace) would be a confusing trust-surface lie.
    for row in expired_rows:
        try:
            await log_audit(
                agent_id=row["agent_id"],
                action="agent.cert_grace_period_expired",
                status="success",
                detail=(
                    f"grace_expired_at={row['previous_grace_period_expires_at']} "
                    f"cleared_at={now}"
                ),
            )
        except Exception as exc:  # noqa: BLE001 — best-effort
            logger.debug(
                "agent.cert_grace_period_expired audit emit failed for "
                "agent=%s: %s",
                row["agent_id"], exc,
            )

    logger.info(
        "agent_cert_grace_cleanup: swept %d expired rows", len(expired_rows),
    )
    return len(expired_rows)


__all__ = ["agent_cert_grace_cleanup_loop", "_sweep_once"]
