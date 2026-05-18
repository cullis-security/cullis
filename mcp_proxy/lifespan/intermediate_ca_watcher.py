"""Background watcher for the Mastio Intermediate CA expiry.

Three-tier PKI hardening (audit 2026-05-18), Phase 4. Weekly tick
(by default) that compares ``self._mastio_ca_cert.not_valid_after``
against ``now``:

* ``> 180 days`` left: silent.
* ``< 180 days``: WARN log, audit row ``pki.intermediate_ca_expiry_warning``.
* ``< 60 days``: ERROR log, audit row ``pki.intermediate_ca_expiry_critical``.
* ``< 30 days``: trigger automatic rotation via
  :meth:`AgentManager.rotate_mastio_ca`, audit row
  ``pki.intermediate_ca_auto_rotate``.

The auto-rotate threshold is intentionally tight (30 days) so a
healthy 5-year cadence will fire it well clear of an operational
emergency, but a pathological clock-skew incident still has a
60-day window to surface as a WARN before the watcher takes action
on its own.

Leader-elected via :func:`mcp_proxy.lifespan.get_leader` so only one
worker runs the loop in a multi-worker deployment. Pattern matches
the other lifespan watchers (federation_subscriber, anomaly_evaluator,
quarantine_expiry — PR #784).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("mcp_proxy.lifespan.intermediate_ca_watcher")

# Default tick: once per 24h. Cheap, gives ample budget for the auto-
# rotate path to retry across a few days of transient errors before the
# 30-day window slams shut.
_DEFAULT_TICK_SECONDS = 24 * 60 * 60
_WARN_THRESHOLD_DAYS = 180
_CRITICAL_THRESHOLD_DAYS = 60
_AUTO_ROTATE_THRESHOLD_DAYS = 30


async def intermediate_ca_watcher_loop(
    agent_manager,
    *,
    tick_seconds: int = _DEFAULT_TICK_SECONDS,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Loop tail: check expiry, log/audit/rotate as configured.

    ``stop_event`` lets the lifespan signal a graceful shutdown so the
    loop returns promptly instead of sleeping out the current tick.
    """
    stop_event = stop_event or asyncio.Event()
    logger.info(
        "intermediate_ca_watcher loop starting (tick=%ds)", tick_seconds,
    )

    while not stop_event.is_set():
        try:
            await _check_once(agent_manager)
        except Exception as exc:  # noqa: BLE001 — defensive long-running loop
            logger.error(
                "intermediate_ca_watcher tick raised %s — continuing", exc,
            )

        # Sleep with an early-exit on stop_event so SIGTERM teardown
        # doesn't have to wait a full day for the loop to wake up.
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=tick_seconds)
        except asyncio.TimeoutError:
            pass

    logger.info("intermediate_ca_watcher loop stopped")


async def _check_once(agent_manager) -> None:
    """One tick of the watcher: read expiry, route to the right action."""
    from mcp_proxy.db import log_audit

    cert = getattr(agent_manager, "_mastio_ca_cert", None)
    if cert is None:
        # Intermediate not loaded yet (mid-bootstrap, or sign-halted).
        # Silent skip; the next tick will retry.
        return

    not_after = cert.not_valid_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    delta = not_after - now
    days_left = int(delta.total_seconds() / 86400)

    if days_left > _WARN_THRESHOLD_DAYS:
        # Healthy window — no log spam.
        return

    if days_left > _CRITICAL_THRESHOLD_DAYS:
        logger.warning(
            "Mastio Intermediate CA expires in %d days (< %d). "
            "Operator should schedule manual rotation soon.",
            days_left, _WARN_THRESHOLD_DAYS,
        )
        try:
            await log_audit(
                agent_id="system",
                action="pki.intermediate_ca_expiry_warning",
                status="success",
                detail=f"days_left={days_left}",
            )
        except Exception:
            pass
        return

    if days_left > _AUTO_ROTATE_THRESHOLD_DAYS:
        logger.error(
            "Mastio Intermediate CA expires in %d days (< %d). "
            "Auto-rotate will trigger at < %d days; operator action "
            "still preferred to keep the audit trail tied to a person.",
            days_left, _CRITICAL_THRESHOLD_DAYS,
            _AUTO_ROTATE_THRESHOLD_DAYS,
        )
        try:
            await log_audit(
                agent_id="system",
                action="pki.intermediate_ca_expiry_critical",
                status="success",
                detail=f"days_left={days_left}",
            )
        except Exception:
            pass
        return

    # Auto-rotate. Best-effort: if it fails we'll retry on the next
    # tick. The Intermediate stays valid until ``not_after`` so the
    # window between the first auto-rotate attempt and actual expiry
    # is the retry budget. With a 24h tick + 30-day threshold that
    # gives ~30 attempts before chain breakage.
    logger.error(
        "Mastio Intermediate CA expires in %d days — triggering "
        "auto-rotation (no operator on the wire).",
        days_left,
    )
    try:
        result = await agent_manager.rotate_mastio_ca(
            grace_days=14,
            operator="watcher",
            dry_run=False,
        )
        try:
            await log_audit(
                agent_id="system",
                action="pki.intermediate_ca_auto_rotate",
                status="success",
                detail=(
                    f"old_cn={result.get('old_intermediate_cn')!r} "
                    f"new_cn={result.get('new_intermediate_cn')!r} "
                    f"days_left_at_trigger={days_left}"
                ),
            )
        except Exception:
            pass
    except Exception as exc:
        logger.error(
            "intermediate_ca_watcher auto-rotate failed: %s — will "
            "retry on next tick (%ds)",
            exc, _DEFAULT_TICK_SECONDS,
        )
        try:
            await log_audit(
                agent_id="system",
                action="pki.intermediate_ca_auto_rotate",
                status="error",
                detail=f"error={type(exc).__name__} days_left={days_left}",
            )
        except Exception:
            pass


__all__ = ["intermediate_ca_watcher_loop"]
