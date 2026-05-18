"""Background watcher for cert expiry visibility across the PKI fleet.

Wave 2 fix 5 (three-tier PKI hardening follow-up, audit 2026-05-18).
A.k.a. "the visibility watcher": Phase 4 of the audit already added
``intermediate_ca_watcher`` (auto-rotation for the Mastio Intermediate
CA). This module covers the rest of the certificate fleet with
warning-only telemetry, no rotation:

* **Org Root CA** (15 years, cold private key): silent unless within
  ``warn_days_org_root`` of expiry. Operator MUST plan a manual
  rotation, the root is a one-shot at this scale.
* **Intermediate CA** (5 years, hot signer): fallback only. The
  primary watcher (``intermediate_ca_watcher``) handles warning +
  auto-rotation; this loop ONLY logs an INFO at a much wider
  fallback threshold so an operator who disables the primary watcher
  (e.g. air-gapped deploy) still has a visible reminder.
* **Mastio leaf** (1 year, manual rotation via dashboard): warn at
  ``warn_days_mastio_leaf`` (90 days default). Rotation requires a
  Court ACK round-trip, so the operator wants 90 days lead time.
* **Agent leaves** (1 year each, no warning today): warn at
  ``warn_days_agent`` (90 days default). One audit row per agent
  per tick when in-threshold, with the agent_id pinned so the row
  shows up in the agent's own audit trail (not just under ``system``).
* **nginx server cert** (90 days, short-lived TLS): warn at
  ``warn_days_nginx`` (30 days default). Wave 2 fix 6 will add the
  runtime renewal path; this loop is the early-warning before that
  ships.

Leader-elected via :func:`mcp_proxy.lifespan.get_leader` so only one
worker runs the loop in a multi-worker deployment. Pattern matches
``intermediate_ca_watcher`` (PR #788) + the other lifespan watchers
(federation_subscriber, anomaly_evaluator, quarantine_expiry, PR #784).

Why warning-only and not auto-rotate? Two of the four tiers (Org Root,
Mastio leaf) need a human in the loop by design (Court ACK for the
leaf, ceremony for the root). The other two (agent leaves, nginx
server) have rotation paths owned elsewhere (Connector re-enrollment
for the agent, Wave 2 fix 6 for nginx). The watcher's only job is to
make sure those rotations DO get scheduled — silent expiry is the
incident this loop prevents.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

logger = logging.getLogger("mcp_proxy.lifespan.cert_expiry_watcher")

_DEFAULT_TICK_SECONDS = 24 * 60 * 60
_DEFAULT_WARN_DAYS_ORG_ROOT = 1825  # 5y (cert is 15y, so >10y silent)
_DEFAULT_WARN_DAYS_INTERMEDIATE = 730  # 2y fallback (primary watcher = 180d)
_DEFAULT_WARN_DAYS_MASTIO_LEAF = 90
_DEFAULT_WARN_DAYS_AGENT = 90
_DEFAULT_WARN_DAYS_NGINX = 30


def _aware(dt: datetime) -> datetime:
    """cryptography <42 returns naive UTC; >=42 returns aware. Normalise."""
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _days_left(not_after: datetime, now: datetime) -> int:
    delta = _aware(not_after) - now
    return int(delta.total_seconds() / 86400)


async def cert_expiry_watcher_loop(
    agent_manager,
    *,
    settings=None,
    tick_seconds: int = _DEFAULT_TICK_SECONDS,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Loop tail: every ``tick_seconds`` check every cert tier, warn-only.

    ``stop_event`` lets the lifespan signal a graceful shutdown so the
    loop returns promptly instead of sleeping out the current tick.
    """
    stop_event = stop_event or asyncio.Event()
    logger.info(
        "cert_expiry_watcher loop starting (tick=%ds)", tick_seconds,
    )

    while not stop_event.is_set():
        try:
            await _check_once(agent_manager, settings)
        except Exception as exc:  # noqa: BLE001 defensive long-running loop
            logger.error(
                "cert_expiry_watcher tick raised %s, continuing", exc,
            )

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=tick_seconds)
        except asyncio.TimeoutError:
            pass

    logger.info("cert_expiry_watcher loop stopped")


async def _check_once(agent_manager, settings) -> None:
    """One tick: dispatch to each tier check independently.

    Each tier is wrapped in its own try/except so a malformed agent
    cert or an unreadable nginx file does not stop the next tier from
    being inspected.
    """
    now = datetime.now(timezone.utc)
    warn_org_root = _resolve_threshold(
        settings, "cert_expiry_warn_days_org_root", _DEFAULT_WARN_DAYS_ORG_ROOT,
    )
    warn_intermediate = _resolve_threshold(
        settings, "cert_expiry_warn_days_intermediate",
        _DEFAULT_WARN_DAYS_INTERMEDIATE,
    )
    warn_mastio_leaf = _resolve_threshold(
        settings, "cert_expiry_warn_days_mastio_leaf",
        _DEFAULT_WARN_DAYS_MASTIO_LEAF,
    )
    warn_agent = _resolve_threshold(
        settings, "cert_expiry_warn_days_agent", _DEFAULT_WARN_DAYS_AGENT,
    )
    warn_nginx = _resolve_threshold(
        settings, "cert_expiry_warn_days_nginx", _DEFAULT_WARN_DAYS_NGINX,
    )

    try:
        await _check_org_root(agent_manager, now, warn_org_root)
    except Exception as exc:  # noqa: BLE001 best-effort, don't break other tiers
        logger.warning("cert_expiry_watcher org_root check raised: %s", exc)

    try:
        await _check_intermediate(agent_manager, now, warn_intermediate)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "cert_expiry_watcher intermediate fallback check raised: %s", exc,
        )

    try:
        await _check_mastio_leaf(agent_manager, now, warn_mastio_leaf)
    except Exception as exc:  # noqa: BLE001
        logger.warning("cert_expiry_watcher mastio_leaf check raised: %s", exc)

    try:
        await _check_agent_leaves(now, warn_agent)
    except Exception as exc:  # noqa: BLE001
        logger.warning("cert_expiry_watcher agent_leaves check raised: %s", exc)

    try:
        await _check_nginx_server(settings, now, warn_nginx)
    except Exception as exc:  # noqa: BLE001
        logger.warning("cert_expiry_watcher nginx_server check raised: %s", exc)


def _resolve_threshold(settings, attr: str, default: int) -> int:
    """Read ``attr`` off settings, fall back to ``default`` if missing/None."""
    if settings is None:
        return default
    value = getattr(settings, attr, None)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


async def _check_org_root(agent_manager, now: datetime, threshold_days: int) -> None:
    from mcp_proxy.db import log_audit

    cert = getattr(agent_manager, "_org_ca_cert", None)
    if cert is None:
        return

    days_left = _days_left(cert.not_valid_after, now)
    if days_left > threshold_days:
        return

    logger.warning(
        "Org Root CA expires in %d days (< %d). Manual rotation required, "
        "the cold root has no auto-path. Plan a re-issuance ceremony soon.",
        days_left, threshold_days,
    )
    try:
        await log_audit(
            agent_id="system",
            action="pki.org_root_expiry_warning",
            status="success",
            detail=f"days_left={days_left} threshold={threshold_days}",
        )
    except Exception:
        pass


async def _check_intermediate(
    agent_manager, now: datetime, threshold_days: int,
) -> None:
    """Fallback INFO log for the Intermediate.

    The primary watcher (``intermediate_ca_watcher``) handles WARN +
    auto-rotate at 180d / 60d / 30d. This loop is here ONLY for the
    case where the primary watcher is disabled (single-process dev
    mode, leader contention failures, future opt-out flag). At
    ``threshold_days`` (2y default) we log a single INFO row so the
    operator sees the Intermediate exists and is being tracked.
    """
    from mcp_proxy.db import log_audit

    cert = getattr(agent_manager, "_mastio_ca_cert", None)
    if cert is None:
        return

    days_left = _days_left(cert.not_valid_after, now)
    if days_left > threshold_days:
        return

    logger.info(
        "Mastio Intermediate CA expires in %d days (< %d, fallback "
        "threshold). Primary watcher (intermediate_ca_watcher) handles "
        "rotation; this log is a visibility fallback.",
        days_left, threshold_days,
    )
    try:
        await log_audit(
            agent_id="system",
            action="pki.intermediate_ca_expiry_visibility",
            status="success",
            detail=f"days_left={days_left} threshold={threshold_days}",
        )
    except Exception:
        pass


async def _check_mastio_leaf(
    agent_manager, now: datetime, threshold_days: int,
) -> None:
    from mcp_proxy.db import log_audit

    active = getattr(agent_manager, "_active_key", None)
    if active is None or getattr(active, "cert_pem", None) is None:
        return

    try:
        cert = x509.load_pem_x509_certificate(active.cert_pem.encode())
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "cert_expiry_watcher: mastio leaf cert parse failed (kid=%s): %s",
            getattr(active, "kid", "?"), exc,
        )
        return

    days_left = _days_left(cert.not_valid_after, now)
    if days_left > threshold_days:
        return

    logger.warning(
        "Mastio leaf cert (kid=%s) expires in %d days (< %d). Trigger "
        "manual rotation via dashboard or POST /v1/admin/mastio/rotate-key "
        "before the window closes; the Court ACK round-trip needs lead time.",
        getattr(active, "kid", "?"), days_left, threshold_days,
    )
    try:
        await log_audit(
            agent_id="system",
            action="pki.mastio_leaf_expiry_warning",
            status="success",
            detail=(
                f"kid={getattr(active, 'kid', '?')!r} "
                f"days_left={days_left} threshold={threshold_days}"
            ),
        )
    except Exception:
        pass


async def _check_agent_leaves(now: datetime, threshold_days: int) -> None:
    """Iterate every internal agent and warn for any cert in-threshold.

    Audit rows pin the agent_id so an operator querying audit-by-agent
    still sees the expiry warning. The system row pattern would hide
    it behind a global feed.
    """
    from mcp_proxy.db import list_agents, log_audit

    try:
        rows = await list_agents()
    except Exception as exc:  # noqa: BLE001 best-effort
        logger.warning(
            "cert_expiry_watcher: list_agents() failed: %s", exc,
        )
        return

    for row in rows:
        agent_id = row.get("agent_id") or ""
        cert_pem = row.get("cert_pem")
        if not cert_pem:
            continue
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "cert_expiry_watcher: agent %s cert parse failed: %s",
                agent_id, exc,
            )
            continue

        days_left = _days_left(cert.not_valid_after, now)
        if days_left > threshold_days:
            continue

        logger.warning(
            "Agent cert for %s expires in %d days (< %d). Re-enroll via "
            "Connector or POST /registry/agents/%s/rotate-cert.",
            agent_id, days_left, threshold_days, agent_id,
        )
        try:
            await log_audit(
                agent_id=agent_id,
                action="pki.agent_cert_expiry_warning",
                status="success",
                detail=f"days_left={days_left} threshold={threshold_days}",
            )
        except Exception:
            pass


async def _check_nginx_server(settings, now: datetime, threshold_days: int) -> None:
    """Inspect the on-disk nginx server cert.

    nginx_cert_dir is empty by default (pytest in-memory + dev paths),
    in which case there is nothing to inspect and the check is a no-op.
    """
    from mcp_proxy.db import log_audit

    cert_dir = getattr(settings, "nginx_cert_dir", "") if settings else ""
    if not cert_dir:
        return

    crt_path = Path(cert_dir) / "mastio-server.crt"
    if not crt_path.exists():
        return

    try:
        cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "cert_expiry_watcher: nginx server cert parse failed (%s): %s",
            crt_path, exc,
        )
        return

    days_left = _days_left(cert.not_valid_after, now)
    if days_left > threshold_days:
        return

    logger.warning(
        "nginx server cert (%s) expires in %d days (< %d). Wave 2 fix 6 "
        "will add a runtime renewal path; for now a Mastio restart picks "
        "up a fresh leaf via ensure_nginx_server_cert (boot-time check).",
        crt_path, days_left, threshold_days,
    )
    try:
        await log_audit(
            agent_id="system",
            action="pki.nginx_server_cert_expiry_warning",
            status="success",
            detail=(
                f"path={str(crt_path)!r} days_left={days_left} "
                f"threshold={threshold_days}"
            ),
        )
    except Exception:
        pass


__all__ = ["cert_expiry_watcher_loop"]
