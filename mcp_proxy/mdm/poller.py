"""Long-running Intune polling task.

Lifecycle owned by ``mcp_proxy.main.lifespan``. Wakes every
``MCP_PROXY_MDM_INTUNE_POLL_INTERVAL_SECONDS`` (default 600), fetches
the managed-device delta, runs the compliance reconciler (F6) +
upserts the projected rows into ``mdm_device_state``.

Failure handling layers:

* Per-iteration: :class:`IntuneGraphError` and any other exception
  trip the F2 exponential backoff (30→60→120→300→300s).
* Across iterations: a three-state circuit breaker (F6,
  :mod:`mcp_proxy.mdm.circuit_breaker`) flips to OPEN after a
  configurable streak of failures and stops the loop from
  spamming Graph during a sustained outage. The CLOSED→OPEN
  transition emits a one-shot ``mdm_polling_degraded`` audit row.

The cache stays warm with the prior poll's data; consumers (F2
enrollment hook, F5 policy gate) treat ``last_seen_at`` as the
freshness signal and downgrade ``effective_tier`` when stale.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from mcp_proxy._lifespan_log import emit_lifespan_log
from mcp_proxy.attestation.audit_events import emit_polling_degraded
from mcp_proxy.db import get_db
from mcp_proxy.mdm.circuit_breaker import (
    CircuitBreaker,
    sleep_until_cooldown_done,
)
from mcp_proxy.mdm.compliance_change import (
    ReconcileSummary,
    reconcile_devices_and_revoke,
)
from mcp_proxy.mdm.intune import (
    IntuneClient,
    IntuneGraphError,
    project_device_row,
)
from mcp_proxy.telemetry_metrics import (
    MDM_DEVICES_SEEN,
    MDM_POLL_DURATION,
    MDM_POLL_TOTAL,
)

_log = logging.getLogger("mcp_proxy.mdm.poller")

# Backoff schedule on consecutive errors. Reset to 0 on the first
# successful poll. Capped at 300s so a long outage settles at 5 min
# rather than crawling toward the polling interval. The circuit
# breaker (F6) wraps this for the >5-failure path.
_BACKOFF_SECONDS = (30, 60, 120, 300, 300)


async def upsert_device_rows(
    devices: list[dict[str, Any]],
    *,
    mdm: str = "intune",
    now: datetime | None = None,
) -> int:
    """Upsert a batch of devices into ``mdm_device_state``.

    Returns the number of rows touched. Skips rows without an
    ``id`` field (Graph never omits it, but we defend against
    malformed test fixtures rather than crashing the poll loop).
    """
    if not devices:
        return 0

    now = now or datetime.now(timezone.utc)
    touched = 0

    async with get_db() as conn:
        dialect = conn.engine.dialect.name if hasattr(conn, "engine") else conn.bind.dialect.name
        # SQLite + Postgres both implement ``INSERT ... ON CONFLICT``
        # since SQLite 3.24 (2018-06) and Postgres 9.5 (2016). The
        # Mastio runtime targets both, and asyncpg / aiosqlite both
        # forward the dialect-native UPSERT.
        if dialect == "sqlite":
            upsert_sql = """
                INSERT INTO mdm_device_state (
                    mdm, device_id, compliance,
                    azure_ad_device_id, user_principal_name,
                    device_name, manufacturer, serial_number,
                    raw_payload, last_seen_at, created_at
                ) VALUES (
                    :mdm, :device_id, :compliance,
                    :azure_ad, :upn,
                    :name, :manufacturer, :serial,
                    :raw, :seen, :created
                )
                ON CONFLICT(mdm, device_id) DO UPDATE SET
                    compliance = excluded.compliance,
                    azure_ad_device_id = excluded.azure_ad_device_id,
                    user_principal_name = excluded.user_principal_name,
                    device_name = excluded.device_name,
                    manufacturer = excluded.manufacturer,
                    serial_number = excluded.serial_number,
                    raw_payload = excluded.raw_payload,
                    last_seen_at = excluded.last_seen_at
            """
        else:
            upsert_sql = """
                INSERT INTO mdm_device_state (
                    mdm, device_id, compliance,
                    azure_ad_device_id, user_principal_name,
                    device_name, manufacturer, serial_number,
                    raw_payload, last_seen_at, created_at
                ) VALUES (
                    :mdm, :device_id, :compliance,
                    :azure_ad, :upn,
                    :name, :manufacturer, :serial,
                    :raw, :seen, :created
                )
                ON CONFLICT (mdm, device_id) DO UPDATE SET
                    compliance = EXCLUDED.compliance,
                    azure_ad_device_id = EXCLUDED.azure_ad_device_id,
                    user_principal_name = EXCLUDED.user_principal_name,
                    device_name = EXCLUDED.device_name,
                    manufacturer = EXCLUDED.manufacturer,
                    serial_number = EXCLUDED.serial_number,
                    raw_payload = EXCLUDED.raw_payload,
                    last_seen_at = EXCLUDED.last_seen_at
            """

        for graph_device in devices:
            projected = project_device_row(graph_device)
            if not projected["device_id"]:
                continue
            await conn.execute(
                text(upsert_sql),
                {
                    "mdm": mdm,
                    "device_id": projected["device_id"],
                    "compliance": projected["compliance"],
                    "azure_ad": projected["azure_ad_device_id"],
                    "upn": projected["user_principal_name"],
                    "name": projected["device_name"],
                    "manufacturer": projected["manufacturer"],
                    "serial": projected["serial_number"],
                    "raw": json.dumps(graph_device, default=str),
                    "seen": now,
                    "created": now,
                },
            )
            touched += 1

    return touched


async def _reconcile_compliance_changes(
    devices: list[dict[str, Any]],
    *,
    mdm: str,
    now: datetime,
) -> ReconcileSummary:
    """Run F6 reconcile against the PRE-upsert cache state.

    Opens its own connection so the upsert call (a separate
    ``get_db`` context) sees a consistent prior view. Tolerant of any
    error: a buggy reconciler must not break the cache-keeping job.
    """
    try:
        async with get_db() as conn:
            return await reconcile_devices_and_revoke(
                conn,
                fresh_devices=devices,
                mdm=mdm,
                now=now,
            )
    except Exception as exc:  # noqa: BLE001 — defensive
        _log.exception(
            "MDM compliance reconcile failed (cache + revocations skipped "
            "this tick): %r", exc,
        )
        return ReconcileSummary()


async def _persist_delta_link(value: str | None) -> None:
    """Persist the Graph deltaLink between poll cycles.

    Stored in ``proxy_config`` under a fixed key. Tolerant to
    schema variations: callers should ``try/except`` around this so
    a transient DB issue does not stop the polling loop.
    """
    if value is None:
        return
    async with get_db() as conn:
        dialect = conn.engine.dialect.name if hasattr(conn, "engine") else conn.bind.dialect.name
        if dialect == "sqlite":
            sql = """
                INSERT INTO proxy_config (key, value) VALUES (:k, :v)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """
        else:
            sql = """
                INSERT INTO proxy_config (key, value) VALUES (:k, :v)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """
        await conn.execute(
            text(sql), {"k": "mdm.intune.delta_link", "v": value},
        )


async def _load_delta_link() -> str | None:
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT value FROM proxy_config WHERE key = :k"),
            {"k": "mdm.intune.delta_link"},
        )).first()
    if row is None:
        return None
    return str(row[0]) if row[0] else None


async def intune_poll_once(
    client: IntuneClient,
    *,
    now: datetime | None = None,
) -> tuple[int, str | None]:
    """One end-to-end poll cycle. Returns ``(rows_upserted, next_delta)``.

    Ordering:

    1. Fetch the Graph delta page(s).
    2. Reconcile against the PRE-upsert cache so the reconciler can
       observe the prior compliance value.
    3. Upsert the cache (a single ``get_db`` round so the dialect
       branch lives in one place).
    4. Persist the deltaLink for the next round.

    Extracted from the loop so tests can drive a single iteration
    against a mocked client without orchestrating timers.
    """
    now = now or datetime.now(timezone.utc)
    delta_link = await _load_delta_link()
    devices, next_delta = await client.fetch_managed_devices_delta(delta_link)
    await _reconcile_compliance_changes(devices, mdm="intune", now=now)
    touched = await upsert_device_rows(devices, mdm="intune", now=now)
    if touched:
        MDM_DEVICES_SEEN.labels(mdm="intune").inc(touched)
    if next_delta:
        try:
            await _persist_delta_link(next_delta)
        except Exception as exc:  # noqa: BLE001 — best-effort persistence
            _log.warning(
                "Failed to persist Intune deltaLink (will full-sync next round): %s",
                exc,
            )
    return touched, next_delta


async def intune_poll_loop(
    *,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    interval_seconds: int,
    stop_event: asyncio.Event,
) -> None:
    """Long-running polling task. Exits when ``stop_event`` is set.

    Owns the :class:`IntuneClient` (and its httpx client) so a
    shutdown closes both deterministically. Errors are isolated to
    a single iteration; the loop keeps running across transient
    failures.
    """
    client = IntuneClient(
        tenant_id=tenant_id, client_id=client_id, client_secret=client_secret,
    )
    backoff_idx = 0
    breaker = CircuitBreaker(mdm="intune")
    last_exc_status: int | None = None
    last_exc_message: str | None = None

    emit_lifespan_log(
        level="INFO",
        logger="mcp_proxy.mdm.poller",
        message=(
            "Intune polling loop started "
            f"(interval={interval_seconds}s, tenant=…{tenant_id[-12:]})"
        ),
    )

    try:
        while not stop_event.is_set():
            if not breaker.should_poll():
                # OPEN with cooldown remaining — sleep until either
                # cooldown elapses or shutdown is requested. The next
                # iteration's should_poll() flips to HALF_OPEN.
                await sleep_until_cooldown_done(breaker, stop_event)
                continue

            started = datetime.now(timezone.utc)
            poll_started_monotonic = asyncio.get_event_loop().time()
            try:
                touched, _ = await intune_poll_once(client, now=started)
                lag = (datetime.now(timezone.utc) - started).total_seconds()
                _log.info(
                    "Intune delta fetch: %d devices upserted (lag_s=%.1f, "
                    "circuit=%s)",
                    touched, lag, breaker.state,
                )
                MDM_POLL_DURATION.labels(mdm="intune").observe(lag)
                MDM_POLL_TOTAL.labels(mdm="intune", result="success").inc()
                breaker.record_success()
                last_exc_status = None
                last_exc_message = None
                backoff_idx = 0
                wait_s = interval_seconds
            except IntuneGraphError as exc:
                # NEVER log the upstream body verbatim — the message
                # is already sanitised by IntuneGraphError.__init__.
                wait_s = _BACKOFF_SECONDS[min(backoff_idx, len(_BACKOFF_SECONDS) - 1)]
                backoff_idx += 1
                MDM_POLL_TOTAL.labels(mdm="intune", result="failure").inc()
                MDM_POLL_DURATION.labels(mdm="intune").observe(
                    asyncio.get_event_loop().time() - poll_started_monotonic,
                )
                last_exc_status = exc.status
                last_exc_message = exc.message
                opened_edge = breaker.record_failure()
                _log.warning(
                    "Intune polling error (status=%d, consecutive=%d) — "
                    "backing off %ds: %s",
                    exc.status, breaker.consecutive_failures, wait_s,
                    exc.message,
                )
                if opened_edge:
                    await _emit_degraded_audit(
                        breaker.consecutive_failures,
                        last_exc_status, last_exc_message,
                    )
            except Exception as exc:  # noqa: BLE001 — defensive last-resort
                wait_s = _BACKOFF_SECONDS[min(backoff_idx, len(_BACKOFF_SECONDS) - 1)]
                backoff_idx += 1
                MDM_POLL_TOTAL.labels(mdm="intune", result="failure").inc()
                MDM_POLL_DURATION.labels(mdm="intune").observe(
                    asyncio.get_event_loop().time() - poll_started_monotonic,
                )
                last_exc_status = 0
                last_exc_message = f"{type(exc).__name__}: {exc}"
                opened_edge = breaker.record_failure()
                _log.exception(
                    "Intune polling unexpected error (consecutive=%d) — "
                    "backing off %ds: %r",
                    breaker.consecutive_failures, wait_s, exc,
                )
                if opened_edge:
                    await _emit_degraded_audit(
                        breaker.consecutive_failures,
                        last_exc_status, last_exc_message,
                    )

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=wait_s)
                # stop_event fired → loop exits next iteration.
            except asyncio.TimeoutError:
                pass
    finally:
        await client.aclose()
        emit_lifespan_log(
            level="INFO",
            logger="mcp_proxy.mdm.poller",
            message="Intune polling loop stopped",
        )


async def _emit_degraded_audit(
    consecutive_failures: int,
    last_status: int | None,
    last_message: str | None,
) -> None:
    """One-shot helper. Tolerant of audit-emit failure so the loop
    keeps running even when the audit chain itself is wedged.
    """
    try:
        await emit_polling_degraded(
            mdm="intune",
            consecutive_failures=consecutive_failures,
            last_error_status=last_status,
            last_error_message=last_message,
        )
    except Exception as exc:  # noqa: BLE001 — never let audit break polling
        _log.warning(
            "Failed to emit mdm_polling_degraded audit row: %s", exc,
        )
