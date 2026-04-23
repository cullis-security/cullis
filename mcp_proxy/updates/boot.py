"""Boot-time detection of pending federation update migrations.

Runs once from ``main.py`` lifespan after ``ensure_mastio_identity``
but before ``LocalIssuer`` construction. Walks every concrete
:class:`~mcp_proxy.updates.base.Migration` via
:func:`mcp_proxy.updates.registry.discover`, asks each whether it is
pending against current state, and:

- Populates the ``pending_updates`` table (idempotent).
- Refreshes the Prometheus gauge grouped by status.
- If any critical pending migration affects an enrollment type
  currently present on this proxy, engages sign-halt via
  :meth:`AgentManager.mark_sign_halted` — which flips the same flag
  the staged-rotation recovery path (#281) uses, so the rest of the
  boot pipeline (``LocalIssuer`` skip, countersign refusal) reacts
  without further plumbing.

Intentional design notes:

- ``check()`` exceptions are caught and logged as WARNING, per the
  contract declared on :class:`Migration`. No row is inserted for a
  migration that raised; it is re-evaluated on the next boot. This
  keeps a buggy migration from bricking startup.
- Migrations whose ``pending_updates`` row is already ``applied`` or
  ``rolled_back`` are skipped: the admin owns those rows and the
  detector must not regress them to ``pending``.
- No async concurrency inside the loop. The detector runs once at
  boot, on a handful of migrations; sequential evaluation keeps the
  failure surface trivial and ordering deterministic.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import text

from mcp_proxy.db import (
    get_db,
    get_pending_updates,
    insert_pending_update,
)
from mcp_proxy.updates.gauge import PENDING_UPDATES_TOTAL
from mcp_proxy.updates.registry import discover

if TYPE_CHECKING:  # pragma: no cover — import cycle at runtime
    from mcp_proxy.egress.agent_manager import AgentManager

logger = logging.getLogger("mcp_proxy.updates.boot")


_ALL_STATUSES: tuple[str, ...] = (
    "pending", "applied", "failed", "rolled_back",
)


async def _current_enrollment_types() -> set[str]:
    """Distinct ``enrollment_method`` across active agents on this proxy.

    Reads ``internal_agents`` directly because the boot detector runs
    before any higher-level cache is populated, and the set is small
    (at most 3 values: connector, byoca, spire). An un-provisioned
    proxy returns ``{"connector"}`` because that is the only method
    that can self-bootstrap without prior admin action — halting on a
    critical Connector-affecting migration before the first operator
    login is the safe default.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT DISTINCT enrollment_method FROM internal_agents "
                "WHERE is_active = 1 AND enrollment_method IS NOT NULL"
            )
        )
        found = {row[0] for row in result.fetchall() if row[0]}
    return found or {"connector"}


async def _refresh_gauge() -> None:
    """Re-read ``pending_updates`` by status and publish to Prometheus."""
    for status in _ALL_STATUSES:
        rows = await get_pending_updates(status=status)
        PENDING_UPDATES_TOTAL.labels(status=status).set(float(len(rows)))


async def detect_pending_migrations(
    agent_manager: "AgentManager",
) -> dict[str, list[str]]:
    """Scan migrations, populate ``pending_updates``, engage halt if needed.

    Returns a summary dict with two keys:

    - ``detected_ids`` — migrations whose ``check()`` returned True and
      whose row was inserted (or already present as ``pending`` /
      ``failed``). Excludes rows with ``applied`` / ``rolled_back``.
    - ``halt_reasons`` — subset of ``detected_ids`` that triggered
      sign-halt on the agent manager.
    """
    migrations = discover()
    enrollment_types = await _current_enrollment_types()
    now_iso = datetime.now(timezone.utc).isoformat()

    existing = {
        row["migration_id"]: row["status"]
        for row in await get_pending_updates()
    }

    detected_ids: list[str] = []
    halt_reasons: list[str] = []

    for m in migrations:
        prior_status = existing.get(m.migration_id)
        if prior_status in ("applied", "rolled_back"):
            # Admin already resolved this one; respect that state.
            continue

        try:
            is_pending = await m.check()
        except Exception as exc:
            logger.warning(
                "updates.boot: check() raised for migration_id=%s (%s): %s "
                "— skipping (will retry on next boot)",
                m.migration_id, type(exc).__name__, exc,
            )
            continue

        if not is_pending:
            continue

        detected_ids.append(m.migration_id)
        # Idempotent insert. First-time rows get status='pending';
        # ON CONFLICT / INSERT OR IGNORE means the original
        # ``detected_at`` and any ``status`` the admin set by hand
        # (``failed`` after a manual apply attempt) survive re-boot.
        await insert_pending_update(
            migration_id=m.migration_id,
            detected_at=now_iso,
        )

        affected = set(m.affects_enrollments) & enrollment_types
        if m.criticality == "critical" and affected:
            halt_reasons.append(m.migration_id)

    if halt_reasons:
        reason = (
            f"pending critical federation updates affect this proxy's "
            f"enrollments ({sorted(enrollment_types)}): "
            f"{', '.join(halt_reasons)}. Resolve via the dashboard "
            f"(/proxy/updates — PR 5) or POST /admin/updates/{{id}}/apply "
            f"once the endpoint is live (PR 4)."
        )
        agent_manager.mark_sign_halted(reason)

    await _refresh_gauge()

    logger.info(
        "updates.boot: %d migrations registered, %d pending after scan, "
        "%d critical → halt=%s",
        len(migrations), len(detected_ids), len(halt_reasons),
        bool(halt_reasons),
    )
    return {"detected_ids": detected_ids, "halt_reasons": halt_reasons}
