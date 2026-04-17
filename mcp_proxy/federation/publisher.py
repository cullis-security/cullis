"""ADR-010 Phase 3 — Mastio federation publisher.

Background task that pushes agents marked ``federated=True`` in
``internal_agents`` to the Court's ``POST /v1/federation/publish-agent``
endpoint (Phase 1). Uses the ADR-009 counter-signature so the Court can
identify which Mastio is pushing. Tracks progress via
``last_pushed_revision`` so every mutation (patch federated, cert
rotation, deactivation) gets exactly one push.

Flow per tick:
  1. Query all rows where ``federated=1`` OR ``federated_at IS NOT NULL``
     (the second lets us push revocations for rows that were federated
     and later flipped off) AND
     ``federation_revision > last_pushed_revision``.
  2. For each row, build the JSON payload, sign the raw bytes with the
     Mastio leaf key via ``AgentManager.countersign()``, POST to the
     Court.
  3. On 2xx, bump ``last_pushed_revision = federation_revision`` +
     ``federated_at = now()``.
  4. On 4xx/5xx, log + skip (next tick will retry; Phase 3 avoids infinite
     retries by design — pathological rows are visible in the audit log).

The Court is contacted via ``app.state.reverse_proxy_broker_url``
(already initialized in the lifespan when the proxy is federated).
Standalone proxies never reach here because ``federated_at`` stays NULL
and revisions never go above ``last_pushed_revision=0``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import httpx
from sqlalchemy import text


_log = logging.getLogger("mcp_proxy.federation.publisher")


def _env_float(name: str, default: float) -> float:
    """Parse a positive-float env var, fall back to ``default`` on junk."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        _log.warning("invalid %s=%r — using default %.1fs", name, raw, default)
        return default
    if value <= 0:
        _log.warning("non-positive %s=%r — using default %.1fs", name, raw, default)
        return default
    return value


# Production defaults match ADR-010 Phase 3. The demo_network smoke pins
# these tighter via ``MCP_PROXY_FEDERATION_POLL_INTERVAL_S`` so the first
# push lands seconds after ``bootstrap-mastio`` seeds ``/v1/admin/agents``,
# instead of blocking the CI smoke on a 30-second tick.
POLL_INTERVAL_S = _env_float("MCP_PROXY_FEDERATION_POLL_INTERVAL_S", 30.0)
HTTP_TIMEOUT_S = 10.0

# Aggregate-stats push is less time-critical than per-agent revisions
# (the Court dashboard tolerates a few minutes of staleness), so the
# stats loop runs an order of magnitude slower than the agent loop.
STATS_INTERVAL_S = _env_float("MCP_PROXY_FEDERATION_STATS_INTERVAL_S", 300.0)


async def _fetch_pending(conn) -> list[dict]:
    """Rows that need a push on this tick.

    ``federated`` is a BOOLEAN column (migration 0010). Postgres rejects
    ``federated = 1`` with ``operator does not exist: boolean = integer``,
    so the predicate is a bare column reference — valid on both SQLite
    (truthy integer) and Postgres (native bool) without casts.
    """
    result = await conn.execute(
        text(
            """
            SELECT agent_id, display_name, capabilities, cert_pem,
                   is_active, federated, federation_revision,
                   last_pushed_revision
              FROM internal_agents
             WHERE (federated OR federated_at IS NOT NULL)
               AND federation_revision > last_pushed_revision
            """
        ),
    )
    return [dict(row) for row in result.mappings().all()]


async def _mark_pushed(conn, agent_id: str, revision: int) -> None:
    await conn.execute(
        text(
            """
            UPDATE internal_agents
               SET last_pushed_revision = :rev,
                   federated_at = :now
             WHERE agent_id = :aid
            """
        ),
        {
            "rev": revision,
            # ``federated_at`` is DateTime(timezone=True) — asyncpg rejects
            # ISO strings with "expected a datetime.date or datetime.datetime
            # instance". SQLAlchemy + asyncpg accept a datetime directly on
            # both SQLite and Postgres.
            "now": datetime.now(timezone.utc),
            "aid": agent_id,
        },
    )


def _build_body(row: dict) -> bytes:
    """Canonical JSON body for signing + sending. Revoked iff
    inactive — an admin can deactivate without clearing the federated
    flag and we still want the Court to hear about it."""
    payload = {
        "agent_id": row["agent_id"],
        "cert_pem": row["cert_pem"] or "",
        "capabilities": json.loads(row["capabilities"] or "[]"),
        "display_name": row["display_name"] or "",
        "revoked": not bool(row["is_active"]),
    }
    return json.dumps(payload).encode()


async def _publish_one(
    *, row: dict, broker_url: str, countersign, client: httpx.AsyncClient,
) -> bool:
    body = _build_body(row)
    signature = countersign(body)
    url = f"{broker_url.rstrip('/')}/v1/federation/publish-agent"
    try:
        resp = await client.post(
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Cullis-Mastio-Signature": signature,
            },
            timeout=HTTP_TIMEOUT_S,
        )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        _log.warning(
            "federation publish: broker unreachable for %s (%s) — will retry",
            row["agent_id"], exc,
        )
        return False

    if resp.is_success:
        _log.info(
            "federation publish OK: %s rev=%d status=%s",
            row["agent_id"], row["federation_revision"],
            (resp.json() or {}).get("status"),
        )
        return True

    _log.warning(
        "federation publish %s → HTTP %d: %s",
        row["agent_id"], resp.status_code, resp.text[:200],
    )
    # 4xx means the Court rejected the payload (bad sig, unpinned pubkey,
    # unknown org, cert not chaining). Re-pushing won't fix it — mark as
    # pushed so we don't spin forever. 5xx transient, retry next tick.
    return 400 <= resp.status_code < 500


async def _tick(app_state) -> int:
    """One iteration: enumerate pending rows, push each, update state.
    Returns the number of rows successfully acknowledged by the Court."""
    broker_url = getattr(app_state, "reverse_proxy_broker_url", None)
    mgr = getattr(app_state, "agent_manager", None)
    http = getattr(app_state, "reverse_proxy_client", None)

    if not broker_url or mgr is None or http is None:
        return 0
    if not getattr(mgr, "mastio_loaded", False):
        return 0

    from mcp_proxy.db import get_db
    acked = 0
    async with get_db() as conn:
        rows = await _fetch_pending(conn)

    for row in rows:
        ok = await _publish_one(
            row=row, broker_url=broker_url,
            countersign=mgr.countersign, client=http,
        )
        if ok:
            async with get_db() as conn:
                await _mark_pushed(conn, row["agent_id"], row["federation_revision"])
            acked += 1
    return acked


async def run_publisher(app_state, *, stop_event: asyncio.Event) -> None:
    """Background task body. Exits when ``stop_event`` is set."""
    _log.info("federation publisher started (poll=%.1fs)", POLL_INTERVAL_S)
    try:
        while not stop_event.is_set():
            try:
                await _tick(app_state)
            except Exception as exc:  # defensive — never let the loop die
                _log.exception("federation publisher tick failed: %s", exc)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=POLL_INTERVAL_S)
            except asyncio.TimeoutError:
                continue
    finally:
        _log.info("federation publisher stopped")


# ── Aggregate stats publisher ───────────────────────────────────────────────
#
# Fire-and-forget snapshot: count active/total internal agents and enabled
# backends, POST to POST /v1/federation/publish-stats. No idempotency state
# — every tick overwrites the Court-side snapshot. Standalone proxies skip.


async def _collect_stats(conn, *, org_id: str) -> dict:
    """Read the three counters off the Mastio DB."""
    agent_rows = (await conn.execute(
        text(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active "
            "FROM internal_agents"
        ),
    )).mappings().first()
    backend_row = (await conn.execute(
        text(
            "SELECT COUNT(*) AS total "
            "FROM local_mcp_resources WHERE enabled = 1"
        ),
    )).mappings().first()
    return {
        "org_id": org_id,
        "agent_active_count": int((agent_rows or {}).get("active") or 0),
        "agent_total_count": int((agent_rows or {}).get("total") or 0),
        "backend_count": int((backend_row or {}).get("total") or 0),
    }


async def _publish_stats_once(app_state) -> bool:
    """One stats push. Returns True on 2xx, False otherwise."""
    broker_url = getattr(app_state, "reverse_proxy_broker_url", None)
    mgr = getattr(app_state, "agent_manager", None)
    http = getattr(app_state, "reverse_proxy_client", None)
    org_id = getattr(app_state, "org_id", None) or ""

    if not broker_url or mgr is None or http is None or not org_id:
        return False
    if not getattr(mgr, "mastio_loaded", False):
        return False

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        payload = await _collect_stats(conn, org_id=org_id)

    body = json.dumps(payload).encode()
    signature = mgr.countersign(body)
    url = f"{broker_url.rstrip('/')}/v1/federation/publish-stats"
    try:
        resp = await http.post(
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Cullis-Mastio-Signature": signature,
            },
            timeout=HTTP_TIMEOUT_S,
        )
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        _log.warning("federation stats: Court unreachable (%s) — will retry", exc)
        return False

    if resp.is_success:
        _log.info(
            "federation stats OK org=%s active=%d total=%d backends=%d",
            payload["org_id"], payload["agent_active_count"],
            payload["agent_total_count"], payload["backend_count"],
        )
        return True
    _log.warning(
        "federation stats → HTTP %d: %s",
        resp.status_code, resp.text[:200],
    )
    return False


async def run_stats_publisher(app_state, *, stop_event: asyncio.Event) -> None:
    """Stats loop — independent of the agent publisher so a slow stats
    push doesn't delay agent revisions. Exits when ``stop_event`` is set."""
    _log.info("federation stats publisher started (poll=%.1fs)", STATS_INTERVAL_S)
    try:
        while not stop_event.is_set():
            try:
                await _publish_stats_once(app_state)
            except Exception as exc:
                _log.exception("federation stats tick failed: %s", exc)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=STATS_INTERVAL_S)
            except asyncio.TimeoutError:
                continue
    finally:
        _log.info("federation stats publisher stopped")
