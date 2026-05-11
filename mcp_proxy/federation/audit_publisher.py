"""Wave B PR8 / D1 — Mastio audit replication publisher.

Background task that pushes ``local_audit`` rows to the Court via
``POST /v1/federation/audit/replicate`` for cross-org dispute
resolution (audit ref imp/audits/2026-05-11-track-3-audit-pdp.md F-3).

Flow per tick:
  1. Read ``proxy_config[last_replicated_local_audit_id]`` cursor.
  2. SELECT new ``local_audit`` rows with ``id > cursor`` AND
     ``chain_seq IS NOT NULL`` (skip pre-chain-migration rows).
     Group by ``org_id`` so each batch covers exactly one chain.
  3. For each batch: build canonical JSON, sign raw bytes via
     ``AgentManager.countersign()`` (ADR-009 leaf key, same one
     publish-agent uses), POST to Court.
  4. On 2xx, advance cursor to max(id) in batch.
  5. On 4xx: log + skip (re-pushing won't fix a structural error).
     On 5xx / network: log + retry on next tick (cursor unchanged).

The cursor is persisted on the Mastio's own DB (``proxy_config``)
because the Court replica's UNIQUE(mastio_org_id, chain_seq) makes
re-submission idempotent — even if the cursor lags, the next tick
re-sends the same chain_seq and the Court counts them as
``already_present``. Conservative side: at-least-once delivery.

Standalone proxies (no broker_url) skip the loop. Federated proxies
that haven't seeded their Mastio identity skip until the leaf key is
loaded.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

import httpx
from sqlalchemy import text


_log = logging.getLogger("mcp_proxy.federation.audit_publisher")


def _env_float(name: str, default: float) -> float:
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


# Audit replication is medium-frequency: latency on Court-side
# dispute reconciliation is acceptable in the seconds-to-minutes
# range, but we don't want a queue to grow unbounded between ticks.
AUDIT_POLL_INTERVAL_S = _env_float(
    "MCP_PROXY_AUDIT_REPLICATION_POLL_INTERVAL_S", 30.0,
)
HTTP_TIMEOUT_S = 15.0
# Cap the number of rows per batch to bound the request body and the
# Court's atomic transaction. The Mastio chain produces a few rows
# per request handled, so 200 covers ~5-10 minutes of bursty traffic.
MAX_BATCH_SIZE = 200

_CURSOR_KEY = "last_replicated_local_audit_id"


async def _read_cursor(conn) -> int:
    """Return the last ``local_audit.id`` we successfully replicated.
    Zero on first run (no row in proxy_config yet)."""
    row = (
        await conn.execute(
            text("SELECT value FROM proxy_config WHERE key = :k"),
            {"k": _CURSOR_KEY},
        )
    ).first()
    if row is None:
        return 0
    try:
        return int(row[0])
    except (TypeError, ValueError):
        _log.warning(
            "audit cursor in proxy_config is not an int (%r) — resetting to 0",
            row[0],
        )
        return 0


async def _write_cursor(conn, value: int) -> None:
    """Upsert the cursor. Same pattern as other proxy_config writes."""
    # SQLite + Postgres both accept ON CONFLICT … DO UPDATE; the proxy
    # config helper uses the same shape elsewhere.
    await conn.execute(
        text(
            """
            INSERT INTO proxy_config (key, value)
            VALUES (:k, :v)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            """
        ),
        {"k": _CURSOR_KEY, "v": str(value)},
    )


async def _fetch_pending(conn, *, after_id: int) -> list[dict]:
    """All replicable rows newer than ``after_id``, ordered by id ASC.

    Filter ``chain_seq IS NOT NULL`` so pre-chain rows (which can't be
    Court-verified for continuity) stay local-only. Cap at
    ``MAX_BATCH_SIZE``."""
    result = await conn.execute(
        text(
            """
            SELECT id, timestamp, event_type, agent_id, session_id, org_id,
                   details, result, previous_hash, chain_seq, entry_hash,
                   hash_format
              FROM local_audit
             WHERE id > :after_id
               AND chain_seq IS NOT NULL
             ORDER BY id ASC
             LIMIT :lim
            """
        ),
        {"after_id": after_id, "lim": MAX_BATCH_SIZE},
    )
    return [dict(row) for row in result.mappings().all()]


def _group_by_org(rows: list[dict]) -> dict[str, list[dict]]:
    """One Court request per org_id. Court endpoint expects all entries
    in a batch to share ``mastio_org_id``."""
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r["org_id"], []).append(r)
    # Sort each org group by chain_seq so the Court-side continuity
    # check sees a monotonic sequence.
    for batch in out.values():
        batch.sort(key=lambda r: r["chain_seq"])
    return out


def _build_body(*, mastio_org_id: str, batch: list[dict]) -> bytes:
    """Canonical JSON body — what the Court receives + countersig
    covers. Field names mirror the Pydantic model on the receiver."""
    payload = {
        "mastio_org_id": mastio_org_id,
        "entries": [
            {
                "chain_seq": int(r["chain_seq"]),
                "entry_hash": r["entry_hash"],
                "previous_hash": r["previous_hash"],
                "timestamp": r["timestamp"],
                "event_type": r["event_type"],
                "agent_id": r["agent_id"],
                "session_id": r["session_id"],
                "details": r["details"],
                "result": r["result"],
                # local_audit doesn't carry principal_type today; once
                # the column lands the publisher will pass it through.
                "principal_type": None,
                "hash_format": r.get("hash_format"),
            }
            for r in batch
        ],
    }
    return json.dumps(payload).encode("utf-8")


async def _publish_batch(
    *, mastio_org_id: str, batch: list[dict], broker_url: str,
    countersign, client: httpx.AsyncClient,
) -> bool:
    body = _build_body(mastio_org_id=mastio_org_id, batch=batch)
    signature = countersign(body)
    url = f"{broker_url.rstrip('/')}/v1/federation/audit/replicate"
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
            "audit replicate: Court unreachable for org=%s "
            "chain_seq[%d..%d] (%s) — will retry",
            mastio_org_id, batch[0]["chain_seq"], batch[-1]["chain_seq"],
            exc,
        )
        return False

    if resp.is_success:
        body_json = {}
        try:
            body_json = resp.json() or {}
        except Exception:
            pass
        _log.info(
            "audit replicate OK: org=%s chain_seq[%d..%d] "
            "stored=%s already_present=%s",
            mastio_org_id, batch[0]["chain_seq"], batch[-1]["chain_seq"],
            body_json.get("stored"), body_json.get("already_present"),
        )
        return True

    _log.warning(
        "audit replicate FAIL org=%s chain_seq[%d..%d] HTTP %d: %s",
        mastio_org_id, batch[0]["chain_seq"], batch[-1]["chain_seq"],
        resp.status_code, resp.text[:300],
    )
    # 4xx structural — advancing the cursor would skip rows forever.
    # Block here; require operator inspection to proceed.
    # 5xx transient — leave cursor in place and try again next tick.
    return False


async def _tick(app_state) -> int:
    """One iteration. Returns total rows successfully Court-acked."""
    broker_url = getattr(app_state, "reverse_proxy_broker_url", None)
    mgr = getattr(app_state, "agent_manager", None)
    http = getattr(app_state, "reverse_proxy_client", None)

    if not broker_url or mgr is None or http is None:
        return 0
    if not getattr(mgr, "mastio_loaded", False):
        return 0

    from mcp_proxy.db import get_db

    async with get_db() as conn:
        cursor = await _read_cursor(conn)
        pending = await _fetch_pending(conn, after_id=cursor)

    if not pending:
        return 0

    grouped = _group_by_org(pending)
    acked = 0
    max_id_acked = cursor

    for org, batch in grouped.items():
        ok = await _publish_batch(
            mastio_org_id=org, batch=batch, broker_url=broker_url,
            countersign=mgr.countersign, client=http,
        )
        if ok:
            acked += len(batch)
            for r in batch:
                if r["id"] > max_id_acked:
                    max_id_acked = r["id"]

    if max_id_acked > cursor:
        async with get_db() as conn:
            await _write_cursor(conn, max_id_acked)
            await conn.commit() if hasattr(conn, "commit") else None
    return acked


async def run_audit_publisher(
    app_state, *, stop_event: asyncio.Event,
) -> None:
    """Background task body. Exits when ``stop_event`` is set."""
    _log.info(
        "audit replication publisher started (poll=%.1fs, batch=%d)",
        AUDIT_POLL_INTERVAL_S, MAX_BATCH_SIZE,
    )
    try:
        while not stop_event.is_set():
            try:
                await _tick(app_state)
            except Exception as exc:  # never let the loop die
                _log.exception("audit replication tick failed: %s", exc)
            try:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=AUDIT_POLL_INTERVAL_S,
                )
            except asyncio.TimeoutError:
                continue
    finally:
        _log.info("audit replication publisher stopped")
