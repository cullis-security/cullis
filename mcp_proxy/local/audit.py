"""Append-only local audit chain writer (ADR-006 Fase 1 / PR #2).

Twin of ``app/db/audit.py`` targeting the proxy's ``local_audit`` table.
The canonical hash form is byte-for-byte identical to the broker's
(``mcp_proxy.local.audit_chain.compute_entry_hash``), so a row written
here can be exported and verified on the broker side without schema
translation.

Design notes:
  - Per-org asyncio.Lock guarantees atomicity for "read last head +
    insert new" without blocking writes to other orgs. Top-level guard
    protects the lock dict.
  - SQL stays in raw ``text()`` form to match the rest of
    ``mcp_proxy.local.*`` (the proxy uses SQLAlchemy Core via
    AsyncConnection, not ORM sessions).
  - ``details`` is a free-form JSON string. Caller serializes (so
    sensitive dicts can be redacted before this boundary).
  - ``SYSTEM_ORG`` is the fallback when an event has no natural tenant
    — bootstrap, first-boot CA generation, etc. Same sentinel the
    broker uses, so exports merge cleanly.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mcp_proxy.db import get_db
from mcp_proxy.local.audit_chain import SYSTEM_ORG, compute_entry_hash

_log = logging.getLogger("mcp_proxy.local.audit")

_org_locks: dict[str, asyncio.Lock] = {}
_locks_guard = asyncio.Lock()

# Retry bound for UNIQUE(org_id, chain_seq) collisions between workers.
# See audit F-D-8 — the per-org asyncio.Lock is process-local so
# multi-worker deployments depend on the DB-level UNIQUE to serialise.
_MAX_CHAIN_RETRIES = 5


async def _get_org_lock(org_id: str) -> asyncio.Lock:
    if org_id in _org_locks:
        return _org_locks[org_id]
    async with _locks_guard:
        if org_id not in _org_locks:
            _org_locks[org_id] = asyncio.Lock()
        return _org_locks[org_id]


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


async def append_local_audit(
    *,
    event_type: str,
    result: str = "ok",
    agent_id: str | None = None,
    session_id: str | None = None,
    org_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one row to ``local_audit``, chained per org.

    Returns a summary dict (``{id, chain_seq, entry_hash, previous_hash}``)
    mostly for tests and for upstream structured logging; callers are
    expected to fire-and-forget in the happy path.

    Multi-worker safety (audit F-D-8): the per-org ``asyncio.Lock`` is
    process-local. Two workers racing on the same org can both compute
    the same ``new_seq``. The DB-level ``UNIQUE(org_id, chain_seq)``
    rejects the loser with ``IntegrityError``; we open a fresh
    transaction, re-read the head, and retry with the next seq.
    Bounded by ``_MAX_CHAIN_RETRIES``.
    """
    chain_org = org_id or SYSTEM_ORG
    details_json = json.dumps(details, separators=(",", ":"), sort_keys=True) if details else None
    lock = await _get_org_lock(chain_org)

    async with lock:
        last_exc: IntegrityError | None = None
        for attempt in range(_MAX_CHAIN_RETRIES):
            try:
                async with get_db() as conn:
                    # 1. Fetch current head for this org (entry_hash + chain_seq).
                    head = (await conn.execute(
                        text(
                            """
                            SELECT entry_hash, chain_seq FROM local_audit
                             WHERE org_id = :org_id AND chain_seq IS NOT NULL
                             ORDER BY chain_seq DESC
                             LIMIT 1
                            """
                        ),
                        {"org_id": chain_org},
                    )).first()
                    previous_hash = head[0] if head else None
                    last_seq = head[1] if head else 0
                    new_seq = last_seq + 1

                    # 2. Insert with placeholder entry_hash; database auto-assigns id.
                    now = datetime.now(timezone.utc)
                    ts_iso = _iso(now)
                    insert_result = await conn.execute(
                        text(
                            """
                            INSERT INTO local_audit (
                                timestamp, event_type, agent_id, session_id, org_id,
                                details, result, previous_hash, chain_seq,
                                peer_org_id, peer_row_hash, entry_hash
                            ) VALUES (
                                :timestamp, :event_type, :agent_id, :session_id, :org_id,
                                :details, :result, :previous_hash, :chain_seq,
                                NULL, NULL, :placeholder
                            )
                            """
                        ),
                        {
                            "timestamp": ts_iso,
                            "event_type": event_type,
                            "agent_id": agent_id,
                            "session_id": session_id,
                            "org_id": chain_org,
                            "details": details_json,
                            "result": result,
                            "previous_hash": previous_hash,
                            "chain_seq": new_seq,
                            "placeholder": "",
                        },
                    )
                    # SQLite drivers expose ``lastrowid`` on the CursorResult; asyncpg
                    # *does not* have that attribute at all (raises AttributeError,
                    # not returns None), so the ``is None`` check below never fires
                    # on Postgres. ``getattr(..., None)`` normalises both dialects to
                    # the same "unknown → query back" fallback path.
                    row_id = getattr(insert_result, "lastrowid", None)
                    if row_id is None:
                        id_row = (await conn.execute(
                            text(
                                "SELECT id FROM local_audit WHERE org_id = :org_id "
                                "AND chain_seq = :chain_seq"
                            ),
                            {"org_id": chain_org, "chain_seq": new_seq},
                        )).first()
                        row_id = id_row[0]

                    # 3. Compute the hash now that we know the row id.
                    entry_hash = compute_entry_hash(
                        entry_id=row_id,
                        timestamp=now,
                        event_type=event_type,
                        agent_id=agent_id,
                        session_id=session_id,
                        org_id=chain_org,
                        result=result,
                        details=details_json,
                        previous_hash=previous_hash,
                        chain_seq=new_seq,
                        peer_org_id=None,
                    )

                    # 4. Back-fill the hash. The row is immutable from here on.
                    await conn.execute(
                        text("UPDATE local_audit SET entry_hash = :h WHERE id = :id"),
                        {"h": entry_hash, "id": row_id},
                    )
                # ``get_db()`` committed on clean exit. Return the summary.
                return {
                    "id": row_id,
                    "chain_seq": new_seq,
                    "entry_hash": entry_hash,
                    "previous_hash": previous_hash,
                }
            except IntegrityError as exc:
                last_exc = exc
                _log.warning(
                    "local_audit chain_seq collision on org=%s attempt=%d/%d",
                    chain_org, attempt + 1, _MAX_CHAIN_RETRIES,
                )
                # ``get_db()`` already rolled back the failed transaction
                # on exception exit; loop around and try the next seq.
                continue

        raise RuntimeError(
            f"local_audit chain_seq collision persisted for org={chain_org!r} "
            f"after {_MAX_CHAIN_RETRIES} retries"
        ) from last_exc


async def verify_local_chain(org_id: str) -> tuple[bool, str | None]:
    """Recompute every row's entry_hash from canonical inputs and compare.

    Returns ``(True, None)`` when the chain is intact; ``(False, reason)``
    with the first divergent row's description when tampering is found.
    Meant for CLI / dashboard "verify" buttons, not the hot path.
    """
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT id, timestamp, event_type, agent_id, session_id,
                       org_id, details, result, previous_hash, chain_seq,
                       peer_org_id, entry_hash
                  FROM local_audit
                 WHERE org_id = :org_id AND chain_seq IS NOT NULL
                 ORDER BY chain_seq ASC
                """
            ),
            {"org_id": org_id},
        )
        expected_prev: str | None = None
        for row in result.mappings():
            ts_raw = row["timestamp"]
            ts = datetime.fromisoformat(ts_raw) if isinstance(ts_raw, str) else ts_raw
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if row["previous_hash"] != expected_prev:
                return False, (
                    f"row chain_seq={row['chain_seq']} previous_hash mismatch: "
                    f"expected {expected_prev!r}, got {row['previous_hash']!r}"
                )
            expected = compute_entry_hash(
                entry_id=row["id"],
                timestamp=ts,
                event_type=row["event_type"],
                agent_id=row["agent_id"],
                session_id=row["session_id"],
                org_id=row["org_id"],
                result=row["result"],
                details=row["details"],
                previous_hash=row["previous_hash"],
                chain_seq=row["chain_seq"],
                peer_org_id=row["peer_org_id"],
            )
            if expected != row["entry_hash"]:
                return False, (
                    f"row id={row['id']} chain_seq={row['chain_seq']} "
                    f"entry_hash mismatch: expected {expected}, got "
                    f"{row['entry_hash']}"
                )
            expected_prev = row["entry_hash"]
    return True, None
