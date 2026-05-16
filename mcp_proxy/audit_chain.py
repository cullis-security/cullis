"""Batched audit chain — F0.4 Tier 2 unlock (ADR-033).

In-memory queue + periodic flush, hash chain computed per batch
instead of per row. Trade-off:

  * Throughput: 50-100x improvement (1 fsync + 1 head fetch per batch
    instead of per row).
  * Latency p99: -10x reduction at sustained Tier 2 (no per-row
    asyncio.Lock contention).
  * Immutability proof: preserved per *batch boundary* (~1s at Tier 2
    sustained), not per individual row. Compliance trade-off
    documented in ``enterprise-kit/compliance-posture.md``.
  * Audit visibility lag: bounded by ``flush_interval_s`` between
    ``append()`` and the row landing on disk.
  * Crash safety: rows queued in memory but not flushed are lost on
    SIGKILL / OOM. Mitigation is the bounded flush interval plus
    ``verify_audit_chain`` catching structural breaks; operators
    requiring per-row durability must set ``batch_size=1`` or
    ``MCP_PROXY_AUDIT_CHAIN_DISABLED=true`` to fall back to the
    legacy per-row ``log_audit()`` path.

Cross-process serialisation: each uvicorn worker carries its own
``BatchedAuditChain`` instance. The ``audit_log`` ``UNIQUE(chain_seq)``
constraint plus the retry loop catches race windows between workers
(same pattern as the legacy ``log_audit()`` — see A.1b Run 1 where
4 workers wrote 472k rows with zero IntegrityErrors).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mcp_proxy.db import (
    _AUDIT_CHAIN_MAX_RETRIES,
    _audit_chain_head,
    compute_audit_row_hash,
    get_db,
)

_log = logging.getLogger("mcp_proxy.audit_chain")


_AUDIT_INSERT_SQL = text(
    """INSERT INTO audit_log (
           timestamp, agent_id, action, tool_name,
           status, detail, request_id, duration_ms,
           chain_seq, prev_hash, row_hash, dpop_jkt
       ) VALUES (
           :timestamp, :agent_id, :action, :tool_name,
           :status, :detail, :request_id, :duration_ms,
           :chain_seq, :prev_hash, :row_hash, :dpop_jkt
       )"""
)


class BatchedAuditChain:
    """In-memory batched audit chain with size + time flush triggers.

    Two flush triggers:
      1. **Size threshold** — ``append()`` triggers a synchronous flush
         when ``len(_pending) >= batch_size``.
      2. **Time threshold** — a background task started by ``start()``
         flushes every ``flush_interval_s`` seconds, draining any
         queued rows even under low-throughput scenarios where the
         size threshold would never fire.

    The class is intentionally engine-agnostic — it reads no settings
    at construction time so tests can build instances directly. The
    Mastio lifespan in ``mcp_proxy/main.py`` is responsible for wiring
    the singleton.
    """

    def __init__(
        self,
        *,
        batch_size: int = 100,
        flush_interval_s: float = 1.0,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        if flush_interval_s <= 0:
            raise ValueError("flush_interval_s must be > 0")
        self._batch_size = batch_size
        self._flush_interval_s = flush_interval_s
        self._pending: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._flush_task: asyncio.Task[None] | None = None
        self._stopped = False

    @property
    def batch_size(self) -> int:
        return self._batch_size

    @property
    def flush_interval_s(self) -> float:
        return self._flush_interval_s

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    async def append(self, row: dict[str, Any]) -> None:
        """Queue an audit row; flush synchronously when the size
        threshold is reached.

        ``row`` carries the keys the legacy ``log_audit()`` persists:
        ``timestamp``, ``agent_id``, ``action``, ``tool_name``,
        ``status``, ``detail``, ``request_id``, ``duration_ms``,
        ``dpop_jkt``. Required keys: ``timestamp``, ``agent_id``,
        ``action``, ``status``. Optional keys default to ``None``.
        """
        async with self._lock:
            self._pending.append(row)
            if len(self._pending) >= self._batch_size:
                await self._flush_locked()

    async def flush_now(self) -> int:
        """Force a flush of any pending rows; return rows written.

        Public entrypoint for shutdown drains and tests. Idempotent —
        zero pending rows returns 0 without touching the database.
        """
        async with self._lock:
            return await self._flush_locked()

    async def _flush_locked(self) -> int:
        """Drain ``self._pending`` and persist with the chain hash.

        Caller MUST hold ``self._lock``. Returns the number of rows
        successfully written.

        Failure mode: after ``_AUDIT_CHAIN_MAX_RETRIES`` UNIQUE(chain_seq)
        collisions (every retry refetches the head and recomputes the
        full batch chain) the rows are dropped with a CRITICAL log
        entry. This matches the legacy ``log_audit()`` fail-open
        posture (``MCP_PROXY_AUDIT_FAIL_DENY=false``) — the daemon
        survives so the next batch can flush. Operators who require
        fail-deny semantics must keep ``batch_size=1`` (the legacy
        path raises and surfaces a 500 to the caller).
        """
        if not self._pending:
            return 0
        batch = self._pending
        self._pending = []

        for _attempt in range(_AUDIT_CHAIN_MAX_RETRIES):
            try:
                async with get_db() as conn:
                    last_seq, prev_hash = await _audit_chain_head(conn)
                    insert_params: list[dict[str, Any]] = []
                    running_prev = prev_hash
                    for i, row in enumerate(batch):
                        chain_seq = last_seq + i + 1
                        row_hash = compute_audit_row_hash(
                            chain_seq=chain_seq,
                            timestamp=row["timestamp"],
                            agent_id=row["agent_id"],
                            action=row["action"],
                            tool_name=row.get("tool_name"),
                            status=row["status"],
                            detail=row.get("detail"),
                            request_id=row.get("request_id"),
                            prev_hash=running_prev,
                        )
                        insert_params.append(
                            {
                                "timestamp": row["timestamp"],
                                "agent_id": row["agent_id"],
                                "action": row["action"],
                                "tool_name": row.get("tool_name"),
                                "status": row["status"],
                                "detail": row.get("detail"),
                                "request_id": row.get("request_id"),
                                "duration_ms": row.get("duration_ms"),
                                "chain_seq": chain_seq,
                                "prev_hash": running_prev,
                                "row_hash": row_hash,
                                "dpop_jkt": row.get("dpop_jkt"),
                            }
                        )
                        running_prev = row_hash
                    await conn.execute(_AUDIT_INSERT_SQL, insert_params)
                    return len(batch)
            except IntegrityError:
                # Another worker claimed an overlapping chain_seq
                # window between our head fetch and our INSERT. Refetch
                # the head and rebuild the batch hashes from scratch.
                continue

        _log.critical(
            "BatchedAuditChain: dropped %d row(s) after %d retries on "
            "UNIQUE(chain_seq) conflict; another worker may be stuck. "
            "First row: agent_id=%s action=%s status=%s",
            len(batch),
            _AUDIT_CHAIN_MAX_RETRIES,
            batch[0].get("agent_id"),
            batch[0].get("action"),
            batch[0].get("status"),
        )
        return 0

    async def start(self) -> None:
        """Spawn the periodic flush background task. Idempotent."""
        if self._flush_task is not None and not self._flush_task.done():
            return
        self._stopped = False
        self._flush_task = asyncio.create_task(
            self._periodic_flush_loop(),
            name="mcp_proxy.audit_chain.periodic_flush",
        )

    async def stop(self) -> None:
        """Cancel the periodic task and drain ``_pending``. Idempotent.

        Order matters: cancel the loop first so it cannot enqueue more
        sleeps, then flush_now to drain anything still queued.
        """
        self._stopped = True
        task = self._flush_task
        self._flush_task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:  # pragma: no cover — defensive
                _log.exception(
                    "BatchedAuditChain: periodic flush task crashed during stop()"
                )
        await self.flush_now()

    async def _periodic_flush_loop(self) -> None:
        """Wake every ``flush_interval_s`` and drain ``_pending``.

        Exceptions inside the flush are logged and swallowed so a
        transient DB blip doesn't kill the daemon — the loop continues
        and the next tick retries.
        """
        try:
            while not self._stopped:
                await asyncio.sleep(self._flush_interval_s)
                if self._stopped:
                    break
                try:
                    await self.flush_now()
                except Exception:
                    _log.exception(
                        "BatchedAuditChain: periodic flush raised; "
                        "loop continues to keep the daemon alive"
                    )
        except asyncio.CancelledError:
            raise
