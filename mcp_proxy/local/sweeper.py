"""Local mini-broker sweeper — ADR-001 Phase 3d.

Background task that periodically:
  - Closes idle or TTL-expired local sessions (mirrors M1 broker-side).
  - Flips TTL-expired pending local_messages rows to `expired` and
    best-effort notifies senders via the local WS manager (mirrors M3.6).

Lifecycle is owned by the FastAPI lifespan in `mcp_proxy/main.py`.
Kept defensive: each step's failures are isolated so one broken piece
doesn't stop the others from running.
"""
from __future__ import annotations

import asyncio
import logging
import os

from mcp_proxy.local import message_queue as local_queue
from mcp_proxy.local.models import SessionStatus
from mcp_proxy.local.persistence import save_session as save_local_session
from mcp_proxy.local.session import (
    LOCAL_SESSION_IDLE_TIMEOUT_SECONDS,
    LocalSessionStore,
)
from mcp_proxy.local.ws_manager import LocalConnectionManager

_log = logging.getLogger("mcp_proxy.local.sweeper")


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


LOCAL_SWEEP_INTERVAL_SECONDS = _env_int("PROXY_LOCAL_SWEEP_INTERVAL_SECONDS", 30)


async def sweep_once(
    store: LocalSessionStore,
    ws_manager: LocalConnectionManager | None = None,
    *,
    idle_timeout_seconds: int = LOCAL_SESSION_IDLE_TIMEOUT_SECONDS,
) -> tuple[int, int]:
    """One sweep pass. Returns `(sessions_closed, messages_expired)`.

    Extracted so tests can exercise the logic deterministically without
    spawning a loop.
    """
    # ── Sessions: close stale (idle or TTL-expired) ──────────────
    stale = store.find_stale(idle_timeout_seconds=idle_timeout_seconds)
    sessions_closed = 0
    for session, reason in stale:
        async with store._lock:
            if session.status == SessionStatus.closed:
                continue
            store.close(session.session_id, reason)

        try:
            await save_local_session(session)
        except Exception:
            _log.exception(
                "sweeper: failed to persist local session %s close",
                session.session_id,
            )

        if ws_manager is not None:
            payload = {
                "type": "session_closed",
                "session_id": session.session_id,
                "reason": reason.value,
            }
            for agent_id in (session.initiator_agent_id, session.responder_agent_id):
                try:
                    await ws_manager.send_to_agent(agent_id, payload)
                except Exception as exc:
                    _log.debug(
                        "session_closed notify failed for %s (session %s): %s",
                        agent_id, session.session_id, exc,
                    )

        sessions_closed += 1
        _log.info(
            "local sweeper closed session %s (reason=%s)",
            session.session_id, reason.value,
        )

    # ── Messages: expire TTL-lapsed pending rows ─────────────────
    try:
        notices = await asyncio.wait_for(local_queue.sweep_expired(), timeout=5.0)
    except asyncio.TimeoutError:
        _log.warning("local sweeper: message queue sweep exceeded 5s — skipping")
        notices = []
    except Exception:
        _log.exception("local sweeper: message queue sweep failed")
        notices = []

    if ws_manager is not None:
        for n in notices:
            payload = {
                "type": "message_expired",
                "session_id": n.session_id,
                "msg_id": n.msg_id,
                "recipient_agent_id": n.recipient_agent_id,
                "reason": "ttl",
            }
            try:
                await ws_manager.send_to_agent(n.sender_agent_id, payload)
            except Exception as exc:
                _log.debug(
                    "message_expired notify failed for sender %s (msg %s): %s",
                    n.sender_agent_id, n.msg_id, exc,
                )

    return sessions_closed, len(notices)


async def sweeper_loop(
    store: LocalSessionStore,
    ws_manager: LocalConnectionManager | None = None,
    *,
    interval_seconds: int = LOCAL_SWEEP_INTERVAL_SECONDS,
    idle_timeout_seconds: int = LOCAL_SESSION_IDLE_TIMEOUT_SECONDS,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run sweeps on a cadence until `stop_event` fires (or task cancel)."""
    _log.info(
        "local sweeper started (interval=%ds, idle_timeout=%ds)",
        interval_seconds, idle_timeout_seconds,
    )
    while True:
        try:
            if stop_event is not None and stop_event.is_set():
                break
            await sweep_once(
                store, ws_manager, idle_timeout_seconds=idle_timeout_seconds,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("local sweeper cycle failed — continuing")

        if stop_event is not None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
                break
            except asyncio.TimeoutError:
                continue
        else:
            await asyncio.sleep(interval_seconds)

    _log.info("local sweeper stopped")
