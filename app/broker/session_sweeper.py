"""
Background session sweeper (M1.1).

Periodically scans the in-memory session store for sessions that should
be closed:

- ``ttl_expired``  → hard TTL (``expires_at``) reached
- ``idle_timeout`` → no activity within ``SESSION_IDLE_TIMEOUT_SECONDS``

For each stale session the sweeper:
1. Mutates the in-memory state via ``store.close(session_id, reason)``
2. Persists the new state to the DB (``save_session``)
3. Emits a best-effort ``session.closed`` event to both peers via the
   WebSocket manager (M1.3 — O3 decision: best-effort, not durable)
4. Records metrics

The task is owned by the FastAPI lifespan: started in ``lifespan`` and
cancelled on shutdown.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.broker.models import SessionCloseReason, SessionStatus
from app.broker.session import (
    SESSION_IDLE_TIMEOUT_SECONDS,
    Session,
    SessionStore,
)

_log = logging.getLogger("agent_trust")

# Default cycle interval. Overridable via env for tests (see app/broker/session.py
# for the _env_int helper pattern; kept simple here to avoid a back-import).
import os

try:
    SWEEP_INTERVAL_SECONDS = max(1, int(os.environ.get("SESSION_SWEEP_INTERVAL_SECONDS", "30")))
except ValueError:
    SWEEP_INTERVAL_SECONDS = 30


async def _emit_closed_event(session: Session, reason: SessionCloseReason) -> None:
    """Best-effort notification to both peers (M1.3, O3 decision)."""
    # Imported lazily so the sweeper module does not force ws_manager wiring
    # in contexts (tests, tools) that don't need it.
    try:
        from app.broker.ws_manager import ws_manager
    except Exception:
        return

    payload = {
        "type": "session_closed",
        "session_id": session.session_id,
        "reason": reason.value,
    }
    for agent_id in (session.initiator_agent_id, session.target_agent_id):
        try:
            await ws_manager.send_to_agent(agent_id, payload)
        except Exception as exc:  # noqa: BLE001 — best-effort, swallow
            _log.debug(
                "session.closed notify failed for %s (session %s): %s",
                agent_id, session.session_id, exc,
            )


async def _sweep_message_queue() -> int:
    """Expire TTL-lapsed queued messages and notify their senders (M3.6).

    Runs on each sweeper cycle. Isolated so DB or WS failures don't
    kill the session sweep. Returns the number of messages expired.

    Skipped under pytest (``PYTEST_CURRENT_TEST`` env set): the sweep
    contends with the in-memory SQLite StaticPool used in tests and can
    deadlock the suite. The queue expiry behaviour is covered directly
    by ``tests/test_m3_sweeper_ttl.py`` calling this function in
    isolation, so we don't lose coverage.
    """
    if os.environ.get("CULLIS_DISABLE_QUEUE_OPS") == "1":
        return 0

    try:
        from app.broker import message_queue as mq
        from app.broker.ws_manager import ws_manager
        from app.db.database import AsyncSessionLocal
        from app.telemetry_metrics import MESSAGE_EXPIRED_COUNTER
    except Exception:
        return 0

    try:
        async with AsyncSessionLocal() as db:
            notices = await asyncio.wait_for(mq.sweep_expired(db), timeout=5.0)
    except asyncio.TimeoutError:
        _log.warning("sweeper: message queue sweep exceeded 5s — skipping this cycle")
        return 0
    except Exception:
        _log.exception("sweeper: message queue sweep failed")
        return 0

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
        except Exception as exc:  # noqa: BLE001
            _log.debug(
                "message_expired notify failed for sender %s (msg %s): %s",
                n.sender_agent_id, n.msg_id, exc,
            )

    if notices:
        MESSAGE_EXPIRED_COUNTER.add(len(notices))
    return len(notices)


async def _persist_closed(session: Session) -> None:
    """Persist the close to the DB. Isolated so failures don't kill the sweep."""
    try:
        from app.broker.persistence import save_session
        from app.db.database import AsyncSessionLocal
    except Exception:
        return

    try:
        async with AsyncSessionLocal() as db:
            await save_session(db, session)
    except Exception:  # noqa: BLE001
        _log.exception(
            "sweeper: failed to persist session %s close", session.session_id
        )


async def sweep_once(
    store: SessionStore,
    idle_timeout_seconds: int = SESSION_IDLE_TIMEOUT_SECONDS,
) -> int:
    """Run a single sweep pass. Returns the number of sessions closed.

    Extracted so tests can trigger sweeps deterministically without waiting
    for the background loop.
    """
    # Import here to avoid import cycles during test bootstrap.
    from app.telemetry_metrics import (
        SESSION_CLOSED_COUNTER,
        SESSION_SWEEPER_CLOSED_COUNTER,
        SESSION_SWEEPER_CYCLES_COUNTER,
    )

    stale = store.find_stale(idle_timeout_seconds=idle_timeout_seconds)
    closed = 0
    for session, reason in stale:
        # Re-check under lock: another task may have closed it in the meantime.
        async with store._lock:
            if session.status == SessionStatus.closed:
                continue
            store.close(session.session_id, reason)

        await _persist_closed(session)
        await _emit_closed_event(session, reason)

        SESSION_CLOSED_COUNTER.add(1, {"reason": reason.value, "source": "sweeper"})
        SESSION_SWEEPER_CLOSED_COUNTER.add(1, {"reason": reason.value})
        closed += 1
        _log.info(
            "sweeper closed session %s (reason=%s, initiator=%s, target=%s)",
            session.session_id, reason.value,
            session.initiator_agent_id, session.target_agent_id,
        )

    # M3.6 — also sweep TTL-expired queued messages (independent of session close).
    await _sweep_message_queue()

    SESSION_SWEEPER_CYCLES_COUNTER.add(1, {"closed": str(closed)})
    return closed


async def sweeper_loop(
    store: SessionStore,
    interval_seconds: int = SWEEP_INTERVAL_SECONDS,
    idle_timeout_seconds: int = SESSION_IDLE_TIMEOUT_SECONDS,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    """Run the sweeper loop until ``stop_event`` fires (or cancel)."""
    _log.info(
        "session sweeper started (interval=%ds, idle_timeout=%ds)",
        interval_seconds, idle_timeout_seconds,
    )
    while True:
        try:
            if stop_event is not None and stop_event.is_set():
                break
            await sweep_once(store, idle_timeout_seconds=idle_timeout_seconds)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            _log.exception("sweeper cycle failed — continuing")
        # Wait out the interval, waking early if shutdown signalled.
        if stop_event is not None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
                break  # stop_event set
            except asyncio.TimeoutError:
                continue
        else:
            await asyncio.sleep(interval_seconds)

    _log.info("session sweeper stopped")
