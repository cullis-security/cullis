"""SSE endpoint for proxies to mirror per-org broker state (Phase 4a).

A proxy subscribes with its agent credentials and replays all events
with `seq > since_seq`, then tails new ones. Events are filtered to
the org of the authenticated agent: cross-org leakage is impossible at
this layer because the SQL `WHERE org_id = :org` clause is derived from
the token, not the query string.

The transport is bare SSE (text/event-stream). Each event carries:
  - `id: <seq>` so the client can resume via `Last-Event-ID` header
    per SSE spec (and/or `?since_seq=` query param as a fallback).
  - `event: <event_type>` from the federation catalogue.
  - `data: <json>` payload.

No persistent in-memory subscriber set: the stream polls the DB every
`_POLL_INTERVAL_SECONDS` for new events. Single-process and multi-worker
deployments both work since the source of truth is the table. A future
optimization can wake the poller via pg_notify / Redis pubsub.
"""
from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import TokenPayload, get_current_agent
from app.broker.federation import list_events_since
from app.db.database import AsyncSessionLocal, get_db

router = APIRouter(prefix="/broker/federation", tags=["federation"])

# Session factory used by the tail loop. Exposed as a module attribute
# so tests can swap in their in-memory TestSessionLocal without having
# to patch every call site. Production paths never touch this.
_tail_session_factory = AsyncSessionLocal

# How often the streaming task polls the DB for new events. 2s balances
# latency against DB load; bulk replays (after a long proxy outage)
# drain in the first tick so this only governs tail latency.
_POLL_INTERVAL_SECONDS = 2.0

# How often we emit an SSE keepalive comment when there are no events,
# so intermediate proxies/load balancers don't idle-close the stream.
_KEEPALIVE_INTERVAL_SECONDS = 25.0

# Hard cap on events returned per tick. Prevents a single proxy
# reconnecting after a long outage from pulling a huge batch into
# memory at once; the next tick continues where this one left off.
_BATCH_LIMIT = 500


def _parse_since(request: Request, since_seq: int) -> int:
    """Prefer `Last-Event-ID` header if present (standard SSE resume
    semantics); fall back to the query param. Ignore malformed values."""
    header = request.headers.get("Last-Event-ID")
    if header:
        try:
            return max(0, int(header))
        except ValueError:
            pass
    return max(0, since_seq)


@router.get("/events/stream")
async def federation_events_stream(
    request: Request,
    since_seq: int = 0,
    current: TokenPayload = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Tail the federation event log scoped to the caller's org.

    `since_seq` (or `Last-Event-ID`) is the cursor — the next event
    returned will have `seq = since_seq + 1` or higher. Pass `0` on a
    first connection to receive the full history (up to backlog).
    """
    org_id = current.org
    cursor = _parse_since(request, since_seq)

    async def event_stream() -> AsyncIterator[str]:
        nonlocal cursor
        yield "event: connected\ndata: {\"cursor\":" + str(cursor) + "}\n\n"

        # Drain any backlog using the request-scoped session first, so a
        # proxy reconnecting from a stale cursor sees everything before
        # we start polling.
        events = await list_events_since(
            db, org_id=org_id, since_seq=cursor, limit=_BATCH_LIMIT,
        )
        for ev in events:
            yield _format_sse(ev.seq, ev.event_type, ev.as_dict())
            cursor = ev.seq

        last_keepalive = asyncio.get_event_loop().time()

        # Tail loop: open a fresh session per tick to avoid pinning the
        # request-scoped session for the lifetime of the stream.
        while True:
            if await request.is_disconnected():
                return
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            async with _tail_session_factory() as tick_db:
                new_events = await list_events_since(
                    tick_db, org_id=org_id, since_seq=cursor,
                    limit=_BATCH_LIMIT,
                )
            if new_events:
                for ev in new_events:
                    yield _format_sse(ev.seq, ev.event_type, ev.as_dict())
                    cursor = ev.seq
                last_keepalive = asyncio.get_event_loop().time()
                continue
            now = asyncio.get_event_loop().time()
            if now - last_keepalive >= _KEEPALIVE_INTERVAL_SECONDS:
                yield ": keepalive\n\n"
                last_keepalive = now

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _format_sse(seq: int, event_type: str, payload: dict) -> str:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return f"id: {seq}\nevent: {event_type}\ndata: {data}\n\n"
