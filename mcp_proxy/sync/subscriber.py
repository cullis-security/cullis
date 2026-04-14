"""Federation SSE subscriber task (ADR-001 Phase 4b).

Opens a long-lived `text/event-stream` connection to the broker's
`/v1/broker/federation/events/stream` endpoint, applies each event to
the proxy cache, and persists the cursor so a restart/reconnect resumes
without replaying the full history.

Reconnect strategy is exponential backoff with a ceiling, capped at a
configurable maximum. Transient failures (network blip, broker reboot,
token refresh) don't require human intervention.

Auth is delegated to the caller: the subscriber takes a preconfigured
`httpx.AsyncClient` (or async factory) plus a bearer-style headers dict.
This keeps the subscriber agnostic to DPoP / mTLS / API-key choices —
the wiring in `mcp_proxy/main.py` decides which credential flavor to
use based on the deployment profile.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable

import httpx

from mcp_proxy.db import get_db
from mcp_proxy.sync.handlers import apply_event, get_cursor

_log = logging.getLogger("mcp_proxy.sync.subscriber")


@dataclass
class SubscriberConfig:
    broker_url: str
    org_id: str
    # Factory so each reconnect gets a fresh client with fresh auth
    # (DPoP proofs, SPIFFE cert, etc.). Returning an httpx.AsyncClient
    # with appropriate base_url and headers is the caller's job.
    client_factory: Callable[[], Awaitable[httpx.AsyncClient]]
    initial_backoff_seconds: float = 1.0
    max_backoff_seconds: float = 60.0
    backoff_multiplier: float = 2.0
    # If set, the subscriber stops after this many successful events —
    # used by tests; None in production.
    stop_after_events: int | None = None
    # Observability counters; tests read these to assert behaviour
    # without having to intercept log lines.
    stats: "SubscriberStats" = field(default_factory=lambda: SubscriberStats())


@dataclass
class SubscriberStats:
    connects: int = 0
    reconnects: int = 0
    events_applied: int = 0
    last_applied_seq: int = 0
    last_error: str | None = None


async def run_subscriber(
    cfg: SubscriberConfig,
    *,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Main loop. Exits when `stop_event` is set or `stop_after_events`
    is reached. Each reconnect reloads the cursor from the cache DB so
    out-of-band rebuild-cache invocations are respected."""
    backoff = cfg.initial_backoff_seconds
    while stop_event is None or not stop_event.is_set():
        try:
            applied_this_session = await _run_once(cfg, stop_event=stop_event)
            if cfg.stop_after_events is not None and \
                    cfg.stats.events_applied >= cfg.stop_after_events:
                return
            if applied_this_session > 0:
                backoff = cfg.initial_backoff_seconds
        except Exception as exc:  # noqa: BLE001
            cfg.stats.last_error = f"{type(exc).__name__}: {exc}"
            cfg.stats.reconnects += 1
            _log.warning(
                "federation subscriber error: %s — reconnecting in %.1fs",
                exc, backoff,
            )
        if stop_event is None:
            await asyncio.sleep(backoff)
        else:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=backoff)
                return
            except asyncio.TimeoutError:
                pass
        backoff = min(backoff * cfg.backoff_multiplier, cfg.max_backoff_seconds)


async def _run_once(
    cfg: SubscriberConfig,
    *,
    stop_event: asyncio.Event | None,
) -> int:
    """Open one SSE stream, drain until it closes or we're asked to
    stop. Returns the number of events applied during this attempt."""
    async with get_db() as conn:
        cursor = await get_cursor(conn, cfg.org_id)

    client = await cfg.client_factory()
    cfg.stats.connects += 1
    applied = 0
    try:
        async with client.stream(
            "GET",
            f"{cfg.broker_url.rstrip('/')}/v1/broker/federation/events/stream",
            headers={"Last-Event-ID": str(cursor)} if cursor else None,
            timeout=httpx.Timeout(connect=10.0, read=None, write=10.0, pool=10.0),
        ) as resp:
            resp.raise_for_status()
            async for frame in _iter_sse_frames(resp):
                if stop_event is not None and stop_event.is_set():
                    return applied
                seq = frame.get("id")
                event_type = frame.get("event")
                data = frame.get("data")
                if seq is None or event_type is None or data is None:
                    continue
                if event_type == "connected":
                    continue
                try:
                    payload = json.loads(data)
                except json.JSONDecodeError:
                    _log.warning("malformed SSE data frame — skipping")
                    continue
                seq_int = int(seq)
                async with get_db() as conn:
                    await apply_event(
                        conn,
                        org_id=cfg.org_id,
                        seq=seq_int,
                        event_type=event_type,
                        payload=payload.get("payload", payload),
                    )
                cfg.stats.events_applied += 1
                cfg.stats.last_applied_seq = seq_int
                applied += 1
                if cfg.stop_after_events is not None and \
                        cfg.stats.events_applied >= cfg.stop_after_events:
                    return applied
    finally:
        await client.aclose()
    return applied


async def _iter_sse_frames(resp: httpx.Response):
    """Yield parsed SSE frames from `resp`. Each frame is a dict with
    any of `id`, `event`, `data` fields set.

    SSE wire format: consecutive lines of the form "field: value",
    frames separated by a blank line. We ignore retry/comment lines.
    """
    current: dict[str, str] = {}
    async for line in resp.aiter_lines():
        if line == "":
            if current:
                yield current
                current = {}
            continue
        if line.startswith(":"):
            continue  # keepalive / comment
        if ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        current[field_name] = value
    if current:
        yield current
