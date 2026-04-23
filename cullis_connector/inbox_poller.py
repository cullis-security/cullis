"""Background inbox poller for the dashboard process.

The MCP stdio server only lives while the user's MCP client (Claude
Code, Cursor, …) is open — closing the client kills the polling
loop and you stop seeing notifications. The dashboard process,
installed by `cullis-connector install-autostart`, stays up at login
and is the right place to keep a long-lived ``receive_oneshot``
poller running.

Layout:

    DashboardInboxPoller
      └─ asyncio.Task that ticks every poll_interval_s
         ├─ on success: emits decoded envelopes to app.state.inbox_events
         └─ on failure: exponential backoff (5s → poll_interval_s × 6 cap)

The poller does NOT call the notifier directly — that's wired by
M2.3 so the queue can have multiple consumers (notifier, SSE feed,
test inspectors).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from cullis_connector.tools._identity import canonical_recipient
from cullis_sdk import PubkeyFetchError

if TYPE_CHECKING:
    from cullis_sdk import CullisClient

_log = logging.getLogger("cullis_connector.inbox_poller")


@dataclass
class InboxEvent:
    """A single decoded one-shot message lifted off the inbox.

    Mirrors the shape the dashboard SSE feed and the notifier consume.
    Only successful decodes get an event — bad-signature rows are
    logged and dropped.
    """
    msg_id: str
    sender_agent_id: str       # canonicalized "<org>::<name>"
    correlation_id: str | None
    reply_to: str | None
    text: str
    received_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def preview(self, length: int = 80) -> str:
        return (
            self.text if len(self.text) <= length
            else self.text[: length - 1] + "…"
        )


@dataclass
class _BackoffState:
    """Mutable backoff bookkeeping kept out of the public surface."""
    consecutive_failures: int = 0
    next_delay_s: float = 0.0


class DashboardInboxPoller:
    """Long-running poller that ticks while the dashboard is up.

    Owns nothing the rest of the app touches directly — produces
    events on a bounded queue. Stop with :meth:`stop` (sends a
    sentinel and awaits the task) or by cancelling the surrounding
    lifespan, both are safe.
    """

    SENTINEL: Any = object()

    def __init__(
        self,
        client: "CullisClient",
        *,
        poll_interval_s: float = 10.0,
        queue_maxsize: int = 50,
        max_backoff_s: float = 60.0,
    ) -> None:
        self._client = client
        self._poll_interval_s = poll_interval_s
        self._max_backoff_s = max_backoff_s
        self._events: asyncio.Queue[InboxEvent | object] = asyncio.Queue(
            maxsize=queue_maxsize
        )
        self._stop_evt = asyncio.Event()
        self._backoff = _BackoffState()
        self._task: asyncio.Task | None = None

    # ── public API ───────────────────────────────────────────────────

    @property
    def events(self) -> asyncio.Queue:
        """Bounded queue producers can subscribe to.

        Callers ``await events.get()`` to receive :class:`InboxEvent`s
        in arrival order, or :attr:`SENTINEL` when the poller is
        shutting down.
        """
        return self._events

    def start(self) -> asyncio.Task:
        if self._task is not None and not self._task.done():
            return self._task
        self._stop_evt.clear()
        self._task = asyncio.create_task(self._run(), name="inbox-poller")
        return self._task

    async def stop(self, *, timeout_s: float = 5.0) -> None:
        self._stop_evt.set()
        if self._task is None:
            return
        try:
            await asyncio.wait_for(self._task, timeout=timeout_s)
        except asyncio.TimeoutError:
            self._task.cancel()
        finally:
            try:
                # Best-effort sentinel so blocked consumers wake up.
                self._events.put_nowait(self.SENTINEL)
            except asyncio.QueueFull:
                pass

    # ── internals ────────────────────────────────────────────────────

    async def _run(self) -> None:
        _log.info("inbox poller started, interval=%.1fs", self._poll_interval_s)
        while not self._stop_evt.is_set():
            try:
                await self._tick()
                self._backoff.consecutive_failures = 0
                self._backoff.next_delay_s = 0.0
                delay = self._poll_interval_s
            except Exception as exc:  # noqa: BLE001
                self._backoff.consecutive_failures += 1
                # 5s → 10s → 20s → 40s capped at max_backoff_s
                self._backoff.next_delay_s = min(
                    5.0 * (2 ** (self._backoff.consecutive_failures - 1)),
                    self._max_backoff_s,
                )
                _log.warning(
                    "inbox poll failed (attempt %d, next in %.1fs): %s",
                    self._backoff.consecutive_failures,
                    self._backoff.next_delay_s,
                    exc,
                )
                delay = self._backoff.next_delay_s

            try:
                await asyncio.wait_for(self._stop_evt.wait(), timeout=delay)
                # stop_evt fired → loop exits next iteration.
            except asyncio.TimeoutError:
                continue
        _log.info("inbox poller stopped")

    async def _tick(self) -> None:
        """One poll round: fetch + decrypt + enqueue per row."""
        # CullisClient is sync; we offload to a thread so the loop
        # stays responsive even if the local Mastio is slow.
        rows = await asyncio.to_thread(self._client.receive_oneshot)
        if not rows:
            return
        for row in rows:
            event = await asyncio.to_thread(self._decode_row, row)
            if event is None:
                continue
            try:
                self._events.put_nowait(event)
            except asyncio.QueueFull:
                # Bounded queue — drop the oldest unread event so the
                # newest still surfaces. Operators that genuinely want
                # an unbounded backlog should drain the queue faster.
                try:
                    self._events.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                self._events.put_nowait(event)

    def _decode_row(self, row: dict) -> InboxEvent | None:
        """Sync helper — runs in the to_thread pool. Returns None on
        any decode/verify failure (logged so tests + operators can see)."""
        sender_raw = row.get("sender_agent_id", "?")
        sender = (
            sender_raw if "::" in sender_raw
            else canonical_recipient(sender_raw)
        )
        msg_id = row.get("msg_id")
        if not msg_id:
            return None
        # decrypt_oneshot needs the sender's cert to verify the envelope
        # signature. Device-code-enrolled Connectors can't spend a
        # broker JWT on the Court's federation API, so we hand the SDK
        # the proxy-backed fetcher that auths with X-API-Key + DPoP.
        # Pubkey-lookup failures are security-relevant (the message is
        # dropped so no unverified plaintext surfaces) — log at ERROR
        # so operators see the skip without toggling DEBUG. Other decrypt
        # errors (malformed envelope, signature mismatch) stay at WARNING.
        try:
            decoded = self._client.decrypt_oneshot(
                row,
                pubkey_fetcher=self._client.get_agent_public_key_via_egress,
            )
        except PubkeyFetchError as exc:
            _log.error(
                "skipping msg %s from %s — pubkey fetch failed: %s",
                msg_id, sender, exc,
            )
            return None
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "decrypt_oneshot failed for msg %s from %s: %s",
                msg_id, sender, exc,
            )
            return None
        payload = decoded.get("payload") or {}
        text = (
            payload["text"] if isinstance(payload, dict) and "text" in payload
            else str(payload)
        )
        return InboxEvent(
            msg_id=msg_id,
            sender_agent_id=sender,
            correlation_id=row.get("correlation_id"),
            reply_to=row.get("reply_to"),
            text=text,
        )
