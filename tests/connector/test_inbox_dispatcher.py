"""InboxDispatcher: drains the poller queue, dedupes msg_ids, sends
to the notifier. Tested without real plyer / real Mastio."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from cullis_connector.inbox_dispatcher import InboxDispatcher, _LRUSeen
from cullis_connector.inbox_poller import InboxEvent


class _FakePoller:
    """Stand-in for DashboardInboxPoller exposing just .events + .SENTINEL."""

    SENTINEL = object()

    def __init__(self) -> None:
        self.events: asyncio.Queue = asyncio.Queue()


def _ev(msg_id: str, sender: str = "acme::alice", text: str = "hello") -> InboxEvent:
    return InboxEvent(
        msg_id=msg_id,
        sender_agent_id=sender,
        correlation_id="c",
        reply_to=None,
        text=text,
    )


# ── _LRUSeen unit ────────────────────────────────────────────────────


def test_lruseen_ignores_duplicates_and_evicts_oldest():
    s = _LRUSeen(maxsize=3)
    s.add("a")
    s.add("b")
    s.add("c")
    assert "a" in s and "b" in s and "c" in s

    s.add("d")  # evicts oldest ("a")
    assert "a" not in s
    assert "b" in s and "c" in s and "d" in s

    # Re-adding "b" promotes it; next overflow should evict "c" not "b".
    s.add("b")
    s.add("e")
    assert "c" not in s
    assert "b" in s and "d" in s and "e" in s


# ── dispatcher ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatcher_calls_notifier_per_unique_event():
    poller = _FakePoller()
    notifier = MagicMock()

    d = InboxDispatcher(poller, notifier)
    d.start()
    try:
        await poller.events.put(_ev("m1", text="hello"))
        await poller.events.put(_ev("m2", sender="acme::bob", text="yo"))
        await asyncio.sleep(0.1)  # let dispatcher drain
    finally:
        await d.stop()

    assert notifier.notify.call_count == 2
    titles = [c.kwargs.get("title") or c.args[0] for c in notifier.notify.call_args_list]
    assert any("acme::alice" in t for t in titles)
    assert any("acme::bob" in t for t in titles)


@pytest.mark.asyncio
async def test_dispatcher_dedupes_repeated_msg_id():
    poller = _FakePoller()
    notifier = MagicMock()

    d = InboxDispatcher(poller, notifier)
    d.start()
    try:
        ev = _ev("m1")
        await poller.events.put(ev)
        await asyncio.sleep(0.05)
        await poller.events.put(ev)  # duplicate
        await poller.events.put(_ev("m2"))
        await asyncio.sleep(0.1)
    finally:
        await d.stop()

    assert notifier.notify.call_count == 2
    msg_ids_seen = [c.args[1] if len(c.args) > 1 else c.kwargs.get("body") for c in notifier.notify.call_args_list]
    # Just confirm we got two distinct calls — the body content is
    # the event preview.
    assert len(set(msg_ids_seen)) >= 1


@pytest.mark.asyncio
async def test_dispatcher_passes_click_url_to_notifier():
    poller = _FakePoller()
    notifier = MagicMock()

    d = InboxDispatcher(poller, notifier, click_url="http://my-dashboard:9999/inbox")
    d.start()
    try:
        await poller.events.put(_ev("m1"))
        await asyncio.sleep(0.05)
    finally:
        await d.stop()

    notifier.notify.assert_called_once()
    kwargs = notifier.notify.call_args.kwargs
    assert kwargs["on_click_url"] == "http://my-dashboard:9999/inbox"


@pytest.mark.asyncio
async def test_dispatcher_stops_on_sentinel():
    poller = _FakePoller()
    notifier = MagicMock()
    d = InboxDispatcher(poller, notifier)
    task = d.start()
    await poller.events.put(poller.SENTINEL)
    # Should exit on its own — not block on stop().
    await asyncio.wait_for(task, timeout=1.0)
    assert task.done()


@pytest.mark.asyncio
async def test_dispatcher_stop_cancels_blocked_consumer():
    """No events flowing — stop() must still complete via cancellation."""
    poller = _FakePoller()
    notifier = MagicMock()
    d = InboxDispatcher(poller, notifier)
    d.start()
    await asyncio.sleep(0.05)
    await d.stop(timeout_s=1.0)  # should return without hanging
    notifier.notify.assert_not_called()


# ── status snapshot + ack ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_status_snapshot_initially_empty():
    poller = _FakePoller()
    d = InboxDispatcher(poller, MagicMock())
    snap = d.status_snapshot()
    assert snap["unread"] == 0
    assert snap["last_sender"] is None
    assert snap["last_preview"] is None
    assert snap["last_received_at"] is None
    assert snap["total_seen"] == 0


@pytest.mark.asyncio
async def test_status_snapshot_tracks_unread_and_last_event():
    poller = _FakePoller()
    d = InboxDispatcher(poller, MagicMock())
    d.start()
    try:
        await poller.events.put(_ev("m1", sender="acme::alice", text="ciao"))
        await poller.events.put(_ev("m2", sender="acme::bob", text="yo"))
        await asyncio.sleep(0.1)
    finally:
        await d.stop()

    snap = d.status_snapshot()
    assert snap["unread"] == 2
    assert snap["last_sender"] == "acme::bob"
    assert snap["last_preview"] == "yo"
    assert snap["last_received_at"] is not None
    assert snap["total_seen"] == 2


@pytest.mark.asyncio
async def test_ack_resets_unread_but_keeps_dedup():
    poller = _FakePoller()
    d = InboxDispatcher(poller, MagicMock())
    d.start()
    try:
        await poller.events.put(_ev("m1"))
        await asyncio.sleep(0.05)

        d.ack()
        snap = d.status_snapshot()
        assert snap["unread"] == 0
        assert snap["total_seen"] == 1  # dedup memory survives ack

        # Re-delivery of the same msg_id stays suppressed.
        await poller.events.put(_ev("m1"))
        await asyncio.sleep(0.05)
        snap = d.status_snapshot()
        assert snap["unread"] == 0

        # New msg bumps the counter again.
        await poller.events.put(_ev("m2"))
        await asyncio.sleep(0.05)
    finally:
        await d.stop()
    assert d.status_snapshot()["unread"] == 1
