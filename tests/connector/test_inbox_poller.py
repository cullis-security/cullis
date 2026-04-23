"""Tests for DashboardInboxPoller — the long-running poll loop the
dashboard process uses to lift one-shot messages off the local Mastio
and surface them as ``InboxEvent``s for the notifier and SSE feed."""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from cullis_connector.inbox_poller import (
    DashboardInboxPoller,
    InboxEvent,
)
from cullis_sdk import PubkeyFetchError


class _FakeClient:
    """Drives the poller with scripted ``receive_oneshot`` outputs and a
    deterministic ``decrypt_oneshot`` mock.

    ``decrypt_oneshot`` accepts the ``pubkey_fetcher`` kwarg the real
    SDK now exposes — the poller always passes it, so the fake must
    swallow the keyword. The fetcher itself isn't invoked by this
    fake unless an individual test wires it up.
    """

    def __init__(
        self,
        rounds: list[Any],
        decoder=None,
    ) -> None:
        # Each entry in ``rounds`` is either a list of rows (success)
        # or an Exception class/instance (failure round).
        self._rounds = list(rounds)
        self._decoder = decoder or (
            lambda r: {"payload": {"text": r.get("text", "decoded")}}
        )
        self.calls = 0
        self.pubkey_fetch_calls: list[str] = []

    def get_agent_public_key_via_egress(
        self, agent_id: str, force_refresh: bool = False,
    ) -> str:
        """Default fetcher — returns a stub PEM. Tests that want to
        exercise the failure branch override this on the instance."""
        self.pubkey_fetch_calls.append(agent_id)
        return "-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----"

    def receive_oneshot(self) -> list[dict]:
        self.calls += 1
        if not self._rounds:
            return []
        nxt = self._rounds.pop(0)
        if isinstance(nxt, BaseException) or (
            isinstance(nxt, type) and issubclass(nxt, BaseException)
        ):
            raise (nxt() if isinstance(nxt, type) else nxt)
        return list(nxt)

    def decrypt_oneshot(self, row: dict, *, pubkey_fetcher=None) -> dict:
        # Mirror the real SDK contract: when a fetcher is provided, call
        # it so tests can observe / inject failures via that surface.
        if pubkey_fetcher is not None:
            pubkey_fetcher(row.get("sender_agent_id", ""))
        return self._decoder(row)


async def _drain_events(poller: DashboardInboxPoller, n: int, timeout: float = 2.0) -> list[InboxEvent]:
    out: list[InboxEvent] = []
    for _ in range(n):
        ev = await asyncio.wait_for(poller.events.get(), timeout=timeout)
        out.append(ev)
    return out


@pytest.mark.asyncio
async def test_poll_emits_events_for_each_decoded_row():
    rows = [
        {"msg_id": "m1", "sender_agent_id": "acme::alice", "correlation_id": "c1", "reply_to": None, "text": "hi"},
        {"msg_id": "m2", "sender_agent_id": "acme::bob", "correlation_id": "c2", "reply_to": "m1", "text": "yo"},
    ]
    client = _FakeClient(rounds=[rows])
    poller = DashboardInboxPoller(client, poll_interval_s=99.0)

    poller.start()
    try:
        events = await _drain_events(poller, n=2)
    finally:
        await poller.stop(timeout_s=1.0)

    assert {e.msg_id for e in events} == {"m1", "m2"}
    by_id = {e.msg_id: e for e in events}
    assert by_id["m1"].text == "hi"
    assert by_id["m2"].reply_to == "m1"
    assert by_id["m1"].sender_agent_id == "acme::alice"


@pytest.mark.asyncio
async def test_decode_failure_drops_row_silently():
    """Bad signature → row is logged and skipped, no event emitted, the
    next round still produces."""
    counter = {"n": 0}

    def _decoder(row):
        counter["n"] += 1
        if counter["n"] == 1:
            raise RuntimeError("bad sig")
        return {"payload": {"text": row.get("text")}}

    rows_round1 = [{"msg_id": "bad", "sender_agent_id": "acme::mallory", "correlation_id": "c", "reply_to": None, "text": "x"}]
    rows_round2 = [{"msg_id": "good", "sender_agent_id": "acme::alice", "correlation_id": "c2", "reply_to": None, "text": "ok"}]
    client = _FakeClient(rounds=[rows_round1, rows_round2], decoder=_decoder)

    poller = DashboardInboxPoller(client, poll_interval_s=0.05)
    poller.start()
    try:
        events = await _drain_events(poller, n=1, timeout=2.0)
    finally:
        await poller.stop(timeout_s=1.0)

    assert len(events) == 1
    assert events[0].msg_id == "good"


@pytest.mark.asyncio
async def test_missing_msg_id_row_skipped():
    """Defensive: a row without msg_id can't be deduped or replied to,
    so we don't surface it."""
    rows = [
        {"sender_agent_id": "acme::a", "correlation_id": "c", "reply_to": None, "text": "no id"},
        {"msg_id": "m1", "sender_agent_id": "acme::a", "correlation_id": "c", "reply_to": None, "text": "ok"},
    ]
    client = _FakeClient(rounds=[rows])
    poller = DashboardInboxPoller(client, poll_interval_s=99.0)
    poller.start()
    try:
        events = await _drain_events(poller, n=1)
    finally:
        await poller.stop(timeout_s=1.0)
    assert events[0].msg_id == "m1"


@pytest.mark.asyncio
async def test_backoff_on_receive_failure():
    """Failing receive_oneshot triggers exponential backoff but keeps
    retrying — the next success eventually emits an event."""
    rows_after_fail = [{"msg_id": "m1", "sender_agent_id": "acme::a", "correlation_id": "c", "reply_to": None, "text": "after"}]
    client = _FakeClient(rounds=[ConnectionError, rows_after_fail])

    # Tight intervals so the test runs in <1s. Backoff of attempt #1
    # is 5s in production, but the wait is interruptible by stop_evt
    # which we don't fire — so use the small default and stop right
    # after seeing the success event.
    poller = DashboardInboxPoller(client, poll_interval_s=0.05, max_backoff_s=0.1)
    poller.start()
    try:
        events = await _drain_events(poller, n=1, timeout=3.0)
    finally:
        await poller.stop(timeout_s=1.0)
    assert events[0].msg_id == "m1"


@pytest.mark.asyncio
async def test_bounded_queue_drops_oldest_event():
    """maxsize=2 + 3 incoming events → newest 2 win, oldest dropped."""
    rows = [
        {"msg_id": "old", "sender_agent_id": "acme::a", "correlation_id": "c0", "reply_to": None, "text": "oldest"},
        {"msg_id": "mid", "sender_agent_id": "acme::a", "correlation_id": "c1", "reply_to": None, "text": "middle"},
        {"msg_id": "new", "sender_agent_id": "acme::a", "correlation_id": "c2", "reply_to": None, "text": "newest"},
    ]
    client = _FakeClient(rounds=[rows])
    poller = DashboardInboxPoller(client, poll_interval_s=99.0, queue_maxsize=2)
    poller.start()
    # Let the producer fill the queue + drop one.
    await asyncio.sleep(0.1)
    await poller.stop(timeout_s=1.0)

    received_ids: set[str] = set()
    while True:
        try:
            ev = poller.events.get_nowait()
        except asyncio.QueueEmpty:
            break
        if ev is poller.SENTINEL:
            continue
        received_ids.add(ev.msg_id)

    assert "old" not in received_ids
    assert {"mid", "new"} <= received_ids


@pytest.mark.asyncio
async def test_stop_releases_blocked_consumer_via_sentinel():
    """A consumer awaiting events.get() must wake up when the poller
    stops, so the dashboard shutdown doesn't hang."""
    client = _FakeClient(rounds=[])  # never produces anything
    poller = DashboardInboxPoller(client, poll_interval_s=99.0)
    poller.start()

    consumer_woke = asyncio.Event()

    async def _consume():
        ev = await poller.events.get()
        if ev is poller.SENTINEL:
            consumer_woke.set()

    consume_task = asyncio.create_task(_consume())
    await asyncio.sleep(0.05)
    await poller.stop(timeout_s=1.0)
    await asyncio.wait_for(consumer_woke.wait(), timeout=1.0)
    consume_task.cancel()


@pytest.mark.asyncio
async def test_pubkey_fetch_failure_skips_message_does_not_crash_loop():
    """Security invariant — if the SDK pubkey fetcher raises
    ``PubkeyFetchError`` (empty cert_pem, network error, peer not
    found), the poller MUST log at ERROR and skip the row, NOT
    surface unverified plaintext. Loop continues so subsequent rounds
    still drain the inbox.

    Exercise recovery: round 1 fetcher fails, round 2 succeeds —
    we await the successful event to pin the survival invariant
    deterministically (no flaky time-based asserts).
    """
    failure_rounds = {"left": 1}
    fetch_calls = {"count": 0}
    decode_attempts = {"count": 0}

    class _RecoverableClient(_FakeClient):
        def get_agent_public_key_via_egress(
            self, agent_id, force_refresh=False,
        ):
            fetch_calls["count"] += 1
            if failure_rounds["left"] > 0:
                failure_rounds["left"] -= 1
                raise PubkeyFetchError(
                    f"proxy returned no cert_pem for {agent_id}"
                )
            return "STUB-PEM"

        def decrypt_oneshot(self, row, *, pubkey_fetcher=None):
            decode_attempts["count"] += 1
            return super().decrypt_oneshot(row, pubkey_fetcher=pubkey_fetcher)

    rows_round1 = [{"msg_id": "skip-me", "sender_agent_id": "acme::alice", "correlation_id": "c", "reply_to": None, "text": "x"}]
    rows_round2 = [{"msg_id": "next-round", "sender_agent_id": "acme::alice", "correlation_id": "c2", "reply_to": None, "text": "ok"}]
    client = _RecoverableClient(rounds=[rows_round1, rows_round2])

    poller = DashboardInboxPoller(client, poll_interval_s=0.05)
    poller.start()
    try:
        events = await _drain_events(poller, n=1, timeout=3.0)
    finally:
        await poller.stop(timeout_s=1.0)

    # Loop kept running past the skip — the NEXT round produced.
    assert events[0].msg_id == "next-round"
    # Fetcher was hit twice (round 1 skip + round 2 success),
    # so the skip path actually ran — not a silent fallthrough.
    assert fetch_calls["count"] == 2, fetch_calls
    # decrypt_oneshot was entered for both rounds (the fetcher runs
    # inside decrypt_oneshot in the real SDK; the fake mirrors that).
    # Round 1 raised inside decrypt; round 2 succeeded.
    assert decode_attempts["count"] == 2, decode_attempts


@pytest.mark.asyncio
async def test_canonicalizes_bare_sender():
    """A row whose sender_agent_id is bare (legacy intra-org) must be
    promoted to ``<org>::<name>`` so downstream reply() speaks the
    canonical form the Mastio expects."""
    from unittest.mock import MagicMock
    from cullis_connector.state import get_state, reset_state

    reset_state()
    fake_attr = MagicMock()
    fake_attr.value = "acme"
    fake_cert = MagicMock()
    fake_cert.subject.get_attributes_for_oid.return_value = [fake_attr]
    fake_identity = MagicMock()
    fake_identity.cert = fake_cert
    get_state().extra["identity"] = fake_identity

    rows = [{"msg_id": "m1", "sender_agent_id": "alice", "correlation_id": "c", "reply_to": None, "text": "hi"}]
    client = _FakeClient(rounds=[rows])
    poller = DashboardInboxPoller(client, poll_interval_s=99.0)
    poller.start()
    try:
        events = await _drain_events(poller, n=1)
    finally:
        await poller.stop(timeout_s=1.0)
        reset_state()

    assert events[0].sender_agent_id == "acme::alice"
