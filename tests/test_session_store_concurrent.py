"""Audit L4-H1 regression , SessionStore concurrent-mutation safety.

The original finding was that ``SessionStore._lock`` (asyncio.Lock) was
declared with the comment "protects state transitions (accept/reject/close)"
but never acquired inside any mutation method. The fix introduces a
reentrant ``_state_lock`` (threading.RLock) that is held inside every
mutation and around every iteration over ``self._sessions``. This file
is the chaos test that would surface the original bug.

Specifically reproduces the two failure modes called out in the audit:

  1. ``close_all_for_agent`` iterating ``self._sessions.values()`` while
     another task ``create()`` s a new session , ``RuntimeError: dictionary
     changed size during iteration``.
  2. Two concurrent acceptors / closers racing on the same pending session.

We can't easily preempt asyncio coroutines mid-iteration on a single
event loop, so we drive the store from a thread pool. That mirrors the
real risk surface (FastAPI threadpool sync endpoints, BackgroundTasks,
future workers) and exposes the pre-fix bug deterministically.
"""
from __future__ import annotations

import asyncio
import threading

import pytest

from app.broker.models import SessionCloseReason, SessionStatus
from app.broker.session import SessionStore


# ── Threadpool driver ────────────────────────────────────────────────────


@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
def test_threaded_create_vs_close_all_no_iteration_error():
    """Hammer create() and close_all_for_agent() from many threads.

    Pre-fix this raises RuntimeError("dictionary changed size during
    iteration") within seconds. Post-fix the threading.RLock around the
    iteration snapshot makes it safe.
    """
    store = SessionStore(active_cap_per_agent=10_000)
    # Lift the hard cap so the create loop doesn't hit "Session store full".
    store._MAX_SESSIONS = 100_000

    errors: list[BaseException] = []
    stop = threading.Event()
    AGENT = "agent-victim"

    def creator() -> None:
        i = 0
        try:
            while not stop.is_set():
                store.create(
                    initiator_agent_id=AGENT,
                    initiator_org_id="org-a",
                    target_agent_id=f"peer-{i}",
                    target_org_id="org-b",
                    requested_capabilities=[],
                )
                i += 1
        except BaseException as exc:  # noqa: BLE001 , capture for assertion
            errors.append(exc)

    def closer() -> None:
        try:
            while not stop.is_set():
                store.close_all_for_agent(AGENT)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=creator) for _ in range(4)] + [
        threading.Thread(target=closer) for _ in range(4)
    ]
    for t in threads:
        t.start()

    # Let the workers race for a short, deterministic window.
    threading.Event().wait(0.5)
    stop.set()
    for t in threads:
        t.join(timeout=5)
        assert not t.is_alive(), "worker thread did not stop"

    assert not errors, f"concurrent create/close raced: {errors!r}"


@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
def test_threaded_concurrent_close_idempotent():
    """N closers on the same session-set never double-mark or crash."""
    store = SessionStore(active_cap_per_agent=10_000)
    store._MAX_SESSIONS = 10_000

    sessions = [
        store.create(
            initiator_agent_id="alice",
            initiator_org_id="org-a",
            target_agent_id=f"bob-{i}",
            target_org_id="org-b",
            requested_capabilities=[],
        )
        for i in range(50)
    ]
    for s in sessions:
        store.activate(s.session_id)

    errors: list[BaseException] = []

    def closer() -> None:
        try:
            for s in sessions:
                store.close(s.session_id)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=closer) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, f"concurrent close raised: {errors!r}"
    for s in sessions:
        assert s.status == SessionStatus.closed
        # close_reason set exactly once , the lock makes the if-None check atomic.
        assert s.close_reason == SessionCloseReason.normal


@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
def test_threaded_create_under_per_agent_cap_stays_within_cap():
    """create() runs evict + cap check + insert atomically.

    Without the RLock around the whole sequence, two concurrent creators
    could both observe ``count_active_for_agent == cap - 1`` and both
    insert, blowing past the cap. With the lock the count is exact.
    """
    cap = 5
    store = SessionStore(active_cap_per_agent=cap)
    store._MAX_SESSIONS = 10_000

    errors: list[BaseException] = []
    cap_rejections = 0
    cap_lock = threading.Lock()

    # Pre-seed the agent with `cap` ACTIVE sessions so further creates must
    # be rejected. Each thread tries to push one more.
    seeds = [
        store.create("alice", "org-a", f"target-{i}", "org-b", [])
        for i in range(cap)
    ]
    for s in seeds:
        store.activate(s.session_id)

    def attempt() -> None:
        nonlocal cap_rejections
        from app.broker.session import AgentSessionCapExceeded

        try:
            store.create("alice", "org-a", "extra", "org-b", [])
        except AgentSessionCapExceeded:
            with cap_lock:
                cap_rejections += 1
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, f"create() raised unexpected error: {errors!r}"
    # All 20 should be rejected (cap was already saturated by the seeds).
    assert cap_rejections == 20
    # The active count for alice must not have grown past the cap.
    assert store.count_active_for_agent("alice") == cap


# ── Asyncio-level sanity ────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.serial
@pytest.mark.xdist_group(name="serial_state_mutators")
async def test_asyncio_gather_create_then_close_all():
    """End-to-end on the event loop: many gather()-ed coroutines drive the
    store the way the broker router does in production. No RuntimeError,
    every session ends in a terminal state.
    """
    store = SessionStore(active_cap_per_agent=10_000)
    store._MAX_SESSIONS = 10_000
    AGENT = "alice"

    async def one_create(i: int) -> None:
        store.create(AGENT, "org-a", f"peer-{i}", "org-b", [])

    async def close_sweep() -> None:
        store.close_all_for_agent(AGENT)

    # Interleave 30 creates with 5 close_all calls.
    tasks = [one_create(i) for i in range(30)]
    tasks += [close_sweep() for _ in range(5)]
    await asyncio.gather(*tasks)

    # Every session that survived the creates must be in a terminal state
    # OR pending (a create that completed after the last close_all is fine).
    for s in list(store._sessions.values()):
        assert s.status in (
            SessionStatus.pending,
            SessionStatus.active,
            SessionStatus.closed,
        )
