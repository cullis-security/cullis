"""In-process idempotency cache for
``POST /v1/onboarding/orgs/{org_id}/mastio-pubkey/rotate``.

A legitimate operator who retries a rotation (network blip, proxy
restart, UI double-click) sends the same continuity proof twice within
the 600-second freshness window. Without a dedupe layer the Court
re-runs the full ECDSA verify *and* appends a fresh audit row for the
replay, polluting the hash chain that SOC/compliance relies on.

The cache keys on ``(org_id, signature_b64u)`` — the proof signature is
the natural idempotency token because it's derived from the old private
key over a canonical envelope (issued_at + new_kid + new_pubkey_pem +
old_kid) that is content-unique per rotation attempt. A hit returns
the original response body verbatim so the client sees an identical
200 on retry.

TTL matches the proof freshness window (600s): proofs older than that
are rejected by ``verify_proof`` regardless, so keeping them in cache
longer would not help a legitimate retry and would just enlarge the
memory footprint.

Concurrency (audit L4-H4)
-------------------------

A naive ``get → verify → store`` sequence has a TOCTOU race: two
concurrent retries with the SAME proof both miss the dedupe ``get``,
both pass the ECDSA verify, both invoke
``activate_staged_and_deprecate_old`` and both append
``admin.mastio_pubkey_rotated`` rows to the per-org audit chain — the
exact pollution this module is supposed to prevent.

``claim_or_wait`` closes the race: under one lock acquisition we either
serve a cached result, or attach to an in-flight ``asyncio.Future`` for
the same key, or install a new Future and become the worker. Worker
runs the verify+commit+audit out of the lock, then sets the Future's
result (cached) or exception (not cached). All concurrent callers with
the same proof signature observe **exactly one** verify+commit+audit;
N-1 losers receive the same successful response or the same rejection
the worker observed. This is the contract the docstring promises to the
audit chain.

TODO(#282): Redis-backed variant when we support HA multi-replica
brokers. The in-process map is fine for the current single-replica
Court topology but would split-brain across replicas (each would
allow one successful rotation, though the Court's single-row
``organizations.mastio_pubkey`` column still converges after the
winner commits). The fix here is per-replica — for cross-replica
atomicity swap to Redis ``SET NX EX`` (mirroring
``RedisDpopJtiStore``).
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


_TTL_SECONDS = 600.0  # matches proof freshness window in mastio_rotation.py


@dataclass(frozen=True)
class _CachedResponse:
    """Response payload snapshot. Stored so a replayed proof returns
    exactly what the first call returned, including ``rotated_at`` —
    a retry that sees a ``rotated_at`` later than its own ``issued_at``
    is valid; a retry that sees a totally different ``new_kid`` would
    be a bug.
    """
    body: dict[str, Any]
    inserted_at: float


class RotateDedupeCache:
    """Process-local (org_id, signature) → response cache + atomic claim.

    Two state maps share one lock:

    - ``_entries``: completed-and-cached responses keyed by
      ``(org_id, signature_b64u)``. Populated only after a successful
      commit + audit so a transient failure does not poison retries.
    - ``_in_progress``: in-flight ``asyncio.Future`` per key. The
      first caller to claim a key installs the Future and becomes the
      worker; concurrent callers attach to the same Future and await
      its result. Cleared as soon as the worker resolves it.

    The lock guards transitions between {absent, in-flight, cached}
    so a caller that drops the lock to await the Future cannot lose a
    race against the worker storing the cached entry.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], _CachedResponse] = {}
        self._in_progress: dict[tuple[str, str], asyncio.Future[dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def get(self, org_id: str, signature_b64u: str) -> dict[str, Any] | None:
        """Return the cached response body for this proof, or None.

        Lazily evicts expired entries when keys are probed — no
        background sweeper required, and a cold cache after a long
        idle period costs nothing.

        Note: this method only inspects the completed-cache map. It
        does NOT participate in the atomic claim protocol — for the
        race-free path use :meth:`claim_or_wait`. ``get`` is retained
        for tests and for callers that want a non-blocking peek.
        """
        key = (org_id, signature_b64u)
        now = time.monotonic()
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if now - entry.inserted_at > _TTL_SECONDS:
                self._entries.pop(key, None)
                return None
            return dict(entry.body)

    async def store(
        self, org_id: str, signature_b64u: str, body: dict[str, Any],
    ) -> None:
        """Record the response for future retries within the TTL.

        Called only after a successful commit + audit — a failed
        rotation must NOT be cached, because a second attempt should
        get a fresh verify pass (the first failure might have been a
        transient rowcount glitch or the DB lock retry loop).
        """
        key = (org_id, signature_b64u)
        async with self._lock:
            self._entries[key] = _CachedResponse(
                body=dict(body), inserted_at=time.monotonic(),
            )

    async def claim_or_wait(
        self,
        org_id: str,
        signature_b64u: str,
        do_work: Callable[[], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        """Atomic claim: at most ONE caller runs ``do_work`` per key.

        Resolves audit L4-H4. The previous ``get → verify → store``
        sequence let two concurrent retries with identical proof both
        miss the cache, both verify, both append to the per-org audit
        chain. Here, under one lock acquisition we observe one of three
        states and act accordingly:

        - **cached**: a previous worker already completed; return a
          fresh copy of the cached body.
        - **in-flight**: another caller is already running ``do_work``;
          attach to its Future and ``await`` outside the lock.
        - **absent**: install a new Future, drop the lock, become the
          worker, run ``do_work``, set the Future's result on success
          or exception on failure. On success, also populate the
          completed-cache so subsequent retries short-circuit.

        Failed work (do_work raises) is propagated to all waiters and
        is NOT cached — matching the existing "transient failure must
        re-verify on retry" contract. Future entry is cleared in either
        case so subsequent retries with a fresh proof are not blocked
        on a stale entry.
        """
        key = (org_id, signature_b64u)
        now = time.monotonic()

        loop = asyncio.get_running_loop()

        async with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                if now - entry.inserted_at <= _TTL_SECONDS:
                    return dict(entry.body)
                # Expired — fall through to re-claim.
                self._entries.pop(key, None)

            in_flight = self._in_progress.get(key)
            if in_flight is not None:
                # Attach as waiter. Drop the lock before awaiting so
                # the worker (or other waiters) can make progress.
                fut = in_flight
                is_worker = False
            else:
                fut = loop.create_future()
                self._in_progress[key] = fut
                is_worker = True

        if not is_worker:
            # Waiters re-raise whatever the worker raised, or get a
            # copy of the worker's result. ``dict(...)`` defensively
            # isolates each waiter from later mutation.
            result = await fut
            return dict(result)

        # Worker path: run ``do_work`` outside the lock so concurrent
        # rotations on *different* keys are not serialized.
        try:
            result = await do_work()
        except BaseException as exc:
            # Publish failure to waiters, clear the in-flight slot so
            # a subsequent retry with the same proof can re-verify
            # (matching the "failed rotations are not cached" rule).
            async with self._lock:
                self._in_progress.pop(key, None)
            if not fut.done():
                fut.set_exception(exc)
                # Mark the exception retrieved so a Future with no
                # waiters does not log "exception was never retrieved"
                # on GC. Awaiters still re-raise via ``await fut``.
                fut.exception()
            raise

        # Success: populate cache and resolve the future under the
        # lock so a waiter that wakes up *after* the in-flight slot
        # is cleared sees the cached entry on its next ``get``.
        async with self._lock:
            self._entries[key] = _CachedResponse(
                body=dict(result), inserted_at=time.monotonic(),
            )
            self._in_progress.pop(key, None)
        if not fut.done():
            fut.set_result(dict(result))
        return dict(result)

    async def reset(self) -> None:
        """Test helper — drop all entries. Not called by production code."""
        async with self._lock:
            self._entries.clear()
            # Cancel any lingering in-flight futures so a botched test
            # does not leave waiters hanging across the next test.
            for fut in self._in_progress.values():
                if not fut.done():
                    fut.cancel()
            self._in_progress.clear()


# Shared module-level cache. One entry per in-flight rotation
# (org_id, signature_b64u); max cardinality is tiny because rotations
# are rate-limited to 5/min/IP × 600s TTL = ~50 entries per org under
# load, so unbounded growth is not a concern.
rotate_dedupe = RotateDedupeCache()
