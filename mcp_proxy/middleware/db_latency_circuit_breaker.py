"""DB latency circuit breaker — ADR-013 layer 6.

Sheds a fraction of incoming requests with 503 when the DB latency
signal (from ``mcp_proxy.observability.db_latency.DbLatencyTracker``)
sits above the activation threshold. Goal: keep the Mastio responsive
as the DB recovers, rather than piling every new request onto a
saturated pool where they compete for connections that never come.

Key design choices, each addressing a failure mode we thought about:

- **Pure ASGI middleware**, same reason as the global rate limit
  (PR #306 / #307): ``__call__`` runs in the request's own task, no
  BaseHTTPMiddleware wrapper task, stderr-direct log emit survives
  the uvicorn logger mute issue.

- **Shed is pre-state**: the decision happens before the auth dep
  and before any handler touches the DB, the session store, the
  DPoP nonce cache, etc. A shed 503 never consumes server-side state
  the client would have to reconcile on retry.

- **Hysteresis** with asymmetric thresholds (500 ms activation /
  350 ms deactivation): without it, a p99 oscillating around 500 ms
  ± jitter would flap the shed fraction between 0 and 10 %,
  producing random 503s when the system is actually fine. Two
  thresholds = one extra line, eliminates the flap. Inside the
  shedding state the fraction itself lerps from 10 % at activation
  up to ``max_shed_fraction`` (default 0.95) at 3× the activation
  threshold. 0.95 and not 1.0 on purpose: a small trickle of traffic
  still reaches handlers under full shed, so the operator can tell
  "breaker active, DB recovering" from "breaker active, DB dead"
  from the traffic alone without having to read the latency probe
  separately.

- **Fail-open on warmup**: if the tracker hasn't collected enough
  samples yet (first few seconds after boot, or if something broke
  the probe + passive sampler together), the middleware falls
  through to pass-through. Phase 1 (DB pool cap) and Phase 2 (global
  bucket) continue to protect; silently dropping every request
  during warmup is the wrong default.

- **Bypass observability paths**: /health, /metrics, /.well-known/
  never shed. Same reasoning as the global rate limit — an operator
  trying to diagnose a slow DB needs /health and /metrics to answer.

- **Shed-aware emit**: every shed writes a JSON WARNING record
  directly to stderr in the ``JSONFormatter`` shape, bypassing the
  Python logger for the same reason documented in
  ``global_rate_limit.py``.
"""
from __future__ import annotations

import json
import random
import sys
import time
from collections import deque
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_proxy.observability.db_latency import DbLatencyTracker


_BYPASS_PREFIXES: tuple[str, ...] = (
    "/health",
    "/metrics",
    "/.well-known/",
)

_SHED_BODY = json.dumps({
    "detail": "DB latency high — circuit breaker shedding, retry shortly",
    "error": "db_latency_circuit_breaker_open",
}).encode()

_SHED_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-type", b"application/json"),
    (b"content-length", str(len(_SHED_BODY)).encode()),
    (b"retry-after", b"5"),
    (b"x-cullis-shed-reason", b"db_latency_circuit_breaker"),
]

# 95th-percentile samples retained for the "last 60 s" counter. 60 s
# at typical shed rates stays well under a few thousand entries.
_SHED_WINDOW_S: float = 60.0

# Minimum shed fraction the moment the breaker enters the shedding
# state — enough to relieve the DB immediately without a cold-start
# behaviour that looks indistinguishable from ``not shedding``.
_ENTRY_SHED_FRACTION: float = 0.10

# Above this multiple of the activation threshold the lerp saturates.
# Chosen so a well-saturated system (p99 at 3× target) is held at
# ``max_shed_fraction`` rather than overshooting to 100 %.
_SATURATION_MULTIPLIER: float = 3.0


def _emit_shed_log(path: str, method: str, p99_ms: float, fraction: float,
                   shed_total: int) -> None:
    """Write a WARNING record straight to stderr, matching the JSON
    shape of ``mcp_proxy.logging_setup.JSONFormatter``. The
    ``mcp_proxy`` logger is muted inside the ASGI dispatch path at
    runtime — see global_rate_limit.py for the full story."""
    record = json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "WARNING",
        "logger": "mcp_proxy",
        "message": (
            f"db latency circuit breaker shed: path={path} method={method} "
            f"p99_ms={p99_ms:.0f} shed_fraction={fraction:.2f} "
            f"total_shed={shed_total}"
        ),
    }, default=str)
    print(record, file=sys.stderr, flush=True)


class CircuitBreakerState:
    """Shed bookkeeping for the middleware. Injected into the
    middleware at construction and exposed via ``app.state`` so the
    admin observability endpoint can read counters + state without
    walking the middleware stack.
    """

    def __init__(
        self,
        *,
        activation_ms: float = 500.0,
        deactivation_ms: float = 350.0,
        max_shed_fraction: float = 0.95,
    ) -> None:
        if deactivation_ms >= activation_ms:
            raise ValueError(
                f"deactivation_ms ({deactivation_ms}) must be below "
                f"activation_ms ({activation_ms}) — asymmetric thresholds "
                f"are the whole point of the hysteresis"
            )
        if not 0.0 < max_shed_fraction <= 1.0:
            raise ValueError(
                f"max_shed_fraction must be in (0, 1], got {max_shed_fraction}"
            )
        self.activation_ms = activation_ms
        self.deactivation_ms = deactivation_ms
        self.max_shed_fraction = max_shed_fraction
        self.is_shedding: bool = False
        self.shed_total: int = 0
        self._shed_timestamps: deque[float] = deque()

    def update_state(self, p99_ms: float) -> None:
        """Apply hysteresis to the latency signal."""
        if self.is_shedding:
            if p99_ms < self.deactivation_ms:
                self.is_shedding = False
        else:
            if p99_ms > self.activation_ms:
                self.is_shedding = True

    def shed_fraction(self, p99_ms: float) -> float:
        """Linear lerp between activation threshold and saturation.

        Called only while ``is_shedding`` is True — outside that state
        the middleware bypasses this path entirely.
        """
        if p99_ms <= self.activation_ms:
            return _ENTRY_SHED_FRACTION
        saturation_ms = self.activation_ms * _SATURATION_MULTIPLIER
        if p99_ms >= saturation_ms:
            return self.max_shed_fraction
        ratio = (p99_ms - self.activation_ms) / (saturation_ms - self.activation_ms)
        return _ENTRY_SHED_FRACTION + ratio * (
            self.max_shed_fraction - _ENTRY_SHED_FRACTION
        )

    def record_shed(self) -> None:
        self.shed_total += 1
        self._shed_timestamps.append(time.monotonic())
        self._trim_window()

    def shed_count_last_60s(self) -> int:
        self._trim_window()
        return len(self._shed_timestamps)

    def _trim_window(self) -> None:
        cutoff = time.monotonic() - _SHED_WINDOW_S
        while self._shed_timestamps and self._shed_timestamps[0] < cutoff:
            self._shed_timestamps.popleft()


class DbLatencyCircuitBreakerMiddleware:
    """Pure ASGI middleware that sheds when DB p99 sits above threshold.

    Reads the ``DbLatencyTracker`` and ``CircuitBreakerState`` from
    ``scope["app"].state`` at request time rather than taking them as
    constructor arguments. Reason: ``app.add_middleware`` runs at
    module import, but the tracker needs a live DB engine and is
    created inside the lifespan — the state-lookup pattern lets the
    middleware be registered early and picked up later once the
    lifespan has wired ``app.state.db_latency_tracker`` and
    ``app.state.db_latency_cb_state``. When either attribute is
    missing (warmup, standalone test harness) the middleware
    pass-through-s: fail-open.
    """

    def __init__(
        self,
        app,
        bypass_prefixes: tuple[str, ...] = _BYPASS_PREFIXES,
        rng: "random.Random | None" = None,
    ) -> None:
        self.app = app
        self._bypass_prefixes = bypass_prefixes
        # Injectable RNG so tests can run with a deterministic seed
        # when they need exact shed/pass counts per fraction.
        self._rng = rng or random

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(p) for p in self._bypass_prefixes):
            await self.app(scope, receive, send)
            return

        app_state = scope["app"].state
        tracker = getattr(app_state, "db_latency_tracker", None)
        state = getattr(app_state, "db_latency_cb_state", None)
        if tracker is None or state is None:
            # Lifespan hasn't wired us yet (or the standalone test
            # harness omitted the tracker on purpose): fail-open.
            await self.app(scope, receive, send)
            return

        _, _, p99 = tracker.p99_ms()
        if p99 is None:
            # Warmup or both sources quiet: fail-open. Phase 1/2/6 all
            # cooperate — the global bucket + DB pool cap still protect
            # us while the tracker scales its sample window.
            await self.app(scope, receive, send)
            return

        state.update_state(p99)
        if not state.is_shedding:
            await self.app(scope, receive, send)
            return

        fraction = state.shed_fraction(p99)
        if self._rng.random() >= fraction:
            # Pass-through within the shedding state — keeps a trickle
            # of real traffic flowing so operators can tell recovering
            # from dead at a glance, and so the passive sampler has
            # something to measure as the DB returns.
            await self.app(scope, receive, send)
            return

        state.record_shed()
        method = scope.get("method", "?")
        _emit_shed_log(path, method, p99, fraction, state.shed_total)
        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": _SHED_HEADERS,
        })
        await send({
            "type": "http.response.body",
            "body": _SHED_BODY,
        })
