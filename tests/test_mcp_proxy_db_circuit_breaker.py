"""Tests for the DB latency circuit breaker middleware — ADR-013
layer 6.

Covers:
- ``CircuitBreakerState`` hysteresis (asymmetric activation/deactivation)
- Shed fraction lerp at the interesting boundaries
- Per-request shedding with an injected deterministic RNG
- Fail-open when the tracker has no ready p99 (warmup)
- Observability path bypass
- Shed record emitted as JSON WARNING on stderr

The ``DbLatencyTracker`` dependency is replaced with a tiny fake so
the tests don't need a live async DB engine — we're testing the
decision logic, not the tracker (that has its own test file).
"""
from __future__ import annotations

import json
import random

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.middleware.db_latency_circuit_breaker import (
    CircuitBreakerState,
    DbLatencyCircuitBreakerMiddleware,
)


class _FakeTracker:
    """Stub that returns whatever p99 the test sets."""
    def __init__(self, p99: float | None = None) -> None:
        self.p99 = p99
    def p99_ms(self):
        # (probe, passive, effective) — only effective matters for the middleware
        return (self.p99, self.p99, self.p99)


# ── State hysteresis ────────────────────────────────────────────────

def test_state_rejects_deactivation_above_activation():
    with pytest.raises(ValueError):
        CircuitBreakerState(activation_ms=300, deactivation_ms=400)


def test_state_hysteresis_entry_requires_crossing_activation():
    s = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    assert s.is_shedding is False
    s.update_state(499)
    assert s.is_shedding is False    # below activation, stays closed
    s.update_state(500)
    assert s.is_shedding is False    # AT activation, not strictly above, stays closed
    s.update_state(501)
    assert s.is_shedding is True     # strictly above activation, opens


def test_state_hysteresis_exit_requires_crossing_deactivation():
    s = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    s.update_state(600)              # enter shedding
    assert s.is_shedding is True

    s.update_state(400)              # in between, must stay shedding
    assert s.is_shedding is True
    s.update_state(350)              # at deactivation, not strictly below
    assert s.is_shedding is True
    s.update_state(349)              # strictly below, exits
    assert s.is_shedding is False


def test_state_shed_fraction_boundaries():
    s = CircuitBreakerState(
        activation_ms=500, deactivation_ms=350, max_shed_fraction=0.95,
    )
    # At activation → entry fraction (10%).
    assert abs(s.shed_fraction(500) - 0.10) < 1e-9
    # At saturation (3× activation) → max fraction.
    assert abs(s.shed_fraction(1500) - 0.95) < 1e-9
    # Above saturation → clamped to max.
    assert abs(s.shed_fraction(5000) - 0.95) < 1e-9
    # Halfway through the lerp.
    mid = s.shed_fraction(1000)  # (1000-500)/(1500-500) = 0.5
    assert abs(mid - (0.10 + 0.5 * (0.95 - 0.10))) < 1e-9


def test_state_shed_count_last_60s_trims():
    s = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    for _ in range(5):
        s.record_shed()
    assert s.shed_count_last_60s() == 5
    assert s.shed_total == 5


# ── Middleware integration ──────────────────────────────────────────

def _build_app(tracker: _FakeTracker, state: CircuitBreakerState,
               rng: random.Random | None = None) -> FastAPI:
    app = FastAPI()
    app.add_middleware(DbLatencyCircuitBreakerMiddleware, rng=rng)
    # Wire via app.state the way the lifespan does in main.py.
    app.state.db_latency_tracker = tracker
    app.state.db_latency_cb_state = state

    @app.get("/v1/egress/peers")
    async def peers():
        return {"peers": []}

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/metrics")
    async def metrics():
        return "# metrics\n"

    @app.get("/.well-known/jwks-local.json")
    async def jwks():
        return {"keys": []}

    return app


def test_middleware_fail_open_when_tracker_not_ready():
    tracker = _FakeTracker(p99=None)
    state = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    app = _build_app(tracker, state)
    with TestClient(app) as client:
        # All requests pass through even with breaker configured —
        # warmup window must not drop traffic.
        for _ in range(5):
            r = client.get("/v1/egress/peers")
            assert r.status_code == 200
    assert state.shed_total == 0


def test_middleware_passes_through_when_below_activation():
    tracker = _FakeTracker(p99=100.0)   # well below 500 ms activation
    state = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    app = _build_app(tracker, state)
    with TestClient(app) as client:
        for _ in range(5):
            r = client.get("/v1/egress/peers")
            assert r.status_code == 200
    assert state.is_shedding is False
    assert state.shed_total == 0


def test_middleware_sheds_with_deterministic_rng():
    """With a fixed-seed RNG we can assert exact shed/pass counts for
    a known fraction. At p99 = 1500 ms the fraction is max (0.95).
    """
    tracker = _FakeTracker(p99=1500.0)
    state = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    rng = random.Random(42)
    app = _build_app(tracker, state, rng=rng)

    # Pre-simulate what the middleware's random.random() will return
    # so we can predict outcomes. Seed 42, first 20 samples:
    expected = []
    _rng = random.Random(42)
    for _ in range(20):
        expected.append(_rng.random() < 0.95)

    with TestClient(app) as client:
        outcomes = []
        for _ in range(20):
            r = client.get("/v1/egress/peers")
            outcomes.append(r.status_code == 503)

    assert outcomes == expected
    assert state.is_shedding is True
    assert state.shed_total == sum(outcomes)


def test_middleware_shed_response_headers_and_body():
    tracker = _FakeTracker(p99=1500.0)
    state = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    # Force a shed with an always-below RNG.
    always_shed_rng = random.Random()
    always_shed_rng.random = lambda: 0.0  # type: ignore[assignment]
    app = _build_app(tracker, state, rng=always_shed_rng)

    with TestClient(app) as client:
        r = client.get("/v1/egress/peers")

    assert r.status_code == 503
    assert r.headers.get("Retry-After") == "5"
    assert r.headers.get("X-Cullis-Shed-Reason") == "db_latency_circuit_breaker"
    body = r.json()
    assert body["error"] == "db_latency_circuit_breaker_open"


def test_middleware_bypasses_observability_paths_even_when_shedding():
    tracker = _FakeTracker(p99=5000.0)   # max shed fraction
    state = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    always_shed_rng = random.Random()
    always_shed_rng.random = lambda: 0.0  # type: ignore[assignment]
    app = _build_app(tracker, state, rng=always_shed_rng)

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/metrics").status_code == 200
        assert client.get("/.well-known/jwks-local.json").status_code == 200


def test_middleware_emits_shed_json_on_stderr(capsys):
    """Same pattern as the global rate limit test — the mcp_proxy
    logger is muted inside ASGI dispatch, the middleware writes
    WARNING records directly to stderr. capsys captures that output
    and parses each line as JSON.
    """
    tracker = _FakeTracker(p99=1500.0)
    state = CircuitBreakerState(activation_ms=500, deactivation_ms=350)
    always_shed_rng = random.Random()
    always_shed_rng.random = lambda: 0.0  # type: ignore[assignment]
    app = _build_app(tracker, state, rng=always_shed_rng)

    with TestClient(app) as client:
        for _ in range(3):
            r = client.get("/v1/egress/peers")
            assert r.status_code == 503

    captured = capsys.readouterr().err
    shed_lines = [
        line for line in captured.splitlines()
        if "db latency circuit breaker shed" in line
    ]
    assert len(shed_lines) == 3, (
        f"expected 3 WARNING records on stderr, got {len(shed_lines)}:\n{captured!r}"
    )
    for line in shed_lines:
        record = json.loads(line)
        assert record["level"] == "WARNING"
        assert record["logger"] == "mcp_proxy"
        assert "timestamp" in record
        assert "path=/v1/egress/peers" in record["message"]
        assert "p99_ms=" in record["message"]
