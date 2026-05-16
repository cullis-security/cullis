"""Three-state circuit breaker for the MDM polling loop (ADR-032 F6).

Sits ABOVE the F2 exponential backoff. The backoff handles the
ordinary case (one Graph 429, one transient TLS hiccup): retry with
30s, 60s, 120s, 300s, 300s. The circuit breaker handles the
pathological case: the integration is broken (tenant rotated the
secret, admin consent revoked, network partition) and continued
polling at the backoff cadence is wasted work + adds noise to the
audit chain.

State machine (RFC 1457 it is not — just the three states everyone
actually uses):

* ``CLOSED``  — normal polling cadence. Every success keeps the
  failure counter at zero.
* ``OPEN``    — too many consecutive failures. The loop sleeps for
  the cooldown window without calling Graph; one audit row of action
  ``mdm_polling_degraded`` was emitted on the CLOSED->OPEN transition.
* ``HALF_OPEN`` — cooldown elapsed. The next poll is a single probe.
  Success closes the circuit; failure re-opens for another cooldown.

Thresholds + cooldown are operator-tunable via
``MCP_PROXY_MDM_CIRCUIT_BREAKER_*`` env vars (Phase 1: hard-coded
defaults are fine; the config surface lands when we wire Jamf / WS1
and need per-MDM tuning).
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from mcp_proxy.telemetry_metrics import MDM_CIRCUIT_STATE

_log = logging.getLogger("mcp_proxy.mdm.circuit_breaker")

STATE_CLOSED = "closed"
STATE_OPEN = "open"
STATE_HALF_OPEN = "half_open"

_STATE_TO_GAUGE_VALUE = {
    STATE_CLOSED: 0,
    STATE_HALF_OPEN: 1,
    STATE_OPEN: 2,
}


@dataclass
class CircuitBreakerConfig:
    """Operator-tunable thresholds. Defaults locked by Decision F."""

    # Number of consecutive failures that flip CLOSED -> OPEN. 5 is
    # chosen so a single Graph throttle storm (~3 transient 429s within
    # a few minutes) does not trip the breaker, while a sustained
    # outage does within ~10 minutes at the default poll interval.
    failure_threshold: int = 5
    # Cooldown window before HALF_OPEN. 30 minutes matches the
    # ADR-032 "5-15 minute MDM freshness" reasoning: by the time we
    # come back, the customer has either fixed the integration or the
    # outage is genuinely sustained and we should not be burning
    # polling cycles against it.
    cooldown_seconds: int = 1800


@dataclass
class CircuitBreaker:
    """In-memory three-state breaker scoped to one MDM integration."""

    mdm: str
    config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    state: str = STATE_CLOSED
    consecutive_failures: int = 0
    opened_at_monotonic: float | None = None

    def _set_state(self, new_state: str) -> None:
        if self.state == new_state:
            return
        _log.info(
            "MDM circuit breaker (%s): %s -> %s "
            "(consecutive_failures=%d)",
            self.mdm, self.state, new_state, self.consecutive_failures,
        )
        self.state = new_state
        MDM_CIRCUIT_STATE.labels(mdm=self.mdm).set(
            _STATE_TO_GAUGE_VALUE[new_state]
        )

    def cooldown_remaining_seconds(self) -> float:
        """Return remaining cooldown if OPEN, else 0.

        Uses ``time.monotonic`` so the timer survives wall-clock
        adjustments (DST, NTP step). The cooldown is short enough
        relative to typical clock drift that a few seconds either way
        doesn't matter.
        """
        if self.state != STATE_OPEN or self.opened_at_monotonic is None:
            return 0.0
        elapsed = time.monotonic() - self.opened_at_monotonic
        remaining = max(0.0, self.config.cooldown_seconds - elapsed)
        return remaining

    def should_poll(self) -> bool:
        """True when the loop should attempt a poll this tick.

        OPEN returns False until the cooldown elapses; the caller
        flips the state to HALF_OPEN right before attempting the
        probe so a concurrent reader sees the transition.
        """
        if self.state == STATE_CLOSED:
            return True
        if self.state == STATE_HALF_OPEN:
            return True
        if self.cooldown_remaining_seconds() <= 0:
            self._set_state(STATE_HALF_OPEN)
            return True
        return False

    def record_success(self) -> None:
        """Reset failure counter + close the circuit."""
        self.consecutive_failures = 0
        self.opened_at_monotonic = None
        self._set_state(STATE_CLOSED)

    def record_failure(self) -> bool:
        """Increment failure counter; return ``True`` on CLOSED->OPEN edge.

        The edge bool drives the one-shot audit emission upstream — the
        breaker itself does not touch the audit chain so this module
        stays unit-testable without DB plumbing.
        """
        self.consecutive_failures += 1

        if self.state == STATE_HALF_OPEN:
            # Probe failed — back to OPEN, but no new edge audit (we
            # already audited the original CLOSED->OPEN).
            self.opened_at_monotonic = time.monotonic()
            self._set_state(STATE_OPEN)
            return False

        if (
            self.state == STATE_CLOSED
            and self.consecutive_failures >= self.config.failure_threshold
        ):
            self.opened_at_monotonic = time.monotonic()
            self._set_state(STATE_OPEN)
            return True

        return False


async def sleep_until_cooldown_done(
    breaker: CircuitBreaker, stop_event: asyncio.Event,
) -> None:
    """Wait for the OPEN cooldown without busy-looping.

    Returns early if ``stop_event`` fires so a shutdown does not have
    to wait the full 30 minutes. Caller still owns the post-cooldown
    state flip via :meth:`CircuitBreaker.should_poll`.
    """
    remaining = breaker.cooldown_remaining_seconds()
    if remaining <= 0:
        return
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=remaining)
    except asyncio.TimeoutError:
        pass
