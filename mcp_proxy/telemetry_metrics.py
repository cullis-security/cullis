"""Prometheus-compatible metrics with a no-op fallback when
``prometheus_client`` is not installed.

The mcp_proxy package does not declare ``prometheus_client`` as a
dependency today — the broker (``app/``) does, and operators who want
metrics can co-install it. The no-op shim keeps the proxy importable
in minimal environments (standalone ``proxy-init`` container, CI unit
tests) without carrying the dependency weight.

Metrics defined here surface operator-visible state that can't be
derived from logs alone — e.g. a staged rotation row whose presence
means the local issuer is sign-halted.
"""
from __future__ import annotations


class _NoopMetric:
    """Minimal stand-in with the subset of the ``prometheus_client``
    gauge/counter/histogram surface the proxy actually uses.
    """

    def set(self, _value: float) -> None:  # noqa: D401 — no-op
        return None

    def inc(self, _amount: float = 1.0) -> None:  # noqa: D401 — no-op
        return None

    def dec(self, _amount: float = 1.0) -> None:  # noqa: D401 — no-op
        return None

    def observe(self, _value: float) -> None:  # noqa: D401 — no-op
        return None

    def labels(self, **_kwargs) -> "_NoopMetric":  # noqa: D401 — no-op
        return self


try:
    from prometheus_client import Counter, Gauge, Histogram  # type: ignore

    MASTIO_ROTATION_STAGED = Gauge(
        "cullis_mastio_rotation_staged",
        "1 when a staged mastio-key rotation row is present (sign-halt), "
        "0 otherwise. Non-zero means admin intervention is required via "
        "POST /proxy/mastio-key/complete-staged.",
    )
    LEGACY_CA_PATHLEN_ZERO = Gauge(
        "cullis_proxy_legacy_ca_pathlen_zero",
        "1 when the proxy booted with an Org CA that has pathLen=0 and "
        "therefore cannot accommodate the Mastio intermediate CA without "
        "breaking RFC 5280 §4.2.1.9. Remediation: POST /pki/rotate-ca. "
        "See issues #280 and #285.",
    )

    # ADR-032 F6 — MDM polling visibility. ``cullis_mdm_poll_total``
    # carries result="success"/"failure" so an operator can distinguish
    # a quiet tenant from a broken integration; failure-only is the
    # signal that powers the circuit breaker. ``cullis_mdm_circuit_state``
    # gauges the breaker so dashboards can colour-code the polling
    # health without scraping logs.
    MDM_POLL_TOTAL = Counter(
        "cullis_mdm_poll_total",
        "MDM polling cycles, labelled by result.",
        labelnames=("mdm", "result"),
    )
    MDM_POLL_DURATION = Histogram(
        "cullis_mdm_poll_duration_seconds",
        "Wall-clock duration of a single MDM polling cycle.",
        labelnames=("mdm",),
    )
    MDM_CIRCUIT_STATE = Gauge(
        "cullis_mdm_circuit_state",
        "MDM polling circuit-breaker state: 0=closed, 1=half_open, 2=open.",
        labelnames=("mdm",),
    )
    MDM_DEVICES_SEEN = Counter(
        "cullis_mdm_devices_seen_total",
        "Number of device rows upserted per polling cycle.",
        labelnames=("mdm",),
    )
    ATTESTATION_REVOCATIONS = Counter(
        "cullis_attestation_revocations_total",
        "Agent cert revocations triggered by attestation events.",
        labelnames=("mdm", "reason"),
    )
    ATTESTATION_STALE_EVENTS = Counter(
        "cullis_attestation_stale_events_total",
        "Stale-window transitions emitted by the watcher daemon.",
        labelnames=("mdm",),
    )
except ImportError:  # pragma: no cover — exercised only in slim envs
    MASTIO_ROTATION_STAGED = _NoopMetric()  # type: ignore[assignment]
    LEGACY_CA_PATHLEN_ZERO = _NoopMetric()  # type: ignore[assignment]
    MDM_POLL_TOTAL = _NoopMetric()  # type: ignore[assignment]
    MDM_POLL_DURATION = _NoopMetric()  # type: ignore[assignment]
    MDM_CIRCUIT_STATE = _NoopMetric()  # type: ignore[assignment]
    MDM_DEVICES_SEEN = _NoopMetric()  # type: ignore[assignment]
    ATTESTATION_REVOCATIONS = _NoopMetric()  # type: ignore[assignment]
    ATTESTATION_STALE_EVENTS = _NoopMetric()  # type: ignore[assignment]
