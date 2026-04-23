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
    gauge/counter surface the proxy actually uses.
    """

    def set(self, _value: float) -> None:  # noqa: D401 — no-op
        return None

    def inc(self, _amount: float = 1.0) -> None:  # noqa: D401 — no-op
        return None

    def dec(self, _amount: float = 1.0) -> None:  # noqa: D401 — no-op
        return None


try:
    from prometheus_client import Gauge  # type: ignore

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
except ImportError:  # pragma: no cover — exercised only in slim envs
    MASTIO_ROTATION_STAGED = _NoopMetric()  # type: ignore[assignment]
    LEGACY_CA_PATHLEN_ZERO = _NoopMetric()  # type: ignore[assignment]
