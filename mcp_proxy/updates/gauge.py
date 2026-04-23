"""Prometheus gauge for the federation update framework.

Mirrors the ``cullis_mastio_rotation_staged`` pattern from PR #288 —
optional ``prometheus_client`` import with a no-op fallback so the
slim ``proxy-init`` container (``demo_network``/``sandbox``) stays
importable without the metrics dependency.

The gauge is a single multi-label series rather than one gauge per
status bucket because pending updates are a small enum and grouping
them lets the dashboard render a stack chart with zero extra config.
"""
from __future__ import annotations


class _NoopLabeledMetric:
    """Stand-in for ``prometheus_client.Gauge`` with the subset of the
    labeled-gauge surface the boot detector uses.
    """

    def labels(self, **_kwargs: object) -> "_NoopLabeledMetric":  # noqa: D401
        return self

    def set(self, _value: float) -> None:  # noqa: D401 — no-op
        return None


try:
    from prometheus_client import Gauge  # type: ignore

    PENDING_UPDATES_TOTAL = Gauge(
        "cullis_pending_updates_total",
        "Federation updates grouped by status bucket "
        "(pending / applied / failed / rolled_back). Non-zero ``pending`` "
        "means admin attention is required via the dashboard — resolve "
        "through POST /admin/updates/{id}/apply (endpoint lands in PR 4).",
        labelnames=["status"],
    )
except ImportError:  # pragma: no cover — exercised only in slim envs
    PENDING_UPDATES_TOTAL = _NoopLabeledMetric()  # type: ignore[assignment]
