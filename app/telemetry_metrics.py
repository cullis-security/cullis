"""
Business metrics — counters and histograms for the ATN broker.

All instruments are created from the shared meter. When OTel is disabled,
these are no-op instruments (safe to call .add() / .record()).
"""
from app.telemetry import meter

# ── Counters ──────────────────────────────────────────────────────────────────
AUTH_SUCCESS_COUNTER = meter.create_counter(
    name="atn.auth.success",
    description="Successful token issuances",
    unit="1",
)
AUTH_DENY_COUNTER = meter.create_counter(
    name="atn.auth.deny",
    description="Denied token requests",
    unit="1",
)
SESSION_CREATED_COUNTER = meter.create_counter(
    name="atn.session.created",
    description="Sessions successfully created",
    unit="1",
)
SESSION_DENIED_COUNTER = meter.create_counter(
    name="atn.session.denied",
    description="Session requests denied",
    unit="1",
)
POLICY_ALLOW_COUNTER = meter.create_counter(
    name="atn.policy.allow",
    description="Policy evaluations resulting in allow",
    unit="1",
)
POLICY_DENY_COUNTER = meter.create_counter(
    name="atn.policy.deny",
    description="Policy evaluations resulting in deny",
    unit="1",
)
RATE_LIMIT_REJECT_COUNTER = meter.create_counter(
    name="atn.ratelimit.reject",
    description="Requests rejected by rate limiter",
    unit="1",
)

# ── Histograms ────────────────────────────────────────────────────────────────
AUTH_DURATION_HISTOGRAM = meter.create_histogram(
    name="atn.auth.duration",
    description="Full auth token issuance duration",
    unit="ms",
)
X509_VERIFY_DURATION_HISTOGRAM = meter.create_histogram(
    name="atn.x509.verify_duration",
    description="x509 chain verification duration",
    unit="ms",
)
PDP_WEBHOOK_LATENCY_HISTOGRAM = meter.create_histogram(
    name="atn.pdp_webhook.latency",
    description="PDP webhook call latency",
    unit="ms",
)
