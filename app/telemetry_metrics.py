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

# ── M1 Session Reliability Layer ─────────────────────────────────────────────
SESSION_CLOSED_COUNTER = meter.create_counter(
    name="atn.session.closed",
    description="Sessions closed, tagged with the reason",
    unit="1",
)
SESSION_CAP_REJECTED_COUNTER = meter.create_counter(
    name="atn.session.cap_rejected",
    description="Session creations rejected due to per-agent ACTIVE cap",
    unit="1",
)
SESSION_SWEEPER_CYCLES_COUNTER = meter.create_counter(
    name="atn.session.sweeper_cycles",
    description="Sweeper cycles executed",
    unit="1",
)
SESSION_SWEEPER_CLOSED_COUNTER = meter.create_counter(
    name="atn.session.sweeper_closed",
    description="Sessions closed by the sweeper, tagged with reason",
    unit="1",
)

# ── M2 Heartbeat + Resume ────────────────────────────────────────────────────
WS_PING_SENT_COUNTER = meter.create_counter(
    name="atn.ws.ping_sent",
    description="Server-initiated WebSocket pings",
    unit="1",
)
WS_PONG_TIMEOUT_COUNTER = meter.create_counter(
    name="atn.ws.pong_timeout",
    description="WebSocket connections closed due to pong timeout",
    unit="1",
)
WS_RESUME_COUNTER = meter.create_counter(
    name="atn.ws.resume",
    description="Session resume requests received via WS",
    unit="1",
)
WS_RESUME_MESSAGES_DELIVERED_COUNTER = meter.create_counter(
    name="atn.ws.resume_messages_delivered",
    description="Messages replayed on resume",
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

# ── Security signal counters ─────────────────────────────────────────────────
# These metrics drive the Prometheus alert rules in
# enterprise-kit/monitoring/cullis-alerts.yml. Every increment is a potential
# attack signal — incidents start with one of these going non-zero.

CERT_PINNING_MISMATCH_COUNTER = meter.create_counter(
    name="atn.cert_pinning.mismatch",
    description=(
        "Login attempts where the presented x509 cert thumbprint differs "
        "from the pinned thumbprint. Non-zero = possible compromise or "
        "uncoordinated cert rotation."
    ),
    unit="1",
)
AUDIT_CHAIN_VERIFY_FAILED_COUNTER = meter.create_counter(
    name="atn.audit_chain.verify_failed",
    description=(
        "Audit log hash chain verification failures. Non-zero = tampering "
        "with the append-only audit log."
    ),
    unit="1",
)
DPOP_JTI_REPLAY_COUNTER = meter.create_counter(
    name="atn.dpop.jti_replay_attempt",
    description="DPoP proof replay attempts (JTI already seen).",
    unit="1",
)
REVOKED_TOKEN_USE_COUNTER = meter.create_counter(
    name="atn.revoked_token.use_attempt",
    description="Attempts to use a revoked JWT access token.",
    unit="1",
)
KMS_SEAL_STATUS_COUNTER = meter.create_counter(
    name="atn.kms.seal_check_failed",
    description=(
        "KMS/Vault seal-check failures (sealed or unreachable). The broker "
        "remains operational via cached keys but cannot rotate or write new "
        "secrets."
    ),
    unit="1",
)
POLICY_DUAL_ORG_MISMATCH_COUNTER = meter.create_counter(
    name="atn.policy.dual_org_mismatch",
    description=(
        "Sessions where one org's PDP allowed and the other denied. Signals "
        "policy desynchronization between federated organizations."
    ),
    unit="1",
)
MESSAGE_QUEUED_COUNTER = meter.create_counter(
    name="atn.message.queued",
    description="Messages enqueued because the recipient was not connected (M3).",
    unit="1",
)
MESSAGE_QUEUE_DEDUPED_COUNTER = meter.create_counter(
    name="atn.message.queue_deduped",
    description="Enqueue attempts collapsed by idempotency key (M3).",
    unit="1",
)
WS_QUEUE_DRAINED_COUNTER = meter.create_counter(
    name="atn.ws.queue_drained",
    description="Messages pushed to a client via queue-drain on WS connect/resume (M3).",
    unit="1",
)
