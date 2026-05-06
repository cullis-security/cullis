"""
MCP Proxy — SQLAlchemy table definitions.

Schema lives here, CRUD stays in db.py. Metadata is separate from the broker's
Base (app/db/database.py) on purpose: proxy and broker can diverge freely,
no accidental cross-imports.

Tables grouped in two families:
  - Legacy (Phase 0): internal_agents, audit_log, proxy_config. Already
    populated on live deployments.
  - Local-* (Phase 1 ADR-001): local_sessions, local_messages,
    local_policies, local_audit. Created empty here; wiring lands Phase 4.
    ``local_agents`` was dropped in ADR-010 Phase 6b — ``internal_agents``
    is now the sole Mastio-authoritative registry.

Column types picked to render identically on SQLite and PostgreSQL. Integer
primary keys use plain Integer + primary_key=True — SQLAlchemy picks SERIAL
on Postgres and INTEGER on SQLite.
"""
from sqlalchemy import (
    CheckConstraint,
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base

metadata = MetaData()
Base = declarative_base(metadata=metadata)


# ── Legacy tables (schema frozen by migration 0001) ──────────────────────────


class InternalAgent(Base):
    __tablename__ = "internal_agents"

    agent_id = Column(Text, primary_key=True)
    display_name = Column(Text, nullable=False)
    capabilities = Column(Text, nullable=False, server_default="[]")  # JSON array
    cert_pem = Column(Text, nullable=True)
    created_at = Column(Text, nullable=False)
    is_active = Column(Integer, nullable=False, server_default="1")
    # Free-form JSON carried from pending_enrollments.device_info on approval
    # (OS, hostname, Connector version). Null for agents created via CLI.
    device_info = Column(Text, nullable=True)
    # F-B-11 Phase 2 (#181) — RFC 7638 JWK thumbprint of the agent's DPoP
    # keypair. NULL during the Phase 2–6 grace period; populated by the
    # Phase 3 enrollment flow and checked by
    # ``mcp_proxy.auth.dpop_api_key.get_agent_from_dpop_api_key`` when
    # ``CULLIS_EGRESS_DPOP_MODE`` is ``optional`` or ``required``.
    dpop_jkt = Column(Text, nullable=True)
    # ADR-011 Phase 1 — enrollment metadata. ``enrollment_method`` is one of
    # ``admin`` / ``connector`` / ``byoca`` / ``spiffe`` and records how the
    # agent authenticated at enrollment time. ``spiffe_id`` is populated when
    # the Mastio received a SPIFFE SVID (either at enrollment or via a future
    # SPIRE-attached deployment). ``enrolled_at`` is separate from
    # ``created_at`` so an admin can create a placeholder row and complete
    # enrollment later; on backfill of existing rows we set
    # ``enrolled_at = created_at``.
    enrollment_method = Column(Text, nullable=True)
    spiffe_id = Column(Text, nullable=True)
    enrolled_at = Column(Text, nullable=True)
    # Migration 0017 — reach classifies who an agent is allowed to talk
    # to: ``intra`` (same-org only), ``cross`` (other orgs only),
    # ``both``. Legacy rows backfill to ``intra`` when federated=0 or
    # ``both`` when federated=1 (see the migration for the CASE).
    # Nullable=False + default ``both`` keeps the permissive shape for
    # rows written during the grace period before enforcement lands.
    reach = Column(String, nullable=False, server_default="both")


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Text, nullable=False)
    agent_id = Column(Text, nullable=False)
    action = Column(Text, nullable=False)
    tool_name = Column(Text, nullable=True)
    status = Column(Text, nullable=False)
    detail = Column(Text, nullable=True)
    request_id = Column(Text, nullable=True)
    duration_ms = Column(String, nullable=True)  # REAL in SQLite — stored as text-safe numeric
    # H4 lane7 audit fix — forward-integrity hash chain. ``chain_seq``
    # is monotonically increasing per Mastio, ``prev_hash`` is the
    # previous row's ``row_hash`` (or ``"genesis"`` for the first
    # chained row), and ``row_hash`` is SHA-256 over a canonical
    # encoding of every authoritative field. Pre-migration rows leave
    # the columns NULL; verify_audit_chain() skips them.
    chain_seq = Column(Integer, nullable=True)
    prev_hash = Column(Text, nullable=True)
    row_hash = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_audit_log_agent_id", "agent_id"),
        Index("idx_audit_log_timestamp", "timestamp"),
        Index("idx_audit_log_request_id", "request_id"),
        Index("idx_audit_log_chain_seq", "chain_seq", unique=True),
    )


class ProxyConfig(Base):
    __tablename__ = "proxy_config"

    key = Column(Text, primary_key=True)
    value = Column(Text, nullable=False)


class MastioKeyRow(Base):
    """ADR-012 Phase 2.0 — multi-key store for the Mastio ES256 identity.

    A row per historical ES256 leaf keypair. Exactly one row has
    ``activated_at IS NOT NULL AND deprecated_at IS NULL`` at any time:
    that is the current signer used by ``LocalIssuer`` and by the
    ADR-009 counter-signature path.

    Timestamps are ISO-8601 UTC strings (``Text``), matching the
    convention used by ``internal_agents`` and ``pending_enrollments``.
    """
    __tablename__ = "mastio_keys"

    # Deterministic ``mastio-<sha256(pubkey_pem)[:16]>`` — the ``kid``
    # that the LocalIssuer stamps into JWT headers.
    kid = Column(Text, primary_key=True)
    pubkey_pem = Column(Text, nullable=False)
    privkey_pem = Column(Text, nullable=False)
    # The X.509 leaf cert currently chained under this key. Nullable so
    # the CA can re-issue without churning the key, but in practice
    # ``ensure_mastio_identity`` always writes them together.
    cert_pem = Column(Text, nullable=True)
    created_at = Column(Text, nullable=False)
    # Set when the key becomes the current signer. NULL = never activated
    # (staged only, will be unusual until rotation lands in Phase 2.1).
    activated_at = Column(Text, nullable=True)
    # Set when a newer key takes over. NULL while this key is current.
    deprecated_at = Column(Text, nullable=True)
    # After this timestamp the verifier stops accepting this key.
    # NULL = never expires (legacy / single-key mode).
    expires_at = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_mastio_keys_active", "activated_at", "deprecated_at"),
    )


class PendingEnrollment(Base):
    """Connector enrollment requests awaiting admin decision.

    Lifecycle: pending → approved (cert issued) | rejected | expired.
    The requester supplies identity (name/email/reason) and a public key.
    The admin chooses agent_id + capabilities + groups and signs the cert —
    the requester never influences those values.
    """
    __tablename__ = "pending_enrollments"

    session_id = Column(Text, primary_key=True)
    pubkey_pem = Column(Text, nullable=False)
    pubkey_fingerprint = Column(Text, nullable=False)  # SHA-256 hex of SubjectPublicKeyInfo DER
    requester_name = Column(Text, nullable=False)
    requester_email = Column(Text, nullable=False)
    reason = Column(Text, nullable=True)
    device_info = Column(Text, nullable=True)  # free-form JSON from SDK
    # F-B-11 Phase 3b (#181) — RFC 7638 thumbprint of the DPoP JWK
    # the Connector submitted at start_enrollment. Carried forward
    # to ``internal_agents.dpop_jkt`` on approval. NULL when the
    # SDK did not publish a JWK (legacy / pre-Phase-3c clients).
    dpop_jkt = Column(Text, nullable=True)
    status = Column(
        Text, nullable=False, server_default="pending"
    )  # pending | approved | rejected | expired
    created_at = Column(Text, nullable=False)
    expires_at = Column(Text, nullable=False)

    # Filled on admin decision
    decided_at = Column(Text, nullable=True)
    decided_by = Column(Text, nullable=True)

    # Approved: admin-assigned fields and resulting cert
    agent_id_assigned = Column(Text, nullable=True)
    capabilities_assigned = Column(Text, nullable=True, server_default="[]")
    groups_assigned = Column(Text, nullable=True, server_default="[]")
    cert_pem = Column(Text, nullable=True)

    # Rejected
    rejection_reason = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_pending_enrollments_status", "status"),
        Index("idx_pending_enrollments_created_at", "created_at"),
        Index("idx_pending_enrollments_fingerprint", "pubkey_fingerprint"),
    )


# ── Local-* tables (ADR-001 Phase 1, unused until Phase 4) ───────────────────
#
# Minimal forward-compatible columns. Each table exists so that Phase 4 work
# can assume the schema is already deployed, without requiring another
# migration round-trip on live proxies.


class LocalSession(Base):
    """Intra-org sessions. Column names match broker ``sessions`` table."""
    __tablename__ = "local_sessions"

    session_id = Column(Text, primary_key=True)
    initiator_agent_id = Column(Text, nullable=False)
    initiator_org_id = Column(Text, nullable=True)
    target_agent_id = Column(Text, nullable=False)
    target_org_id = Column(Text, nullable=True)
    status = Column(Text, nullable=False)  # pending | active | closed
    requested_capabilities = Column(Text, nullable=False, server_default="[]")
    created_at = Column(Text, nullable=False)
    expires_at = Column(Text, nullable=True)
    closed_at = Column(Text, nullable=True)
    last_activity_at = Column(Text, nullable=True)
    close_reason = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_local_sessions_initiator", "initiator_agent_id"),
        Index("idx_local_sessions_target", "target_agent_id"),
        Index("idx_local_sessions_status", "status"),
        Index("idx_local_sessions_initiator_org", "initiator_org_id"),
        Index("idx_local_sessions_target_org", "target_org_id"),
    )


class LocalMessage(Base):
    """M3-twin queue for intra-org messages.

    ``delivery_status`` mirrors broker ``ProxyMessageQueueRecord``:
    0 = pending, 1 = delivered, 2 = expired.

    ADR-008 Phase 1: one-shot rows set ``session_id = NULL``,
    ``is_oneshot = 1`` and track the request↔response pair through
    ``correlation_id`` / ``reply_to_correlation_id``. Session rows are
    unaffected.
    """
    __tablename__ = "local_messages"

    msg_id = Column(Text, primary_key=True)
    session_id = Column(Text, nullable=True)  # ADR-008: NULL for one-shot rows
    seq = Column(Integer, nullable=True)
    sender_agent_id = Column(Text, nullable=False)
    recipient_agent_id = Column(Text, nullable=False)
    payload_ciphertext = Column(Text, nullable=False)
    nonce = Column(Text, nullable=True)
    signature = Column(Text, nullable=True)
    idempotency_key = Column(Text, nullable=True)
    delivery_status = Column(SmallInteger, nullable=False, server_default="0")
    attempts = Column(Integer, nullable=False, server_default="0")
    enqueued_at = Column(Text, nullable=False)
    delivered_at = Column(Text, nullable=True)
    expired_at = Column(Text, nullable=True)
    expires_at = Column(Text, nullable=True)
    # ADR-008 Phase 1 PR #1 — one-shot pattern metadata.
    is_oneshot = Column(Integer, nullable=False, server_default="0")
    correlation_id = Column(Text, nullable=True)
    reply_to_correlation_id = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_local_messages_session", "session_id"),
        Index(
            "idx_local_messages_recipient_delivery_status",
            "recipient_agent_id",
            "delivery_status",
        ),
        Index("idx_local_messages_idempotency", "idempotency_key"),
        Index("idx_local_messages_correlation", "correlation_id"),
        Index(
            "idx_local_messages_recipient_oneshot",
            "recipient_agent_id",
            "is_oneshot",
            "delivery_status",
        ),
        UniqueConstraint("session_id", "seq", name="uq_local_messages_session_seq"),
        UniqueConstraint("nonce", name="uq_local_messages_nonce"),
    )


class LocalPolicy(Base):
    """Local-only policy records (intra-org scope)."""
    __tablename__ = "local_policies"

    policy_id = Column(Text, primary_key=True)
    org_id = Column(Text, nullable=True)
    policy_type = Column(Text, nullable=True)  # session | message
    name = Column(Text, nullable=False)
    scope = Column(Text, nullable=False, server_default="intra")  # reserved: "intra" | "egress"
    rules_json = Column(Text, nullable=False, server_default="{}")
    enabled = Column(Integer, nullable=False, server_default="1")
    created_at = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)

    __table_args__ = (
        Index("idx_local_policies_org", "org_id"),
        Index("idx_local_policies_type", "policy_type"),
    )


class LocalAudit(Base):
    """Append-only, hash-chained intra-org audit log.

    Column names and hash canonical form match broker ``app/db/audit.py``
    (``AuditLog`` + ``compute_entry_hash``). Rows are byte-for-byte
    portable: export on the proxy and verify on the broker without schema
    translation. Cross-org dual-write columns (``peer_org_id``,
    ``peer_row_hash``) are present for schema parity — the proxy never
    dual-writes in standalone mode, they stay NULL.
    """
    __tablename__ = "local_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Text, nullable=False)
    event_type = Column(Text, nullable=False)
    agent_id = Column(Text, nullable=True)
    session_id = Column(Text, nullable=True)
    org_id = Column(Text, nullable=True)
    details = Column(Text, nullable=True)
    result = Column(Text, nullable=False, server_default="ok")
    entry_hash = Column(Text, nullable=True)
    previous_hash = Column(Text, nullable=True)
    chain_seq = Column(Integer, nullable=True)
    peer_org_id = Column(Text, nullable=True)
    peer_row_hash = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_local_audit_timestamp", "timestamp"),
        Index("idx_local_audit_event_type", "event_type"),
        Index("idx_local_audit_agent", "agent_id"),
        Index("idx_local_audit_session", "session_id"),
        Index("idx_local_audit_org", "org_id"),
        Index("idx_local_audit_peer_org", "peer_org_id"),
    )


# ── MCP Resources (ADR-007 Phase 1, unused until PR-3 wires routing) ─────────


class LocalMCPResource(Base):
    """Registry of MCP resources mediated by the proxy.

    An MCP resource is an external service (postgres-mcp, github-mcp, ...)
    that local agents may call through the proxy. The proxy enforces
    binding + capability + egress-domain allowlists on each call.

    ADR-007 Phase 1 PR #1 deploys schema only — no handler reads from this
    table yet. PR-3 wires aggregated discovery and mediated forwarding.
    """

    __tablename__ = "local_mcp_resources"

    resource_id = Column(Text, primary_key=True)
    org_id = Column(Text, nullable=True)
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    endpoint_url = Column(Text, nullable=False)
    auth_type = Column(Text, nullable=False, server_default="none")
    auth_secret_ref = Column(Text, nullable=True)
    required_capability = Column(Text, nullable=True)
    allowed_domains = Column(Text, nullable=False, server_default="[]")
    enabled = Column(Integer, nullable=False, server_default="1")
    created_at = Column(Text, nullable=False)
    updated_at = Column(Text, nullable=False)

    __table_args__ = (
        Index("idx_local_mcp_resources_org_enabled", "org_id", "enabled"),
        UniqueConstraint(
            "org_id", "name", name="uq_local_mcp_resources_org_name"
        ),
    )


class LocalAgentResourceBinding(Base):
    """Explicit N:N grant: which local principals may call which resources.

    Revocation is soft (``revoked_at`` non-null). Regrant = UPDATE the
    existing row back to ``revoked_at=NULL`` — the UNIQUE on
    ``(agent_id, principal_type, resource_id)`` enforces one logical
    binding per (principal, resource) pair without relying on partial
    indexes (SQLite/Postgres parity).

    ADR-020 — ``principal_type`` widens the table to user / workload
    principals next to the legacy ``agent``. The column name
    ``agent_id`` stays for compatibility with on-disk rows and outside
    callers; semantically it now holds a *principal_id* (canonical
    ``{org}::{name}`` for agents, ``{org}::user::{name}`` /
    ``{org}::workload::{name}`` for typed principals as emitted by the
    auth layer).
    """

    __tablename__ = "local_agent_resource_bindings"

    binding_id = Column(Text, primary_key=True)
    agent_id = Column(Text, nullable=False)
    # ADR-020 — defaults to "agent" so pre-migration rows + tests that
    # don't set the field stay valid. Migration 0024 backfills the
    # legacy table with the same default.
    principal_type = Column(
        Text, nullable=False, server_default="agent",
    )
    resource_id = Column(Text, nullable=False)
    org_id = Column(Text, nullable=True)
    granted_by = Column(Text, nullable=False)
    granted_at = Column(Text, nullable=False)
    revoked_at = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_local_bindings_agent_revoked", "agent_id", "revoked_at"),
        Index("idx_local_bindings_resource_revoked", "resource_id", "revoked_at"),
        Index("idx_local_bindings_org", "org_id"),
        UniqueConstraint(
            "agent_id", "principal_type", "resource_id",
            name="uq_local_bindings_principal_resource",
        ),
    )


# ── Anomaly detector (ADR-013 Phase 4) ───────────────────────────────────────


class AgentTrafficSample(Base):
    """10-min bucketed request counts per agent (4-week rolling window).

    Written by the traffic-recorder middleware (async flush every 30 s).
    Read by the baseline roll-up cron and by the anomaly evaluator's
    5-min windowed rate query.
    """

    __tablename__ = "agent_traffic_samples"

    agent_id = Column(Text, nullable=False)
    bucket_ts = Column(Text, nullable=False)  # ISO-8601, start of 10-min bucket
    req_count = Column(Integer, nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint(
            "agent_id", "bucket_ts", name="pk_agent_traffic_samples"
        ),
        Index("idx_traffic_samples_bucket", "bucket_ts"),
    )


class AgentHourlyBaseline(Base):
    """Rolled-up hour-of-week baselines (168 buckets/agent).

    ``hour_of_week = dow * 24 + hour``. The ratio detector divides the
    current 5-min rate by ``req_per_min_avg`` for the current
    hour_of_week. ``req_per_min_p95`` is reserved for future tuning
    (e.g., compare against p95 instead of mean for bursty-but-legit
    workloads).
    """

    __tablename__ = "agent_hourly_baselines"

    agent_id = Column(Text, nullable=False)
    hour_of_week = Column(SmallInteger, nullable=False)
    req_per_min_avg = Column(Float, nullable=False)
    req_per_min_p95 = Column(Float, nullable=False)
    sample_count = Column(Integer, nullable=False)
    updated_at = Column(Text, nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint(
            "agent_id", "hour_of_week", name="pk_agent_hourly_baselines"
        ),
        CheckConstraint(
            "hour_of_week BETWEEN 0 AND 167",
            name="ck_agent_hourly_baselines_hour_range",
        ),
    )


class AgentQuarantineEvent(Base):
    """Append-only audit of every quarantine decision.

    One row per decision; shadow-mode events are recorded with
    ``mode='shadow'`` and ``expires_at=NULL`` (shadow-mode decisions
    never actually expire because they never actually disabled anyone).
    Operator reactivation and expiry cron both write ``resolved_at`` +
    ``resolved_by`` — the row is never updated otherwise.
    """

    __tablename__ = "agent_quarantine_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(Text, nullable=False)
    quarantined_at = Column(Text, nullable=False)
    mode = Column(Text, nullable=False)  # 'shadow' | 'enforce'
    trigger_ratio = Column(Float, nullable=True)
    trigger_abs_rate = Column(Float, nullable=True)
    expires_at = Column(Text, nullable=True)
    resolved_at = Column(Text, nullable=True)
    resolved_by = Column(Text, nullable=True)  # 'operator:<hash>' | 'expired'
    notification_sent = Column(Integer, nullable=False, server_default="0")

    __table_args__ = (
        CheckConstraint(
            "mode IN ('shadow', 'enforce')",
            name="ck_agent_quarantine_events_mode",
        ),
        Index("idx_quarantine_agent", "agent_id", "quarantined_at"),
    )
