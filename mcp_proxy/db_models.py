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
    Column,
    Index,
    Integer,
    MetaData,
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
    api_key_hash = Column(Text, nullable=False)
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

    __table_args__ = (
        Index("idx_audit_log_agent_id", "agent_id"),
        Index("idx_audit_log_timestamp", "timestamp"),
        Index("idx_audit_log_request_id", "request_id"),
    )


class ProxyConfig(Base):
    __tablename__ = "proxy_config"

    key = Column(Text, primary_key=True)
    value = Column(Text, nullable=False)


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
    """Explicit N:N grant: which local agents may call which resources.

    Revocation is soft (``revoked_at`` non-null). Regrant = UPDATE the
    existing row back to ``revoked_at=NULL`` — the UNIQUE on
    ``(agent_id, resource_id)`` enforces one logical binding per pair
    without relying on partial indexes (SQLite/Postgres parity).
    """

    __tablename__ = "local_agent_resource_bindings"

    binding_id = Column(Text, primary_key=True)
    agent_id = Column(Text, nullable=False)
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
            "agent_id", "resource_id",
            name="uq_local_bindings_agent_resource",
        ),
    )
