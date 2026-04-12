"""
SQLAlchemy models for session, message, and RFQ persistence.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Text, DateTime, Integer, LargeBinary,
    SmallInteger, UniqueConstraint, Index,
)

from app.db.database import Base


class SessionRecord(Base):
    __tablename__ = "sessions"

    session_id          = Column(String(128), primary_key=True)
    initiator_agent_id  = Column(String(128), nullable=False)
    initiator_org_id    = Column(String(128), nullable=False)
    target_agent_id     = Column(String(128), nullable=False)
    target_org_id       = Column(String(128), nullable=False)
    status              = Column(String(16),  nullable=False, index=True)
    requested_capabilities = Column(Text, nullable=False)   # JSON list
    created_at          = Column(DateTime(timezone=True), nullable=False)
    expires_at          = Column(DateTime(timezone=True), nullable=True)
    closed_at           = Column(DateTime(timezone=True), nullable=True)
    last_activity_at    = Column(DateTime(timezone=True), nullable=True)
    close_reason        = Column(String(32),  nullable=True)


class SessionMessageRecord(Base):
    __tablename__ = "session_messages"
    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_session_seq"),
    )

    id              = Column(Integer, primary_key=True, autoincrement=True)
    session_id      = Column(String(128), nullable=False, index=True)
    seq             = Column(Integer, nullable=False)
    sender_agent_id = Column(String(128), nullable=False)
    payload         = Column(Text, nullable=False)          # JSON dict
    nonce           = Column(String(128), nullable=False, unique=True)
    timestamp       = Column(DateTime(timezone=True), nullable=False,
                             default=lambda: datetime.now(timezone.utc))
    signature       = Column(Text, nullable=True)   # base64 RSA-PKCS1v15-SHA256
    client_seq      = Column(Integer, nullable=True)


class ProxyMessageQueueRecord(Base):
    """M3 message durability — queued messages awaiting recipient ack.

    Schema validated in the M0.3 spike (imp/m0_storage_spike.md):
    ~53k enqueue/s single writer, <1ms p99 dequeue, 1M TTL sweep in ~5s.

    A row is enqueued when a message arrives and cannot be confirmed
    delivered (recipient offline, WS send failed, etc.). It is dequeued
    on explicit ack, or swept when ttl_expires_at passes. Metadata-only
    audit survives in session_messages — this table holds the ciphertext
    and is pruned aggressively.

    ``delivery_status`` values:
      0 = pending   — enqueued, awaiting delivery/ack
      1 = delivered — recipient ack'd, row eligible for pruning
      2 = expired   — TTL passed before ack, sender notified
    """

    __tablename__ = "proxy_message_queue"
    __table_args__ = (
        UniqueConstraint(
            "recipient_agent_id", "idempotency_key",
            name="uq_proxy_queue_idempotency",
        ),
        Index(
            "idx_proxy_queue_recipient_pending",
            "recipient_agent_id", "seq",
        ),
        Index(
            "idx_proxy_queue_ttl",
            "ttl_expires_at",
        ),
    )

    msg_id              = Column(String(64), primary_key=True)
    session_id          = Column(String(128), nullable=False, index=True)
    recipient_agent_id  = Column(String(256), nullable=False)
    sender_agent_id     = Column(String(256), nullable=False)
    ciphertext          = Column(LargeBinary, nullable=False)
    seq                 = Column(Integer, nullable=False)
    enqueued_at         = Column(DateTime(timezone=True), nullable=False,
                                 default=lambda: datetime.now(timezone.utc))
    ttl_expires_at      = Column(DateTime(timezone=True), nullable=False)
    delivery_status     = Column(SmallInteger, nullable=False, default=0, index=True)
    attempts            = Column(SmallInteger, nullable=False, default=0)
    idempotency_key     = Column(String(256), nullable=True)
    delivered_at        = Column(DateTime(timezone=True), nullable=True)
    expired_at          = Column(DateTime(timezone=True), nullable=True)


class RfqRecord(Base):
    __tablename__ = "rfq_requests"

    rfq_id              = Column(String(128), primary_key=True)
    initiator_agent_id  = Column(String(256), nullable=False, index=True)
    initiator_org_id    = Column(String(128), nullable=False, index=True)
    capability_filter   = Column(Text, nullable=False)              # JSON list
    payload_json        = Column(Text, nullable=False)              # The RFQ payload
    status              = Column(String(16), nullable=False, index=True)  # open | closed | timeout
    timeout_seconds     = Column(Integer, nullable=False, default=30)
    matched_agents_json = Column(Text, nullable=False, default="[]")  # JSON list of agent_ids
    created_at          = Column(DateTime(timezone=True), nullable=False)
    closed_at           = Column(DateTime(timezone=True), nullable=True)


class RfqResponseRecord(Base):
    __tablename__ = "rfq_responses"
    __table_args__ = (
        UniqueConstraint("rfq_id", "responder_agent_id", name="uq_rfq_responder"),
    )

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    rfq_id              = Column(String(128), nullable=False, index=True)
    responder_agent_id  = Column(String(256), nullable=False)
    responder_org_id    = Column(String(128), nullable=False)
    response_payload    = Column(Text, nullable=False)              # JSON
    received_at         = Column(DateTime(timezone=True), nullable=False)
