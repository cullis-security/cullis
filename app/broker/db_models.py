"""
SQLAlchemy models for session and message persistence.
"""
import json
from datetime import datetime, timezone

from sqlalchemy import Column, String, Text, DateTime, Integer, UniqueConstraint

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
