"""
Append-only audit log — every session event is recorded here.
No row is ever modified or deleted (threat model: non-repudiation).
"""
import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    agent_id = Column(String(128), nullable=True, index=True)
    session_id = Column(String(128), nullable=True, index=True)
    org_id = Column(String(128), nullable=True, index=True)
    details = Column(Text, nullable=True)   # serialized JSON
    result = Column(String(16), nullable=False)  # "ok" | "denied" | "error"


async def log_event(
    db: AsyncSession,
    event_type: str,
    result: str,
    agent_id: str | None = None,
    session_id: str | None = None,
    org_id: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    entry = AuditLog(
        event_type=event_type,
        agent_id=agent_id,
        session_id=session_id,
        org_id=org_id,
        details=json.dumps(details) if details else None,
        result=result,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry
