"""
ORM model and queries for org ↔ agent bindings.

A binding is the server-side approved relationship between an agent_id and an org_id.
It is not declared by the client, not in the token — it is in the database.
"""
import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, UniqueConstraint, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


class BindingRecord(Base):
    __tablename__ = "bindings"
    __table_args__ = (
        UniqueConstraint("org_id", "agent_id", name="uq_binding_org_agent"),
    )

    id = Column(Integer, primary_key=True)
    org_id = Column(String(128), nullable=False, index=True)
    agent_id = Column(String(256), nullable=False, index=True)
    status = Column(String(16), default="pending")   # "pending" | "approved" | "revoked"
    scope_json = Column(Text, default="[]")           # JSON array: ["kyc.read", ...]
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approved_by = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    @property
    def scope(self) -> list[str]:
        return json.loads(self.scope_json)


async def create_binding(
    db: AsyncSession,
    org_id: str,
    agent_id: str,
    scope: list[str],
) -> BindingRecord:
    record = BindingRecord(
        org_id=org_id,
        agent_id=agent_id,
        scope_json=json.dumps(scope),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def get_binding(db: AsyncSession, binding_id: int) -> BindingRecord | None:
    result = await db.execute(
        select(BindingRecord).where(BindingRecord.id == binding_id)
    )
    return result.scalar_one_or_none()


async def get_approved_binding(
    db: AsyncSession, org_id: str, agent_id: str
) -> BindingRecord | None:
    result = await db.execute(
        select(BindingRecord).where(
            BindingRecord.org_id == org_id,
            BindingRecord.agent_id == agent_id,
            BindingRecord.status == "approved",
        )
    )
    return result.scalar_one_or_none()


async def get_binding_by_org_agent(
    db: AsyncSession, org_id: str, agent_id: str
) -> BindingRecord | None:
    result = await db.execute(
        select(BindingRecord).where(
            BindingRecord.org_id == org_id,
            BindingRecord.agent_id == agent_id,
        )
    )
    return result.scalar_one_or_none()


async def approve_binding(
    db: AsyncSession, binding_id: int, approved_by: str
) -> BindingRecord | None:
    from app.broker.federation import (
        EVENT_BINDING_GRANTED,
        publish_federation_event,
    )

    binding = await get_binding(db, binding_id)
    if not binding:
        return None
    if binding.status not in ("pending", "revoked"):
        return None
    binding.status = "approved"
    binding.approved_at = datetime.now(timezone.utc)
    binding.approved_by = approved_by
    await publish_federation_event(
        db,
        org_id=binding.org_id,
        event_type=EVENT_BINDING_GRANTED,
        payload={
            "binding_id": binding_id,
            "agent_id": binding.agent_id,
            "scope": binding.scope,
        },
    )
    await db.commit()
    await db.refresh(binding)
    return binding


async def revoke_binding(db: AsyncSession, binding_id: int) -> BindingRecord | None:
    from app.broker.federation import (
        EVENT_BINDING_REVOKED,
        publish_federation_event,
    )

    binding = await get_binding(db, binding_id)
    if not binding:
        return None
    binding.status = "revoked"
    await publish_federation_event(
        db,
        org_id=binding.org_id,
        event_type=EVENT_BINDING_REVOKED,
        payload={
            "binding_id": binding_id,
            "agent_id": binding.agent_id,
        },
    )
    await db.commit()
    await db.refresh(binding)
    return binding


async def list_bindings(db: AsyncSession, org_id: str) -> list[BindingRecord]:
    result = await db.execute(
        select(BindingRecord).where(BindingRecord.org_id == org_id)
    )
    return list(result.scalars().all())
