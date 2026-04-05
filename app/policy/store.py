"""
ORM model e query per le policy organizzative.
"""
import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


class PolicyRecord(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True)
    policy_id = Column(String(128), unique=True, nullable=False, index=True)
    org_id = Column(String(128), nullable=False, index=True)
    policy_type = Column(String(32), nullable=False)   # "session" | "message"
    rules_json = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    @property
    def rules(self) -> dict:
        return json.loads(self.rules_json)


async def create_policy(
    db: AsyncSession,
    policy_id: str,
    org_id: str,
    policy_type: str,
    rules: dict,
) -> PolicyRecord:
    record = PolicyRecord(
        policy_id=policy_id,
        org_id=org_id,
        policy_type=policy_type,
        rules_json=json.dumps(rules),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def get_policy(db: AsyncSession, policy_id: str) -> PolicyRecord | None:
    result = await db.execute(
        select(PolicyRecord).where(PolicyRecord.policy_id == policy_id)
    )
    return result.scalar_one_or_none()


async def list_policies(
    db: AsyncSession,
    org_id: str,
    policy_type: str | None = None,
) -> list[PolicyRecord]:
    query = select(PolicyRecord).where(
        PolicyRecord.org_id == org_id,
        PolicyRecord.is_active == True,  # noqa: E712
    )
    if policy_type:
        query = query.where(PolicyRecord.policy_type == policy_type)
    result = await db.execute(query)
    return list(result.scalars().all())


async def deactivate_policy(db: AsyncSession, policy_id: str) -> PolicyRecord | None:
    record = await get_policy(db, policy_id)
    if not record:
        return None
    record.is_active = False
    await db.commit()
    await db.refresh(record)
    return record
