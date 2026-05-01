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
    """Revoke a binding and invalidate the agent's active access tokens.

    Audit F-D-1 (revocation-lag): callers that revoke a binding without
    also invalidating the agent's tokens leave up to a 60-minute window
    in which the (now unbound) agent can still hit every authenticated
    REST endpoint. Making token invalidation part of ``revoke_binding``
    closes the gap for every caller — API, dashboard and future
    federation event handlers — without requiring each caller to
    remember the second step. The work stays in the same transaction so
    either both mutations commit or neither does.
    """
    from app.broker.federation import (
        EVENT_BINDING_REVOKED,
        publish_federation_event,
    )
    from app.registry.store import invalidate_agent_tokens

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
    # Stamp token_invalidated_at on the agent row. Tokens issued before
    # this call fail the revocation check in app/auth/jwt.py; tokens
    # issued AFTER re-approve (fresh iat) are unaffected because
    # iat > invalidated_at.
    await invalidate_agent_tokens(db, binding.agent_id)
    await db.commit()
    await db.refresh(binding)
    return binding


async def list_bindings(db: AsyncSession, org_id: str) -> list[BindingRecord]:
    result = await db.execute(
        select(BindingRecord).where(BindingRecord.org_id == org_id)
    )
    return list(result.scalars().all())


async def list_all_bindings(
    db: AsyncSession, status_filter: str | None = None,
) -> list[BindingRecord]:
    """Return every binding across orgs. Network-admin only — used by the
    Court dashboard to render a full registry view; regular org-scoped
    callers must use ``list_bindings(org_id=...)`` to stay tenant-bound."""
    stmt = select(BindingRecord).order_by(BindingRecord.created_at.desc())
    if status_filter:
        stmt = stmt.where(BindingRecord.status == status_filter)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def update_binding_scope(
    db: AsyncSession, binding_id: int, scope: list[str],
) -> BindingRecord | None:
    """Update an existing binding's scope subset. Caller is responsible
    for validating that ``scope`` is a subset of the agent's declared
    capabilities — the binding store does not re-fetch the agent here so
    the same helper works whether the caller has the agent record loaded
    or not. Returns the refreshed binding or None if missing."""
    binding = await get_binding(db, binding_id)
    if not binding:
        return None
    binding.scope_json = json.dumps(scope)
    await db.commit()
    await db.refresh(binding)
    return binding
