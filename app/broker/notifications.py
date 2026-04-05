"""
Persistent notification inbox — stores notifications until the recipient acts.

Notifications are created by the broker when events require agent/admin attention:
  - session_pending  → target agent must accept or reject
  - session_closed   → both agents are notified
  - binding_pending  → org admin must approve

WebSocket pushes the notification in real-time if the agent is online.
If offline, the agent finds it in the inbox on next connect or poll.

Notifications are marked as 'read' or 'acted' — never deleted (audit trail).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime, Text, Boolean, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String(64), primary_key=True, default=lambda: uuid.uuid4().hex)
    recipient_type = Column(String(16), nullable=False, index=True)   # "agent" | "admin"
    recipient_id = Column(String(256), nullable=False, index=True)    # agent_id or "admin"
    org_id = Column(String(128), nullable=True, index=True)           # org isolation — prevents cross-org leaks
    notification_type = Column(String(64), nullable=False, index=True)  # "session_pending", "binding_pending", etc.
    title = Column(String(512), nullable=False)
    body = Column(Text, nullable=True)       # JSON details
    reference_id = Column(String(256), nullable=True)  # session_id, binding_id, etc.
    is_read = Column(Boolean, default=False, nullable=False)
    is_acted = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    acted_at = Column(DateTime(timezone=True), nullable=True)


async def create_notification(
    db: AsyncSession,
    recipient_type: str,
    recipient_id: str,
    notification_type: str,
    title: str,
    body: str | None = None,
    reference_id: str | None = None,
    org_id: str | None = None,
) -> Notification:
    n = Notification(
        recipient_type=recipient_type,
        recipient_id=recipient_id,
        org_id=org_id,
        notification_type=notification_type,
        title=title,
        body=body,
        reference_id=reference_id,
    )
    db.add(n)
    await db.commit()
    await db.refresh(n)
    return n


async def get_pending_notifications(
    db: AsyncSession,
    recipient_type: str,
    recipient_id: str,
    org_id: str | None = None,
    limit: int = 50,
) -> list[Notification]:
    query = (
        select(Notification)
        .where(
            Notification.recipient_type == recipient_type,
            Notification.recipient_id == recipient_id,
            Notification.is_acted.is_(False),
        )
        .order_by(Notification.created_at.desc())
        .limit(limit)
    )
    if org_id:
        query = query.where(Notification.org_id == org_id)
    result = await db.execute(query)
    return list(result.scalars().all())


async def count_pending_notifications(
    db: AsyncSession,
    recipient_type: str,
    recipient_id: str,
    org_id: str | None = None,
) -> int:
    query = (
        select(func.count(Notification.id))
        .where(
            Notification.recipient_type == recipient_type,
            Notification.recipient_id == recipient_id,
            Notification.is_acted.is_(False),
        )
    )
    if org_id:
        query = query.where(Notification.org_id == org_id)
    result = await db.execute(query)
    return result.scalar() or 0


async def mark_acted(db: AsyncSession, notification_id: str) -> None:
    result = await db.execute(
        select(Notification).where(Notification.id == notification_id)
    )
    n = result.scalar_one_or_none()
    if n:
        n.is_acted = True
        n.acted_at = datetime.now(timezone.utc)
        await db.commit()


async def mark_acted_by_reference(
    db: AsyncSession,
    notification_type: str,
    reference_id: str,
) -> None:
    """Mark all notifications for a given reference as acted (e.g., session accepted)."""
    result = await db.execute(
        select(Notification).where(
            Notification.notification_type == notification_type,
            Notification.reference_id == reference_id,
            Notification.is_acted.is_(False),
        )
    )
    for n in result.scalars().all():
        n.is_acted = True
        n.acted_at = datetime.now(timezone.utc)
    await db.commit()
