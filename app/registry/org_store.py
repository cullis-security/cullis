"""
ORM model and queries for the organization registry.
"""
import json
import bcrypt
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


class OrganizationRecord(Base):
    __tablename__ = "organizations"

    org_id = Column(String(128), primary_key=True)
    display_name = Column(String(256), nullable=False)
    secret_hash = Column(String(256), nullable=False)
    status = Column(String(16), default="active")
    registered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    metadata_json = Column(Text, default="{}")
    ca_certificate = Column(Text, nullable=True)
    webhook_url = Column(String(512), nullable=True)  # PDP webhook — None = default-deny
    oidc_issuer_url = Column(String(512), nullable=True)
    oidc_client_id = Column(String(256), nullable=True)
    oidc_client_secret = Column(String(512), nullable=True)

    def verify_secret(self, plain: str) -> bool:
        return bcrypt.checkpw(plain.encode(), self.secret_hash.encode())

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer_url and self.oidc_client_id)

    @property
    def extra(self) -> dict:
        return json.loads(self.metadata_json)


async def register_org(
    db: AsyncSession,
    org_id: str,
    display_name: str,
    secret: str,
    metadata: dict | None = None,
    webhook_url: str | None = None,
) -> OrganizationRecord:
    record = OrganizationRecord(
        org_id=org_id,
        display_name=display_name,
        secret_hash=bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode(),
        metadata_json=json.dumps(metadata or {}),
        webhook_url=webhook_url,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def get_org_by_id(db: AsyncSession, org_id: str) -> OrganizationRecord | None:
    result = await db.execute(
        select(OrganizationRecord).where(OrganizationRecord.org_id == org_id)
    )
    return result.scalar_one_or_none()


async def update_org_webhook(
    db: AsyncSession,
    org_id: str,
    webhook_url: str | None,
) -> OrganizationRecord | None:
    record = await get_org_by_id(db, org_id)
    if record is None:
        return None
    record.webhook_url = webhook_url
    await db.commit()
    await db.refresh(record)
    return record


async def update_org_ca_cert(
    db: AsyncSession,
    org_id: str,
    ca_certificate_pem: str,
) -> OrganizationRecord | None:
    record = await get_org_by_id(db, org_id)
    if record is None:
        return None
    record.ca_certificate = ca_certificate_pem
    await db.commit()
    await db.refresh(record)
    return record


async def update_org_oidc(
    db: AsyncSession,
    org_id: str,
    issuer_url: str | None,
    client_id: str | None,
    client_secret: str | None,
) -> OrganizationRecord | None:
    record = await get_org_by_id(db, org_id)
    if record is None:
        return None
    record.oidc_issuer_url = issuer_url
    record.oidc_client_id = client_id
    record.oidc_client_secret = client_secret
    await db.commit()
    await db.refresh(record)
    return record


async def list_orgs(db: AsyncSession) -> list[OrganizationRecord]:
    result = await db.execute(
        select(OrganizationRecord).where(OrganizationRecord.status == "active")
    )
    return list(result.scalars().all())


async def list_pending_orgs(db: AsyncSession) -> list[OrganizationRecord]:
    result = await db.execute(
        select(OrganizationRecord).where(OrganizationRecord.status == "pending")
    )
    return list(result.scalars().all())


async def set_org_status(db: AsyncSession, org_id: str, new_status: str) -> OrganizationRecord | None:
    record = await get_org_by_id(db, org_id)
    if record is None:
        return None
    record.status = new_status
    await db.commit()
    await db.refresh(record)
    return record
