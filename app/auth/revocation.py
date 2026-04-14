"""
Certificate revocation — blocking compromised x509 certificates.

A revoked certificate is rejected during authentication, before JWT
signature verification.

Lazy cleanup: records with cert_not_after < now are removed on every
insert, similar to the JTI blacklist.
"""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import Column, String, DateTime, select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


class RevokedCert(Base):
    __tablename__ = "revoked_certs"

    serial_hex    = Column(String(64),  primary_key=True)
    org_id        = Column(String(128), nullable=False, index=True)
    revoked_at    = Column(DateTime(timezone=True), nullable=False)
    revoked_by    = Column(String(128), nullable=False)
    reason        = Column(String(256), nullable=True)
    cert_not_after = Column(DateTime(timezone=True), nullable=False)
    agent_id      = Column(String(256), nullable=True, index=True)


async def check_cert_not_revoked(db: AsyncSession, serial_hex: str) -> None:
    """
    Verify that the certificate has not been revoked.
    Raises HTTPException 401 if present in revoked_certs.

    Increments REVOKED_TOKEN_USE_COUNTER on hit — drives the
    RevokedTokenReuseAttempt alert.
    """
    result = await db.execute(
        select(RevokedCert).where(RevokedCert.serial_hex == serial_hex)
    )
    if result.scalar_one_or_none() is not None:
        from app.telemetry_metrics import REVOKED_TOKEN_USE_COUNTER
        REVOKED_TOKEN_USE_COUNTER.add(1, {"kind": "cert_revoked"})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Certificate has been revoked",
        )


async def revoke_cert(
    db: AsyncSession,
    serial_hex: str,
    org_id: str,
    cert_not_after: datetime,
    revoked_by: str,
    agent_id: str | None = None,
    reason: str | None = None,
) -> RevokedCert:
    """
    Register a certificate as revoked.
    Uses atomic INSERT ... ON CONFLICT to avoid TOCTOU race conditions:
    two concurrent revocation requests for the same serial cannot both succeed.
    Performs lazy cleanup of records with expired certs.
    Raises HTTPException 409 if the serial is already revoked.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    now = datetime.now(timezone.utc)

    values = dict(
        serial_hex=serial_hex,
        org_id=org_id,
        revoked_at=now,
        revoked_by=revoked_by,
        reason=reason,
        cert_not_after=cert_not_after,
        agent_id=agent_id,
    )

    dialect_name = db.bind.dialect.name if db.bind else "unknown"

    if dialect_name == "postgresql":
        stmt = pg_insert(RevokedCert).values(**values)
        stmt = stmt.on_conflict_do_nothing(index_elements=["serial_hex"])
    else:
        stmt = sqlite_insert(RevokedCert).values(**values)
        stmt = stmt.on_conflict_do_nothing(index_elements=["serial_hex"])

    result = await db.execute(stmt)

    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Certificate already revoked",
        )

    # Lazy cleanup: remove expired certs (no longer a threat).
    # Buffer of 30 min beyond cert expiry to cover tokens issued just before expiry.
    await db.execute(
        delete(RevokedCert).where(RevokedCert.cert_not_after < now - timedelta(minutes=30))
    )

    # Federation event so proxies can drop the cert from their cache.
    from app.broker.federation import (
        EVENT_AGENT_REVOKED,
        publish_federation_event,
    )
    await publish_federation_event(
        db,
        org_id=org_id,
        event_type=EVENT_AGENT_REVOKED,
        payload={
            "agent_id": agent_id,
            "serial_hex": serial_hex,
            "reason": reason,
        },
    )

    await db.commit()

    # Fetch the inserted record to return
    fetch_result = await db.execute(
        select(RevokedCert).where(RevokedCert.serial_hex == serial_hex)
    )
    record = fetch_result.scalar_one()
    return record


async def list_revoked_certs(
    db: AsyncSession,
    org_id: str | None = None,
) -> list[RevokedCert]:
    """Return all revoked certificates, optionally filtered by org."""
    query = select(RevokedCert)
    if org_id:
        query = query.where(RevokedCert.org_id == org_id)
    result = await db.execute(query)
    return list(result.scalars().all())
