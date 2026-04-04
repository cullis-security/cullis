"""
Certificate revocation — blocco di certificati x509 compromessi.

Un certificato revocato viene rifiutato al momento dell'autenticazione,
prima della verifica della firma JWT.

Lazy cleanup: i record con cert_not_after < now vengono rimossi ad ogni
inserimento, analogamente alla JTI blacklist.
"""
from datetime import datetime, timezone

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
    Verifica che il certificato non sia stato revocato.
    Solleva HTTPException 401 se presente in revoked_certs.
    """
    result = await db.execute(
        select(RevokedCert).where(RevokedCert.serial_hex == serial_hex)
    )
    if result.scalar_one_or_none() is not None:
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
    Registra un certificato come revocato.
    Esegue lazy cleanup dei record con cert già scaduti.
    Solleva HTTPException 409 se il serial è già revocato.
    """
    now = datetime.now(timezone.utc)

    # Controlla doppia revoca
    result = await db.execute(
        select(RevokedCert).where(RevokedCert.serial_hex == serial_hex)
    )
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Certificate already revoked",
        )

    record = RevokedCert(
        serial_hex=serial_hex,
        org_id=org_id,
        revoked_at=now,
        revoked_by=revoked_by,
        reason=reason,
        cert_not_after=cert_not_after,
        agent_id=agent_id,
    )
    db.add(record)

    # Lazy cleanup: rimuove cert già scaduti (non più pericolosi)
    await db.execute(
        delete(RevokedCert).where(RevokedCert.cert_not_after < now)
    )

    await db.commit()
    await db.refresh(record)
    return record


async def list_revoked_certs(
    db: AsyncSession,
    org_id: str | None = None,
) -> list[RevokedCert]:
    """Restituisce tutti i certificati revocati, opzionalmente filtrati per org."""
    query = select(RevokedCert)
    if org_id:
        query = query.where(RevokedCert.org_id == org_id)
    result = await db.execute(query)
    return list(result.scalars().all())
