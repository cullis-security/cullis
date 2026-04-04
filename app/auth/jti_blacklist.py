"""
JTI blacklist for client_assertion — replay attack protection.

Each JTI is recorded on first use together with its expiry (JWT exp).
Subsequent attempts with the same JTI are rejected with 401.

Lazy cleanup: expired records are removed on each insertion.
"""
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import Column, String, DateTime, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


class JtiBlacklist(Base):
    __tablename__ = "jti_blacklist"

    jti        = Column(String(128), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)


async def check_and_consume_jti(db: AsyncSession, jti: str, expires_at: datetime) -> None:
    """
    Verify that the JTI has not already been used, then register it.

    - If the JTI is already present (even expired) → 401 replay attack.
    - If not present → insert the record and clean up expired JTIs.

    Raises HTTPException 401 if a replay is detected.
    """
    now = datetime.now(timezone.utc)

    # Check presence (including expired — better to be conservative)
    result = await db.execute(
        select(JtiBlacklist).where(JtiBlacklist.jti == jti)
    )
    existing = result.scalar_one_or_none()

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client_assertion already used (replay attack detected)",
        )

    # Register the JTI
    db.add(JtiBlacklist(jti=jti, expires_at=expires_at))

    # Lazy cleanup: remove all expired JTIs
    await db.execute(
        delete(JtiBlacklist).where(JtiBlacklist.expires_at < now)
    )

    await db.commit()
