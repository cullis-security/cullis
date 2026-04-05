"""
JTI blacklist for client_assertion — replay attack protection.

Each JTI is recorded on first use together with its expiry (JWT exp).
Subsequent attempts with the same JTI are rejected with 401.

Lazy cleanup: expired records are removed on each insertion.
"""
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import Column, String, DateTime, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


class JtiBlacklist(Base):
    __tablename__ = "jti_blacklist"

    jti        = Column(String(128), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)


async def check_and_consume_jti(db: AsyncSession, jti: str, expires_at: datetime) -> None:
    """
    Verify that the JTI has not already been used, then register it.

    Uses an atomic INSERT … ON CONFLICT DO NOTHING to avoid TOCTOU race
    conditions: two concurrent requests with the same JTI cannot both succeed.

    Raises HTTPException 401 if a replay is detected.
    """
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    now = datetime.now(timezone.utc)

    # Atomic upsert: try to insert — if the JTI already exists the insert
    # is silently skipped (rowcount == 0) and we reject the request.
    dialect_name = db.bind.dialect.name if db.bind else "unknown"

    if dialect_name == "postgresql":
        stmt = pg_insert(JtiBlacklist).values(jti=jti, expires_at=expires_at)
        stmt = stmt.on_conflict_do_nothing(index_elements=["jti"])
    else:
        # SQLite (used in tests) also supports INSERT OR IGNORE
        stmt = sqlite_insert(JtiBlacklist).values(jti=jti, expires_at=expires_at)
        stmt = stmt.on_conflict_do_nothing(index_elements=["jti"])

    result = await db.execute(stmt)

    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client_assertion already used (replay attack detected)",
        )

    # Lazy cleanup: remove all expired JTIs (including boundary)
    await db.execute(
        delete(JtiBlacklist).where(JtiBlacklist.expires_at <= now)
    )

    await db.commit()
