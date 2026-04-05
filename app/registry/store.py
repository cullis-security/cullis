"""
ORM model and queries for the agent registry.
"""
import hashlib
import hmac
import json
import bcrypt
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import Column, String, Boolean, DateTime, Text, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


def _hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()


def _verify_secret(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


class AgentRecord(Base):
    __tablename__ = "agents"

    agent_id = Column(String(256), primary_key=True, index=True)
    org_id = Column(String(128), nullable=False, index=True)
    display_name = Column(String(256), nullable=False)
    secret_hash = Column(String(256), nullable=True)
    capabilities_json = Column(Text, default="[]")
    metadata_json = Column(Text, default="{}")
    is_active = Column(Boolean, default=True, nullable=False)
    registered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    cert_pem = Column(Text, nullable=True)   # Agent x509 certificate — pinned on first login
    cert_thumbprint = Column(String(64), nullable=True)  # SHA-256 of DER cert — anti Rogue CA pinning
    token_invalidated_at = Column(DateTime(timezone=True), nullable=True)  # tokens with iat <= this are rejected

    @property
    def capabilities(self) -> list[str]:
        return json.loads(self.capabilities_json)

    @property
    def extra(self) -> dict:
        return json.loads(self.metadata_json)

    def verify_secret(self, plain: str) -> bool:
        return _verify_secret(plain, self.secret_hash)


async def register_agent(db: AsyncSession, agent_id: str, org_id: str, display_name: str,
                          capabilities: list[str], metadata: dict,
                          secret: str | None = None) -> AgentRecord:
    record = AgentRecord(
        agent_id=agent_id,
        org_id=org_id,
        display_name=display_name,
        secret_hash=_hash_secret(secret) if secret else None,
        capabilities_json=json.dumps(capabilities),
        metadata_json=json.dumps(metadata),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def get_agent_by_id(db: AsyncSession, agent_id: str) -> AgentRecord | None:
    result = await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))
    return result.scalar_one_or_none()


def compute_cert_thumbprint(cert_pem: str) -> str:
    """Compute SHA-256 thumbprint of a PEM certificate (hex digest of its DER encoding)."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cert_der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(cert_der).hexdigest()


async def update_agent_cert(db: AsyncSession, agent_id: str, cert_pem: str,
                             thumbprint: str) -> bool:
    """
    Pin or verify the agent's certificate thumbprint.

    First login (cert_thumbprint is None): stores cert + thumbprint (pin).
    Subsequent logins with same cert: updates cert_pem (idempotent).
    Different cert: returns False (thumbprint mismatch — use rotate endpoint).

    Before pinning, checks that the certificate has not been revoked.
    """
    from app.auth.revocation import check_cert_not_revoked
    from cryptography import x509 as _x509

    # Check revocation before pinning or accepting the cert
    cert_obj = _x509.load_pem_x509_certificate(cert_pem.encode())
    serial_hex = format(cert_obj.serial_number, 'x')
    await check_cert_not_revoked(db, serial_hex)

    agent = await get_agent_by_id(db, agent_id)
    if agent is None:
        return False
    if agent.cert_thumbprint is None:
        # First login — pin the certificate
        agent.cert_pem = cert_pem
        agent.cert_thumbprint = thumbprint
        await db.commit()
        return True
    if hmac.compare_digest(agent.cert_thumbprint, thumbprint):
        # Same cert — idempotent update
        agent.cert_pem = cert_pem
        await db.commit()
        return True
    # Thumbprint mismatch — rogue cert or rotation needed
    return False


async def rotate_agent_cert(db: AsyncSession, agent_id: str, new_cert_pem: str) -> str:
    """
    Rotate an agent's pinned certificate. Called only from explicit rotate endpoints.
    Returns the new thumbprint. Also invalidates active tokens.
    """
    agent = await get_agent_by_id(db, agent_id)
    if agent is None:
        raise ValueError(f"Agent '{agent_id}' not found")
    new_thumbprint = compute_cert_thumbprint(new_cert_pem)
    _old_thumbprint = agent.cert_thumbprint
    agent.cert_pem = new_cert_pem
    agent.cert_thumbprint = new_thumbprint
    agent.token_invalidated_at = datetime.now(timezone.utc).replace(microsecond=0)
    await db.commit()
    return new_thumbprint


async def invalidate_agent_tokens(db: AsyncSession, agent_id: str) -> None:
    """
    Invalidate all currently active access tokens for agent_id.

    Sets token_invalidated_at to the current second boundary. Any token with
    iat <= token_invalidated_at will be rejected by get_current_agent.
    Tokens issued after this call (new logins) are unaffected.
    """
    agent = await get_agent_by_id(db, agent_id)
    if agent is not None:
        agent.token_invalidated_at = datetime.now(timezone.utc).replace(microsecond=0)
        await db.commit()


async def list_agents(db: AsyncSession, org_id: str | None = None) -> list[AgentRecord]:
    query = select(AgentRecord)
    if org_id:
        query = query.where(AgentRecord.org_id == org_id)
    result = await db.execute(query)
    return list(result.scalars().all())


async def search_agents_by_capabilities(
    db: AsyncSession,
    capabilities: list[str],
    exclude_org_id: str | None = None,
) -> list[AgentRecord]:
    """Return active agents that have ALL the requested capabilities."""
    result = await db.execute(
        select(AgentRecord).where(AgentRecord.is_active.is_(True))
    )
    agents = result.scalars().all()

    def has_all(agent: AgentRecord) -> bool:
        agent_caps = set(agent.capabilities)
        return all(c in agent_caps for c in capabilities)

    return [
        a for a in agents
        if has_all(a) and (exclude_org_id is None or a.org_id != exclude_org_id)
    ]
