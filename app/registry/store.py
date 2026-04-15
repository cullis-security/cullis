"""
ORM model and queries for the agent registry.
"""
import hashlib
import hmac
import json
import bcrypt
from fnmatch import fnmatch
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import Column, String, Boolean, DateTime, Text, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base
from app.spiffe import internal_id_to_spiffe, spiffe_to_internal_id


def _hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()


def _verify_secret(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


class AgentRecord(Base):
    __tablename__ = "agents"

    agent_id = Column(String(256), primary_key=True, index=True)
    org_id = Column(String(128), nullable=False, index=True)
    display_name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True, default="")
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
                          secret: str | None = None,
                          description: str = "") -> AgentRecord:
    from app.broker.federation import (
        EVENT_AGENT_REGISTERED,
        publish_federation_event,
    )

    record = AgentRecord(
        agent_id=agent_id,
        org_id=org_id,
        display_name=display_name,
        description=description,
        secret_hash=_hash_secret(secret) if secret else None,
        capabilities_json=json.dumps(capabilities),
        metadata_json=json.dumps(metadata),
    )
    db.add(record)
    await db.flush()
    await publish_federation_event(
        db,
        org_id=org_id,
        event_type=EVENT_AGENT_REGISTERED,
        payload={
            "agent_id": agent_id,
            "display_name": display_name,
            "capabilities": capabilities,
        },
    )
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


async def refresh_agent_cert_svid(
    db: AsyncSession, agent_id: str, cert_pem: str, thumbprint: str,
) -> bool:
    """
    Refresh the agent's stored cert without enforcing thumbprint pinning.

    Used when the caller authenticated in SPIFFE/SVID mode: the leaf cert
    rotates on a short schedule (SPIRE default ~1h), so pinning would
    reject every second login. Identity is still bound by the chain walk
    and the SPIFFE URI match — see ADR-003 §2.3. The broker still needs a
    current cert_pem to verify outbound message signatures, so we overwrite
    it on every SPIFFE-mode token issuance.

    Returns True on success, False if the agent record is missing.
    """
    from app.auth.revocation import check_cert_not_revoked
    from cryptography import x509 as _x509

    cert_obj = _x509.load_pem_x509_certificate(cert_pem.encode())
    serial_hex = format(cert_obj.serial_number, 'x')
    await check_cert_not_revoked(db, serial_hex)

    agent = await get_agent_by_id(db, agent_id)
    if agent is None:
        return False
    agent.cert_pem = cert_pem
    agent.cert_thumbprint = thumbprint
    await db.commit()
    return True


async def rotate_agent_cert(db: AsyncSession, agent_id: str, new_cert_pem: str) -> str:
    """
    Rotate an agent's pinned certificate. Called only from explicit rotate endpoints.
    Returns the new thumbprint. Also invalidates active tokens.
    """
    from app.broker.federation import (
        EVENT_AGENT_ROTATED,
        publish_federation_event,
    )

    agent = await get_agent_by_id(db, agent_id)
    if agent is None:
        raise ValueError(f"Agent '{agent_id}' not found")
    new_thumbprint = compute_cert_thumbprint(new_cert_pem)
    _old_thumbprint = agent.cert_thumbprint
    agent.cert_pem = new_cert_pem
    agent.cert_thumbprint = new_thumbprint
    agent.token_invalidated_at = datetime.now(timezone.utc).replace(microsecond=0)
    await publish_federation_event(
        db,
        org_id=agent.org_id,
        event_type=EVENT_AGENT_ROTATED,
        payload={
            "agent_id": agent_id,
            "thumbprint": new_thumbprint,
        },
    )
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


async def search_agents(
    db: AsyncSession,
    *,
    capabilities: list[str] | None = None,
    agent_id: str | None = None,
    agent_uri: str | None = None,
    org_id: str | None = None,
    pattern: str | None = None,
    q: str | None = None,
    exclude_org_id: str | None = None,
    trust_domain: str = "cullis.local",
) -> list["AgentRecord"]:
    """Unified agent search with multiple optional filters.

    - agent_id / agent_uri: direct lookup (returns 0 or 1 agent)
    - org_id: all active agents in that org
    - pattern: glob on agent_id (e.g. "italmetal::*")
    - capabilities: AND filter on agent capabilities
    All filters are intersected. At least one must be provided.
    """
    # Direct lookup by SPIFFE URI → convert to internal id
    if agent_uri and not agent_id:
        try:
            agent_id = spiffe_to_internal_id(agent_uri)
        except ValueError:
            return []

    # Direct lookup by agent_id
    if agent_id:
        agent = await get_agent_by_id(db, agent_id)
        if not agent or not agent.is_active:
            return []
        if capabilities:
            caps = set(agent.capabilities)
            if not all(c in caps for c in capabilities):
                return []
        return [agent]

    # Broad search: fetch all active agents, then filter
    result = await db.execute(
        select(AgentRecord).where(AgentRecord.is_active.is_(True))
    )
    agents = list(result.scalars().all())

    # Filter by org_id
    if org_id:
        agents = [a for a in agents if a.org_id == org_id]

    # Filter by pattern (glob on agent_id or SPIFFE URI)
    if pattern:
        def _matches(a: AgentRecord) -> bool:
            if fnmatch(a.agent_id, pattern):
                return True
            try:
                spiffe = internal_id_to_spiffe(a.agent_id, trust_domain)
                return fnmatch(spiffe, pattern)
            except ValueError:
                return False
        agents = [a for a in agents if _matches(a)]

    # Filter by capabilities (AND)
    if capabilities:
        def _has_all(a: AgentRecord) -> bool:
            agent_caps = set(a.capabilities)
            return all(c in agent_caps for c in capabilities)
        agents = [a for a in agents if _has_all(a)]

    # Free-text search across display_name, description, agent_id, org_id
    if q:
        q_lower = q.lower()
        def _text_match(a: AgentRecord) -> bool:
            return (q_lower in a.agent_id.lower()
                    or q_lower in a.display_name.lower()
                    or q_lower in a.org_id.lower()
                    or (a.description and q_lower in a.description.lower()))
        agents = [a for a in agents if _text_match(a)]

    # Exclude own org (unless direct lookup)
    if exclude_org_id:
        agents = [a for a in agents if a.org_id != exclude_org_id]

    return agents
