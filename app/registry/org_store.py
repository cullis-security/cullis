"""
ORM model and queries for the organization registry.

DEPRECATION NOTE (ADR-001, network-admin-only refactor)
-------------------------------------------------------
The columns ``oidc_issuer_url``, ``oidc_client_id`` and
``oidc_client_secret`` on ``OrganizationRecord`` are now dead data. The
broker dashboard no longer honors per-org OIDC (tenant login moved to
the proxy), so nothing reads or writes those columns from the broker
codebase anymore. The columns and the legacy ``oidc_enabled`` property
are retained purely for schema stability — dropping them requires an
Alembic migration and coordination with any historical backups, which
we deliberately defer.

Similarly, ``metadata_json['oidc_role_mapping']`` is no longer consumed
by any code path. The helpers that used to read/write it were removed.
"""
import json
import bcrypt
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, String, Text, select
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
    # DEPRECATED: per-org OIDC settings. Kept on the schema for backward
    # compatibility; never read/written by current broker code. See module
    # docstring for rationale.
    oidc_issuer_url = Column(String(512), nullable=True)
    oidc_client_id = Column(String(256), nullable=True)
    oidc_client_secret = Column(String(512), nullable=True)
    # SPIFFE trust domain of the org, for SVID-only auth (no CN/O in cert).
    # Nullable so legacy orgs keep working via CN/O-based agent certs.
    trust_domain = Column(String(256), nullable=True, unique=True, index=True)
    # ADR-009 — mastio/proxy ES256 public key (PEM), pinned at onboarding.
    # Phase 4 made its presence the sole contract: NULL means "onboarding
    # incomplete — Court refuses /v1/auth/token for this org". Orgs always
    # enforce ``X-Cullis-Mastio-Signature`` once this is set.
    mastio_pubkey = Column(Text, nullable=True)
    # Audit F-B-2 — "tenant-sealed" flag. True means the org was onboarded
    # via the attach-ca flow (or manually sealed by the admin), and
    # dashboard mutations require a short-lived per-org re-auth gate on
    # top of the admin session. False = legacy behavior (plain admin
    # session allows every mutation). See app/dashboard/router.py for
    # the enforcement and unseal flow.
    sealed = Column(Boolean, nullable=False, default=False, server_default="0")

    def verify_secret(self, plain: str) -> bool:
        return bcrypt.checkpw(plain.encode(), self.secret_hash.encode())

    @property
    def extra(self) -> dict:
        return json.loads(self.metadata_json)


# Pre-computed dummy hash to ensure constant-time org secret verification
# even when the org does not exist (prevents timing-based org enumeration).
_DUMMY_HASH: str = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12)).decode()


def verify_org_credentials(org: "OrganizationRecord | None", secret: str) -> bool:
    """Verify org secret in constant time regardless of whether the org exists."""
    if org is None or org.status != "active":
        # Always run bcrypt to prevent timing leaks
        bcrypt.checkpw(secret.encode(), _DUMMY_HASH.encode())
        return False
    return org.verify_secret(secret)


async def register_org(
    db: AsyncSession,
    org_id: str,
    display_name: str,
    secret: str,
    metadata: dict | None = None,
    webhook_url: str | None = None,
    status: str = "active",
    trust_domain: str | None = None,
    mastio_pubkey: str | None = None,
) -> OrganizationRecord:
    record = OrganizationRecord(
        org_id=org_id,
        display_name=display_name,
        secret_hash=bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode(),
        metadata_json=json.dumps(metadata or {}),
        webhook_url=webhook_url,
        status=status,
        trust_domain=trust_domain,
        mastio_pubkey=mastio_pubkey,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def get_org_by_trust_domain(
    db: AsyncSession, trust_domain: str
) -> OrganizationRecord | None:
    result = await db.execute(
        select(OrganizationRecord).where(OrganizationRecord.trust_domain == trust_domain)
    )
    return result.scalar_one_or_none()


async def update_org_trust_domain(
    db: AsyncSession,
    org_id: str,
    trust_domain: str,
) -> OrganizationRecord | None:
    record = await get_org_by_id(db, org_id)
    if record is None:
        return None
    record.trust_domain = trust_domain
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


async def update_org_secret(
    db: AsyncSession,
    org_id: str,
    new_secret: str,
) -> OrganizationRecord | None:
    """Replace the org secret with a fresh bcrypt hash."""
    record = await get_org_by_id(db, org_id)
    if record is None:
        return None
    record.secret_hash = bcrypt.hashpw(new_secret.encode(), bcrypt.gensalt()).decode()
    await db.commit()
    await db.refresh(record)
    return record


async def set_org_sealed(
    db: AsyncSession,
    org_id: str,
    sealed: bool,
) -> OrganizationRecord | None:
    """Flip the F-B-2 tenant-sealed flag on an org.

    Called at attach-ca consume time (``sealed=True``) and from the
    admin dashboard when the operator explicitly seals/unseals an org.
    The sealed state gates dashboard mutations behind a per-org re-auth
    challenge; see ``app/dashboard/router.py`` for the enforcement.
    """
    record = await get_org_by_id(db, org_id)
    if record is None:
        return None
    record.sealed = bool(sealed)
    await db.commit()
    await db.refresh(record)
    return record


async def update_org_mastio_pubkey(
    db: AsyncSession,
    org_id: str,
    mastio_pubkey: str | None,
) -> OrganizationRecord | None:
    """Pin or clear the mastio ES256 counter-signature public key (ADR-009)."""
    record = await get_org_by_id(db, org_id)
    if record is None:
        return None
    record.mastio_pubkey = mastio_pubkey
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


# update_org_oidc / get_org_oidc_secret / get_oidc_role_mapping /
# update_org_oidc_role_mapping were removed — per-org OIDC mapping is no
# longer handled on the broker. See the module docstring.


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
