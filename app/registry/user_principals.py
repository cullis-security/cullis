"""User principal mapping (ADR-021 PR2).

Bridges SSO identity (``mario@acme.it``) to a Cullis principal id
(``acme.test/acme/user/mario``) and tracks provisioning state. The
Cullis Frontdesk Ambassador (PR4) calls this layer at the start of
every authenticated session:

    1. ``GET /v1/principals/by-sso?org=acme&subject=mario@acme.it``
    2. if 404 → provision via the KMS (PR1) and ``create()`` here
    3. if 200 → use the returned ``principal_id`` directly

The table is the source of truth for "is this user already
provisioned?". The KMS holds the keys; this table holds the
metadata + the link to the KMS key handle.

Cert columns are nullable until the Ambassador completes the CSR
roundtrip (``KMS.create_keypair`` → Mastio CSR signing →
``KMS.attach_certificate`` → ``attach_cert()`` here). A row with
NULL ``cert_thumbprint`` means provisioning is mid-flight.

``revoked_at`` flips the row to a tombstone instead of deleting it
so audit replay can resolve the historical SSO→principal mapping.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Column, DateTime, Index, String, UniqueConstraint, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base

_log = logging.getLogger("agent_trust")


# ── Model ──────────────────────────────────────────────────────────


class UserPrincipalRecord(Base):
    """SQLAlchemy model for the ``user_principals`` table.

    See ``alembic/versions/o5j6k7l8m9n0_user_principals.py`` for the
    canonical schema. Kept legacy ``Column`` style for symmetry with
    the surrounding registry modules.
    """

    __tablename__ = "user_principals"
    __table_args__ = (
        UniqueConstraint(
            "org_id", "sso_subject", name="uq_user_principals_org_sso",
        ),
        Index(
            "idx_user_principals_lookup",
            "org_id", "sso_subject",
        ),
        # cert_thumbprint lookup powers cert-rotation, revocation and
        # TOFU-pin verification; mirrored in
        # alembic/versions/t0o1p2q3r4s5_idx_thumbprint.py.
        Index(
            "idx_user_principals_cert_thumbprint",
            "cert_thumbprint",
        ),
        # F-A-201 audit 2026-05-20 — pubkey TOFU lookup index. Mirrors
        # the cert_thumbprint index pattern; nullable so legacy rows
        # are silently skipped.
        Index(
            "idx_user_principals_pubkey_thumbprint",
            "pubkey_thumbprint",
        ),
    )

    principal_id     = Column(String(255), primary_key=True)
    org_id           = Column(String(128), nullable=False)
    sso_subject      = Column(String(255), nullable=False)
    display_name     = Column(String(255), nullable=True)
    cert_thumbprint  = Column(String(64),  nullable=True)
    cert_not_after   = Column(DateTime(timezone=True), nullable=True)
    # F-A-201 (audit 2026-05-20). TOFU pubkey pin: SHA-256 of the CSR's
    # SubjectPublicKeyInfo DER. Stable across cert rotations (the
    # Ambassador re-uses its keypair). sign_user_csr records this on
    # first signature and refuses subsequent CSRs that present a
    # different SPKI for the same principal_id. NULL = first-touch
    # window before any CSR has landed; nullable to preserve TOFU
    # semantics on legacy rows that predate migration u1p2q3r4s5t6.
    pubkey_thumbprint = Column(String(64), nullable=True)
    kms_backend      = Column(String(32),  nullable=False)
    kms_key_handle   = Column(String(255), nullable=False)
    provisioned_at   = Column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_active_at   = Column(DateTime(timezone=True), nullable=True)
    revoked_at       = Column(DateTime(timezone=True), nullable=True)


# ── Errors ─────────────────────────────────────────────────────────


class DuplicatePrincipalError(ValueError):
    """Raised when a ``(org_id, sso_subject)`` collision is detected
    or when ``principal_id`` is reused."""


# ── DTO ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class UserPrincipalView:
    """Read-only projection used by the router and external callers.

    The SQLAlchemy model is intentionally not exposed across module
    boundaries: it carries hidden state (the session) that callers
    should not depend on. ``UserPrincipalView`` is a plain dataclass
    safe to serialise.
    """

    principal_id: str
    org_id: str
    sso_subject: str
    display_name: Optional[str]
    cert_thumbprint: Optional[str]
    cert_not_after: Optional[datetime]
    kms_backend: str
    kms_key_handle: str
    provisioned_at: datetime
    last_active_at: Optional[datetime]
    revoked_at: Optional[datetime]

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    @property
    def is_provisioned(self) -> bool:
        """True once a cert has been attached."""
        return self.cert_thumbprint is not None


def _to_view(row: UserPrincipalRecord) -> UserPrincipalView:
    return UserPrincipalView(
        principal_id=row.principal_id,
        org_id=row.org_id,
        sso_subject=row.sso_subject,
        display_name=row.display_name,
        cert_thumbprint=row.cert_thumbprint,
        cert_not_after=row.cert_not_after,
        kms_backend=row.kms_backend,
        kms_key_handle=row.kms_key_handle,
        provisioned_at=row.provisioned_at,
        last_active_at=row.last_active_at,
        revoked_at=row.revoked_at,
    )


# ── CRUD ───────────────────────────────────────────────────────────


async def create(
    session: AsyncSession,
    *,
    principal_id: str,
    org_id: str,
    sso_subject: str,
    kms_backend: str,
    kms_key_handle: str,
    display_name: Optional[str] = None,
) -> UserPrincipalView:
    """Insert a fresh user principal row.

    Raises ``DuplicatePrincipalError`` on either of:
      - ``principal_id`` collision (PK)
      - ``(org_id, sso_subject)`` collision (UNIQUE)

    Cert fields stay NULL until ``attach_cert`` is called.
    """
    if not principal_id or not org_id or not sso_subject:
        raise ValueError(
            "principal_id, org_id, sso_subject are all required",
        )
    if not kms_backend or not kms_key_handle:
        raise ValueError("kms_backend and kms_key_handle are required")

    record = UserPrincipalRecord(
        principal_id=principal_id,
        org_id=org_id,
        sso_subject=sso_subject,
        display_name=display_name,
        kms_backend=kms_backend,
        kms_key_handle=kms_key_handle,
        provisioned_at=datetime.now(timezone.utc),
    )
    session.add(record)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise DuplicatePrincipalError(
            f"principal_id={principal_id!r} or "
            f"(org_id={org_id!r}, sso_subject={sso_subject!r}) already exists",
        ) from exc
    return _to_view(record)


async def get_by_principal_id(
    session: AsyncSession, principal_id: str,
) -> Optional[UserPrincipalView]:
    """Return the row for an exact principal_id, or None."""
    if not principal_id:
        return None
    row = (
        await session.execute(
            select(UserPrincipalRecord).where(
                UserPrincipalRecord.principal_id == principal_id,
            ),
        )
    ).scalar_one_or_none()
    return _to_view(row) if row else None


async def get_by_sso(
    session: AsyncSession,
    *,
    org_id: str,
    sso_subject: str,
) -> Optional[UserPrincipalView]:
    """Look up a principal by its SSO identity within an org.

    This is the hot path for the Ambassador on every authenticated
    request. The composite UNIQUE on ``(org_id, sso_subject)``
    guarantees at most one row.
    """
    if not org_id or not sso_subject:
        return None
    row = (
        await session.execute(
            select(UserPrincipalRecord).where(
                UserPrincipalRecord.org_id == org_id,
                UserPrincipalRecord.sso_subject == sso_subject,
            ),
        )
    ).scalar_one_or_none()
    return _to_view(row) if row else None


async def attach_cert(
    session: AsyncSession,
    *,
    principal_id: str,
    cert_thumbprint: str,
    cert_not_after: datetime,
) -> Optional[UserPrincipalView]:
    """Attach the cert metadata after the CSR roundtrip completes.

    Re-attaching is a normal cert rotation; the call is idempotent
    on the column values. Returns the updated view, or ``None`` if
    the principal does not exist.
    """
    if not cert_thumbprint or len(cert_thumbprint) > 64:
        raise ValueError("cert_thumbprint must be 1-64 chars")
    cur = await session.execute(
        update(UserPrincipalRecord)
        .where(UserPrincipalRecord.principal_id == principal_id)
        .values(
            cert_thumbprint=cert_thumbprint,
            cert_not_after=cert_not_after,
        ),
    )
    if cur.rowcount == 0:
        return None
    await session.flush()
    return await get_by_principal_id(session, principal_id)


async def get_pubkey_thumbprint(
    session: AsyncSession,
    principal_id: str,
) -> tuple[bool, Optional[str]]:
    """F-A-201 (audit 2026-05-20). TOFU pubkey lookup for a user
    principal, mirroring the Mastio
    ``mcp_proxy.db.get_user_principal_pubkey_thumbprint``.

    Returns ``(exists, pubkey_thumbprint)``:
      - ``(False, None)`` — no row for ``principal_id``. Caller
        (``sign_user_csr``) treats this as first-touch and persists the
        CSR's SPKI digest after signature.
      - ``(True, None)`` — row exists but no pubkey pinned yet (legacy
        row predating migration u1p2q3r4s5t6, or admin-pre-created).
        First CSR roundtrip records the SPKI.
      - ``(True, "<sha256_hex>")`` — pinned. Caller compares to the
        presented CSR pubkey and refuses on mismatch.
    """
    row = await session.execute(
        select(UserPrincipalRecord.pubkey_thumbprint)
        .where(UserPrincipalRecord.principal_id == principal_id),
    )
    first = row.first()
    if first is None:
        return (False, None)
    return (True, first[0])


async def attach_pubkey_thumbprint(
    session: AsyncSession,
    *,
    principal_id: str,
    pubkey_thumbprint: str,
) -> Optional[UserPrincipalView]:
    """F-A-201 (audit 2026-05-20). Persist the CSR's SPKI digest on
    first signature so subsequent CSRs are TOFU-checked.

    Idempotent on the column value: re-attaching the same thumbprint is
    a no-op write. Mismatch is caller's job (``sign_user_csr`` raises
    ``CsrValidationError`` before reaching this helper).
    """
    if not pubkey_thumbprint or len(pubkey_thumbprint) > 64:
        raise ValueError("pubkey_thumbprint must be 1-64 chars")
    cur = await session.execute(
        update(UserPrincipalRecord)
        .where(UserPrincipalRecord.principal_id == principal_id)
        .values(pubkey_thumbprint=pubkey_thumbprint),
    )
    if cur.rowcount == 0:
        return None
    await session.flush()
    return await get_by_principal_id(session, principal_id)


async def mark_revoked(
    session: AsyncSession,
    principal_id: str,
) -> Optional[UserPrincipalView]:
    """Set ``revoked_at`` to now if not already set. Idempotent.

    Returns the updated view, or ``None`` if the principal does not
    exist. The row is NOT deleted — historical SSO→principal mapping
    must remain queryable for audit replay.
    """
    now = datetime.now(timezone.utc)
    await session.execute(
        update(UserPrincipalRecord)
        .where(
            UserPrincipalRecord.principal_id == principal_id,
            UserPrincipalRecord.revoked_at.is_(None),
        )
        .values(revoked_at=now),
    )
    # The UPDATE is a no-op on missing or already-revoked principals.
    # A follow-up read disambiguates: missing → None, revoked → view
    # whose revoked_at preserves the original timestamp.
    return await get_by_principal_id(session, principal_id)


async def update_last_active(
    session: AsyncSession,
    principal_id: str,
    *,
    when: Optional[datetime] = None,
) -> None:
    """Touch the ``last_active_at`` timestamp.

    Idempotent and silent on missing principal — telemetry should
    never raise.
    """
    ts = when or datetime.now(timezone.utc)
    await session.execute(
        update(UserPrincipalRecord)
        .where(UserPrincipalRecord.principal_id == principal_id)
        .values(last_active_at=ts),
    )


__all__ = [
    "DuplicatePrincipalError",
    "UserPrincipalRecord",
    "UserPrincipalView",
    "attach_cert",
    "create",
    "get_by_principal_id",
    "get_by_sso",
    "mark_revoked",
    "update_last_active",
]
