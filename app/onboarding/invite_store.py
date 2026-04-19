"""
Invite tokens — gated onboarding for the Cullis trust network.

An admin generates a one-time invite token (the "biglietto da visita").
External orgs must present this token when calling POST /onboarding/join.
Without a valid, unexpired, unused token the endpoint returns 403.
"""
import hashlib
import secrets
from datetime import datetime, timezone, timedelta

from sqlalchemy import Column, String, DateTime, Boolean, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import Base


# Invite types
INVITE_TYPE_ORG_JOIN = "org-join"   # creates a new org (legacy/default)
INVITE_TYPE_ATTACH_CA = "attach-ca"  # uploads CA to an existing org (org_id in linked_org_id)

VALID_INVITE_TYPES = {INVITE_TYPE_ORG_JOIN, INVITE_TYPE_ATTACH_CA}


class InviteToken(Base):
    __tablename__ = "invite_tokens"

    id = Column(String(64), primary_key=True)
    token_hash = Column(String(128), nullable=False, unique=True, index=True)
    label = Column(String(256), nullable=False, default="")
    created_at = Column(DateTime(timezone=True), nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    used_by_org_id = Column(String(128), nullable=True)
    revoked = Column(Boolean, default=False, nullable=False)
    invite_type = Column(String(32), nullable=False, default=INVITE_TYPE_ORG_JOIN,
                         server_default=INVITE_TYPE_ORG_JOIN)
    linked_org_id = Column(String(128), nullable=True, index=True)


def _hash_token(token: str) -> str:
    """SHA-256 hash of the plaintext token (we never store plaintext)."""
    return hashlib.sha256(token.encode()).hexdigest()


async def create_invite(
    db: AsyncSession,
    *,
    label: str = "",
    ttl_hours: int = 72,
    invite_type: str = INVITE_TYPE_ORG_JOIN,
    linked_org_id: str | None = None,
) -> tuple[InviteToken, str]:
    """
    Generate a new invite token.

    Returns (record, plaintext_token). The plaintext is shown once to the
    admin and never stored — only the SHA-256 hash is persisted.

    For attach-ca invites, linked_org_id MUST be set to the target org_id;
    the invite is then only usable to upload a CA for that specific org.
    """
    if invite_type not in VALID_INVITE_TYPES:
        raise ValueError(f"Unknown invite_type: {invite_type!r}")
    if invite_type == INVITE_TYPE_ATTACH_CA and not linked_org_id:
        raise ValueError("attach-ca invites require linked_org_id")
    if invite_type == INVITE_TYPE_ORG_JOIN and linked_org_id is not None:
        raise ValueError("org-join invites must not set linked_org_id")

    plaintext = secrets.token_urlsafe(32)
    record = InviteToken(
        id=secrets.token_hex(16),
        token_hash=_hash_token(plaintext),
        label=label,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=ttl_hours),
        invite_type=invite_type,
        linked_org_id=linked_org_id,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record, plaintext


async def validate_and_consume(
    db: AsyncSession,
    plaintext_token: str,
    org_id: str,
    expected_type: str = INVITE_TYPE_ORG_JOIN,
) -> InviteToken | None:
    """
    Validate an invite token and mark it as consumed.

    Returns the record if valid, None otherwise.
    Token is consumed atomically — a second call with the same token fails
    (audit F-B-17). Mirrors the F-B-4 atomic-consume pattern from
    ``app.kms.admin_secret.consume_bootstrap_token_and_set_password``: a
    single ``UPDATE ... WHERE used = FALSE ... RETURNING *`` is the only
    write that matters; two concurrent callers cannot both win.

    For attach-ca invites the token's linked_org_id must equal the provided
    org_id; the org_id is NEVER trusted from the client alone.
    """
    from sqlalchemy import update as sa_update

    h = _hash_token(plaintext_token)
    now = datetime.now(timezone.utc)

    # Atomic consume: UPDATE WHERE used=false AND revoked=false AND type matches
    # AND expires_at > now RETURNING *. Putting the expiry check inside the
    # same UPDATE (audit F-B-17) removes the legacy rollback branch that
    # would set used=False again on an expired race — that branch could
    # mask concurrent valid consumption attempts under adverse clock drift.
    where_clauses = [
        InviteToken.token_hash == h,
        InviteToken.used == False,  # noqa: E712
        InviteToken.revoked == False,  # noqa: E712
        InviteToken.invite_type == expected_type,
        InviteToken.expires_at > now,
    ]
    if expected_type == INVITE_TYPE_ATTACH_CA:
        # Attach-ca tokens are bound to a specific org — require match.
        where_clauses.append(InviteToken.linked_org_id == org_id)

    # synchronize_session=False: the ORM "evaluate" pass trips over
    # naive-vs-aware datetime comparisons on SQLite; the UPDATE+RETURNING
    # already gives us the authoritative row straight from the DB.
    stmt = (
        sa_update(InviteToken)
        .where(*where_clauses)
        .values(used=True, used_at=now, used_by_org_id=org_id)
        .returning(InviteToken)
        .execution_options(synchronize_session=False)
    )
    result = await db.execute(stmt)
    record = result.scalar_one_or_none()

    if record is None:
        return None

    await db.commit()
    await db.refresh(record)
    return record


async def inspect_invite(
    db: AsyncSession,
    plaintext_token: str,
) -> InviteToken | None:
    """
    Look up an invite WITHOUT consuming it.

    Used by clients (e.g. the MCP proxy setup wizard) to decide which flow
    to run (join vs attach). Returns None if token is unknown, revoked,
    already used, or expired — callers should treat None as "invalid".
    """
    now = datetime.now(timezone.utc)
    h = _hash_token(plaintext_token)
    result = await db.execute(
        select(InviteToken).where(InviteToken.token_hash == h)
    )
    record = result.scalar_one_or_none()
    if record is None or record.used or record.revoked:
        return None
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now > expires_at:
        return None
    return record


async def revoke_invite(db: AsyncSession, invite_id: str) -> InviteToken | None:
    """Revoke an unused invite token."""
    result = await db.execute(
        select(InviteToken).where(InviteToken.id == invite_id)
    )
    record = result.scalar_one_or_none()
    if record is None:
        return None
    record.revoked = True
    await db.commit()
    await db.refresh(record)
    return record


async def list_invites(db: AsyncSession) -> list[InviteToken]:
    """List all invite tokens (newest first)."""
    result = await db.execute(
        select(InviteToken).order_by(InviteToken.created_at.desc())
    )
    return list(result.scalars().all())
