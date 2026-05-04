"""ADR-020 Phase 3 — reach policy four-quadrant matrix.

Cullis recognises three principal types (agent, user, workload). Every
send is therefore assignable to one of nine cells in a (source × dest)
matrix; eight of them get explicit semantics here. Workloads do not
initiate in v0.1, so the W2* row is always denied.

The matrix this module enforces:

                       destination
                       agent              user               workload
   source
   agent               A2A                A2U                tool call
   user                U2A                U2U                tool call
   workload            (deny v0.1)        (deny v0.1)        (deny v0.1)

with the following defaults:

   intra-org   A2A   allow              (this is the existing oneshot/reply path)
   cross-org   A2A   allow if matching reach exists, otherwise deny
   intra-org   U2A   allow if user owns the agent, otherwise consent gate
   cross-org   U2A   deny  + per-source consent grant required
   intra-org   A2U   deny  + per-source consent grant required
   cross-org   A2U   deny  + per-source consent grant required
   intra-org   U2U   allow              (same domain, SSO already trusts both)
   cross-org   U2U   deny  + per-source consent grant required (addressbook)

A2W / U2W (workload-as-destination) are tool calls and live in the MCP
aggregator authz path (binding gate); reach policy is a no-op for that
quadrant and returns allow.

The consent table is a normal-form authorisation grant: any pending
inbox push checks ``reach_consents`` for an active row that covers
the (source, recipient) pair before delivery; otherwise the message
is rejected at the broker edge with an audit row.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, Literal

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    String,
    UniqueConstraint,
    and_,
    or_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.audit import log_event
from app.db.database import Base

_log = logging.getLogger("app.policy.reach")

# Legal principal-type values — aligned with app/spiffe.py PRINCIPAL_TYPES.
PRINCIPAL_TYPES = ("agent", "user", "workload")
PrincipalType = Literal["agent", "user", "workload"]

# Quadrant labels emitted into audit rows.
Quadrant = Literal["A2A", "A2U", "U2A", "U2U", "A2W", "U2W", "W2A", "W2U", "W2W"]

# Wildcard sentinel for the source-name field of a consent grant. Lets
# a user say "I accept incoming from any agent in org X" without
# enumerating each agent.
ANY_NAME = "*"


# ── Data classes ────────────────────────────────────────────────────


@dataclass(frozen=True)
class PrincipalRef:
    """Reference to one principal (sender or recipient of a reach)."""
    org_id: str
    principal_type: PrincipalType
    name: str


@dataclass(frozen=True)
class ReachContext:
    """The (source, destination) pair under evaluation."""
    source: PrincipalRef
    destination: PrincipalRef

    @property
    def is_intra_org(self) -> bool:
        return self.source.org_id == self.destination.org_id

    @property
    def quadrant(self) -> Quadrant:
        # Two-letter shorthand: source-type initial + "2" + dest-type initial.
        # Workload uses W; agent A; user U.
        s = self.source.principal_type[0].upper()
        d = self.destination.principal_type[0].upper()
        return f"{s}2{d}"  # type: ignore[return-value]


@dataclass(frozen=True)
class PolicyDecision:
    """Result of a reach evaluation, ready to be returned to the caller
    and to be audited via ``log_event``."""
    allowed: bool
    reason: str
    quadrant: Quadrant
    consent_id: str | None = None


# ── Persistence model ───────────────────────────────────────────────


class ReachConsent(Base):
    """A persistent grant: recipient agreed to accept incoming reach
    messages from a specific source (or any source of a given type
    from a given org, when ``source_name`` is the wildcard ``*``).

    Revocation is soft (``revoked_at`` non-null). The unique constraint
    on the full (recipient, source) tuple lets a re-grant after revoke
    UPDATE the existing row back to revoked_at=NULL without piling up
    duplicates — same pattern as ``local_agent_resource_bindings``.
    """
    __tablename__ = "reach_consents"

    consent_id = Column(String(64), primary_key=True)
    recipient_org_id = Column(String(128), nullable=False, index=True)
    recipient_principal_type = Column(String(16), nullable=False)
    recipient_name = Column(String(128), nullable=False)
    source_org_id = Column(String(128), nullable=False)
    source_principal_type = Column(String(16), nullable=False)
    source_name = Column(String(128), nullable=False)  # ANY_NAME = wildcard
    granted_at = Column(DateTime(timezone=True), nullable=False)
    granted_by = Column(String(128), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "recipient_org_id", "recipient_principal_type", "recipient_name",
            "source_org_id", "source_principal_type", "source_name",
            name="uq_reach_consent_pair",
        ),
        Index(
            "idx_reach_consent_recipient_active",
            "recipient_org_id", "recipient_principal_type", "recipient_name",
        ),
    )


OwnershipResolver = Callable[[PrincipalRef, PrincipalRef], Awaitable[bool]]
"""Async predicate: does ``user`` own ``agent``? Resolver is supplied by
the caller (Phase 5 wires this to a registry table). Phase 3 default
is ``False`` if no resolver is supplied — callers in v0.1 are agents,
not users-acting-on-their-agents."""


# ── Evaluation ──────────────────────────────────────────────────────


async def _has_active_consent(
    db: AsyncSession, ctx: ReachContext,
) -> str | None:
    """Return ``consent_id`` of an active grant covering ``ctx``, or None.

    Matches a specific source name first, then falls back to a wildcard
    grant (``source_name=ANY_NAME``).
    """
    stmt = select(ReachConsent).where(
        and_(
            ReachConsent.recipient_org_id == ctx.destination.org_id,
            ReachConsent.recipient_principal_type == ctx.destination.principal_type,
            ReachConsent.recipient_name == ctx.destination.name,
            ReachConsent.source_org_id == ctx.source.org_id,
            ReachConsent.source_principal_type == ctx.source.principal_type,
            or_(
                ReachConsent.source_name == ctx.source.name,
                ReachConsent.source_name == ANY_NAME,
            ),
            ReachConsent.revoked_at.is_(None),
        )
    ).order_by(
        # Specific name beats wildcard when both exist for the same pair.
        ReachConsent.source_name.desc(),
    ).limit(1)
    row = (await db.execute(stmt)).scalar_one_or_none()
    return row.consent_id if row else None


async def evaluate_reach_quadrant(
    db: AsyncSession,
    ctx: ReachContext,
    *,
    ownership_resolver: OwnershipResolver | None = None,
    audit_session_id: str | None = None,
) -> PolicyDecision:
    """Decide whether ``ctx`` is permitted by the four-quadrant matrix.

    Side effects:
      - emits a ``policy.reach_evaluated`` audit row on every call (one
        per evaluation), tagged with the resolved quadrant.
    """
    quadrant = ctx.quadrant

    # ── W2* — workloads do not initiate in v0.1 ────────────────────
    if ctx.source.principal_type == "workload":
        decision = PolicyDecision(
            allowed=False,
            reason="Workload-as-source not allowed in v0.1 (W2* deny by default)",
            quadrant=quadrant,
        )
        await _audit_reach(db, ctx, decision, audit_session_id)
        return decision

    # ── *2W — workload-as-destination is a tool call, separate authz ─
    if ctx.destination.principal_type == "workload":
        decision = PolicyDecision(
            allowed=True,
            reason="Workload destination — tool-call binding governs (reach noop)",
            quadrant=quadrant,
        )
        await _audit_reach(db, ctx, decision, audit_session_id)
        return decision

    # ── A2A ────────────────────────────────────────────────────────
    if ctx.source.principal_type == "agent" and ctx.destination.principal_type == "agent":
        if ctx.is_intra_org:
            decision = PolicyDecision(
                allowed=True,
                reason="Intra-org A2A allowed by default",
                quadrant=quadrant,
            )
            await _audit_reach(db, ctx, decision, audit_session_id)
            return decision
        # Cross-org A2A: existing reach mechanism. Phase 3 considers a
        # consent grant equivalent to the legacy reach record. Caller
        # may layer the legacy reach check on top.
        consent_id = await _has_active_consent(db, ctx)
        if consent_id is None:
            decision = PolicyDecision(
                allowed=False,
                reason="Cross-org A2A requires an explicit reach grant",
                quadrant=quadrant,
            )
        else:
            decision = PolicyDecision(
                allowed=True,
                reason="Cross-org A2A authorised by reach grant",
                quadrant=quadrant,
                consent_id=consent_id,
            )
        await _audit_reach(db, ctx, decision, audit_session_id)
        return decision

    # ── A2U ────────────────────────────────────────────────────────
    if ctx.source.principal_type == "agent" and ctx.destination.principal_type == "user":
        # ALWAYS consent-gated. Even intra-org an unsolicited agent must
        # not pop into a human's inbox. The whole anti-spam premise of
        # the user inbox depends on this.
        consent_id = await _has_active_consent(db, ctx)
        if consent_id is None:
            decision = PolicyDecision(
                allowed=False,
                reason="A2U deny: recipient user has not consented to this source",
                quadrant=quadrant,
            )
        else:
            decision = PolicyDecision(
                allowed=True,
                reason="A2U authorised by recipient consent",
                quadrant=quadrant,
                consent_id=consent_id,
            )
        await _audit_reach(db, ctx, decision, audit_session_id)
        return decision

    # ── U2A ────────────────────────────────────────────────────────
    if ctx.source.principal_type == "user" and ctx.destination.principal_type == "agent":
        if ctx.is_intra_org and ownership_resolver is not None:
            owns = await ownership_resolver(ctx.source, ctx.destination)
            if owns:
                decision = PolicyDecision(
                    allowed=True,
                    reason="U2A intra-org allowed: user owns destination agent",
                    quadrant=quadrant,
                )
                await _audit_reach(db, ctx, decision, audit_session_id)
                return decision
        # Otherwise consent-gated.
        consent_id = await _has_active_consent(db, ctx)
        if consent_id is None:
            decision = PolicyDecision(
                allowed=False,
                reason="U2A deny: agent has not consented to this user",
                quadrant=quadrant,
            )
        else:
            decision = PolicyDecision(
                allowed=True,
                reason="U2A authorised by recipient consent",
                quadrant=quadrant,
                consent_id=consent_id,
            )
        await _audit_reach(db, ctx, decision, audit_session_id)
        return decision

    # ── U2U ────────────────────────────────────────────────────────
    if ctx.source.principal_type == "user" and ctx.destination.principal_type == "user":
        if ctx.is_intra_org:
            decision = PolicyDecision(
                allowed=True,
                reason="Intra-org U2U allowed by default (same SSO domain)",
                quadrant=quadrant,
            )
            await _audit_reach(db, ctx, decision, audit_session_id)
            return decision
        consent_id = await _has_active_consent(db, ctx)
        if consent_id is None:
            decision = PolicyDecision(
                allowed=False,
                reason="Cross-org U2U deny: recipient user has not added sender to addressbook",
                quadrant=quadrant,
            )
        else:
            decision = PolicyDecision(
                allowed=True,
                reason="Cross-org U2U authorised by addressbook entry",
                quadrant=quadrant,
                consent_id=consent_id,
            )
        await _audit_reach(db, ctx, decision, audit_session_id)
        return decision

    # ── Unhandled combo (defensive) ────────────────────────────────
    decision = PolicyDecision(
        allowed=False,
        reason=f"Unrecognised quadrant {quadrant} — default deny",
        quadrant=quadrant,
    )
    await _audit_reach(db, ctx, decision, audit_session_id)
    return decision


async def _audit_reach(
    db: AsyncSession,
    ctx: ReachContext,
    decision: PolicyDecision,
    session_id: str | None,
) -> None:
    await log_event(
        db,
        event_type="policy.reach_evaluated",
        result="ok" if decision.allowed else "denied",
        agent_id=f"{ctx.source.org_id}::{ctx.source.name}",
        org_id=ctx.source.org_id,
        session_id=session_id,
        principal_type=ctx.source.principal_type,
        details={
            "quadrant": decision.quadrant,
            "is_intra_org": ctx.is_intra_org,
            "destination_org": ctx.destination.org_id,
            "destination_principal_type": ctx.destination.principal_type,
            "destination_name": ctx.destination.name,
            "consent_id": decision.consent_id,
            "reason": decision.reason,
        },
    )


# ── Consent grant management ────────────────────────────────────────


async def grant_consent(
    db: AsyncSession,
    *,
    recipient: PrincipalRef,
    source_org_id: str,
    source_principal_type: PrincipalType,
    source_name: str = ANY_NAME,
    granted_by: str | None = None,
) -> ReachConsent:
    """Persist a consent grant. Idempotent: re-granting an existing
    pair flips ``revoked_at=None`` instead of creating a duplicate."""
    import uuid

    # Look up existing row first (revoked or not).
    existing = (await db.execute(
        select(ReachConsent).where(
            and_(
                ReachConsent.recipient_org_id == recipient.org_id,
                ReachConsent.recipient_principal_type == recipient.principal_type,
                ReachConsent.recipient_name == recipient.name,
                ReachConsent.source_org_id == source_org_id,
                ReachConsent.source_principal_type == source_principal_type,
                ReachConsent.source_name == source_name,
            )
        )
    )).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if existing is not None:
        existing.revoked_at = None
        existing.granted_at = now
        existing.granted_by = granted_by
        await db.commit()
        return existing

    row = ReachConsent(
        consent_id=str(uuid.uuid4()),
        recipient_org_id=recipient.org_id,
        recipient_principal_type=recipient.principal_type,
        recipient_name=recipient.name,
        source_org_id=source_org_id,
        source_principal_type=source_principal_type,
        source_name=source_name,
        granted_at=now,
        granted_by=granted_by,
        revoked_at=None,
    )
    db.add(row)
    await db.commit()
    return row


async def revoke_consent(
    db: AsyncSession,
    *,
    recipient: PrincipalRef,
    source_org_id: str,
    source_principal_type: PrincipalType,
    source_name: str = ANY_NAME,
) -> bool:
    """Mark an existing grant as revoked. No-op if no matching row.
    Returns True iff a row was actually revoked (was previously active)."""
    row = (await db.execute(
        select(ReachConsent).where(
            and_(
                ReachConsent.recipient_org_id == recipient.org_id,
                ReachConsent.recipient_principal_type == recipient.principal_type,
                ReachConsent.recipient_name == recipient.name,
                ReachConsent.source_org_id == source_org_id,
                ReachConsent.source_principal_type == source_principal_type,
                ReachConsent.source_name == source_name,
                ReachConsent.revoked_at.is_(None),
            )
        )
    )).scalar_one_or_none()
    if row is None:
        return False
    row.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    return True


async def list_active_consents(
    db: AsyncSession, recipient: PrincipalRef,
) -> list[ReachConsent]:
    """List every active grant for a recipient. Useful for the inbox UI."""
    rows = (await db.execute(
        select(ReachConsent).where(
            and_(
                ReachConsent.recipient_org_id == recipient.org_id,
                ReachConsent.recipient_principal_type == recipient.principal_type,
                ReachConsent.recipient_name == recipient.name,
                ReachConsent.revoked_at.is_(None),
            )
        ).order_by(ReachConsent.granted_at.desc())
    )).scalars().all()
    return list(rows)
