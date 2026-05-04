"""ADR-020 Phase 3 — reach policy four-quadrant matrix tests.

Covers:
  * Quadrant detection (intra-org vs cross-org × every principal-type pair)
  * Default-deny / default-allow per quadrant per direction
  * Consent grant + revoke + idempotent re-grant
  * Wildcard source_name='*' matches any source of the same type
  * Audit row emitted on every evaluation
  * verify_chain still passes after a mix of reach evaluations
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.db.audit import AuditLog, verify_chain
from app.policy.reach import (
    ANY_NAME,
    PrincipalRef,
    ReachConsent,
    ReachContext,
    evaluate_reach_quadrant,
    grant_consent,
    list_active_consents,
    revoke_consent,
)
from tests.conftest import TestSessionLocal

pytestmark = pytest.mark.asyncio


# ── fixtures ────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def reach_db():
    """Clean session with audit_log + reach_consents emptied before/after."""
    async with TestSessionLocal() as session:
        await session.execute(delete(ReachConsent))
        await session.execute(delete(AuditLog))
        await session.commit()
    async with TestSessionLocal() as session:
        yield session
    async with TestSessionLocal() as session:
        await session.execute(delete(ReachConsent))
        await session.execute(delete(AuditLog))
        await session.commit()


def _ctx(
    src_org="acme", src_type="agent", src_name="mario-bot",
    dst_org="acme", dst_type="agent", dst_name="compliance-bot",
) -> ReachContext:
    return ReachContext(
        source=PrincipalRef(src_org, src_type, src_name),
        destination=PrincipalRef(dst_org, dst_type, dst_name),
    )


# ── quadrant detection ──────────────────────────────────────────────


def test_quadrant_intra_a2a():
    ctx = _ctx()
    assert ctx.quadrant == "A2A"
    assert ctx.is_intra_org is True


def test_quadrant_cross_u2u():
    ctx = _ctx(src_org="acme", src_type="user", src_name="mario",
               dst_org="bravo", dst_type="user", dst_name="anna")
    assert ctx.quadrant == "U2U"
    assert ctx.is_intra_org is False


def test_quadrant_a2u_a2w_u2a_w2a_w2u_w2w():
    """Spot-check the 6 remaining cells parse to the right shorthand."""
    pairs = [
        ("agent", "user",     "A2U"),
        ("agent", "workload", "A2W"),
        ("user",  "agent",    "U2A"),
        ("user",  "workload", "U2W"),
        ("workload", "agent", "W2A"),
        ("workload", "user",  "W2U"),
        ("workload", "workload", "W2W"),
    ]
    for src, dst, expect in pairs:
        ctx = _ctx(src_type=src, dst_type=dst)
        assert ctx.quadrant == expect, (src, dst, ctx.quadrant)


# ── A2A ─────────────────────────────────────────────────────────────


async def test_a2a_intra_org_default_allow(reach_db):
    decision = await evaluate_reach_quadrant(reach_db, _ctx())
    assert decision.allowed
    assert decision.quadrant == "A2A"
    assert "Intra-org" in decision.reason


async def test_a2a_cross_org_default_deny(reach_db):
    ctx = _ctx(src_org="acme", dst_org="bravo")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert not decision.allowed
    assert "reach grant" in decision.reason


async def test_a2a_cross_org_consent_unblocks(reach_db):
    ctx = _ctx(src_org="acme", dst_org="bravo")
    await grant_consent(
        reach_db,
        recipient=ctx.destination,
        source_org_id="acme", source_principal_type="agent",
        source_name="mario-bot", granted_by="bravo-admin",
    )
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert decision.allowed
    assert decision.consent_id is not None


# ── A2U ─────────────────────────────────────────────────────────────


async def test_a2u_intra_org_default_deny(reach_db):
    """Even intra-org an unsolicited agent must NOT pop into a user inbox."""
    ctx = _ctx(src_type="agent", dst_type="user", dst_name="mario")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert not decision.allowed
    assert decision.quadrant == "A2U"
    assert "consented" in decision.reason


async def test_a2u_intra_org_consent_unblocks(reach_db):
    ctx = _ctx(src_type="agent", dst_type="user", dst_name="mario")
    await grant_consent(
        reach_db,
        recipient=ctx.destination,
        source_org_id="acme", source_principal_type="agent",
        source_name="mario-bot",
    )
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert decision.allowed
    assert decision.consent_id is not None


async def test_a2u_cross_org_default_deny(reach_db):
    ctx = _ctx(src_org="acme", src_type="agent", src_name="snoopy",
               dst_org="bravo", dst_type="user", dst_name="anna")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert not decision.allowed
    assert decision.quadrant == "A2U"


# ── U2A ─────────────────────────────────────────────────────────────


async def test_u2a_intra_org_without_ownership_default_deny(reach_db):
    """Without an ownership resolver, even intra-org U2A is consent-gated."""
    ctx = _ctx(src_type="user", src_name="mario",
               dst_type="agent", dst_name="finance-bot")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert not decision.allowed
    assert decision.quadrant == "U2A"


async def test_u2a_intra_org_with_ownership_allow(reach_db):
    ctx = _ctx(src_type="user", src_name="mario",
               dst_type="agent", dst_name="mario-laptop")

    async def owns(user, agent):
        return user.name == "mario" and agent.name == "mario-laptop"

    decision = await evaluate_reach_quadrant(
        reach_db, ctx, ownership_resolver=owns,
    )
    assert decision.allowed
    assert "owns destination agent" in decision.reason


async def test_u2a_cross_org_default_deny(reach_db):
    ctx = _ctx(src_org="acme", src_type="user", src_name="mario",
               dst_org="bravo", dst_type="agent", dst_name="finance-bot")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert not decision.allowed


# ── U2U ─────────────────────────────────────────────────────────────


async def test_u2u_intra_org_default_allow(reach_db):
    ctx = _ctx(src_type="user", src_name="mario",
               dst_type="user", dst_name="anna")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert decision.allowed
    assert decision.quadrant == "U2U"
    assert "Intra-org" in decision.reason


async def test_u2u_cross_org_default_deny_addressbook(reach_db):
    ctx = _ctx(src_org="acme", src_type="user", src_name="mario",
               dst_org="bravo", dst_type="user", dst_name="anna")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert not decision.allowed
    assert "addressbook" in decision.reason


async def test_u2u_cross_org_consent_unblocks(reach_db):
    ctx = _ctx(src_org="acme", src_type="user", src_name="mario",
               dst_org="bravo", dst_type="user", dst_name="anna")
    await grant_consent(
        reach_db,
        recipient=ctx.destination,
        source_org_id="acme", source_principal_type="user",
        source_name="mario",
    )
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert decision.allowed


# ── workload-as-source / -as-destination ────────────────────────────


async def test_workload_source_always_denied_in_v01(reach_db):
    ctx = _ctx(src_type="workload", src_name="byoca-haiku",
               dst_type="user", dst_name="anna")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert not decision.allowed
    assert "Workload-as-source" in decision.reason


async def test_workload_destination_is_tool_call_noop_allow(reach_db):
    ctx = _ctx(src_type="agent", src_name="mario-bot",
               dst_type="workload", dst_name="postgres-mcp")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert decision.allowed
    assert "Workload destination" in decision.reason


# ── consent grant management ───────────────────────────────────────


async def test_grant_revoke_round_trip(reach_db):
    recipient = PrincipalRef("acme", "user", "mario")
    grant = await grant_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name="snoopy",
    )
    assert grant.consent_id
    revoked = await revoke_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name="snoopy",
    )
    assert revoked is True
    # Second revoke is a no-op
    revoked_again = await revoke_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name="snoopy",
    )
    assert revoked_again is False


async def test_re_grant_after_revoke_is_idempotent(reach_db):
    """Re-granting after a revoke must reuse the same row, not duplicate."""
    recipient = PrincipalRef("acme", "user", "mario")
    g1 = await grant_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name="snoopy",
    )
    await revoke_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name="snoopy",
    )
    g2 = await grant_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name="snoopy",
    )
    assert g1.consent_id == g2.consent_id
    assert g2.revoked_at is None

    rows = (await reach_db.execute(select(ReachConsent))).scalars().all()
    assert len(rows) == 1


async def test_wildcard_source_matches_any_name(reach_db):
    """source_name='*' grants admit any sender of that type from that org."""
    ctx = _ctx(src_org="bravo", src_type="agent", src_name="anything",
               dst_org="acme", dst_type="user", dst_name="mario")
    await grant_consent(
        reach_db,
        recipient=ctx.destination,
        source_org_id="bravo", source_principal_type="agent",
        source_name=ANY_NAME,
    )
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert decision.allowed
    assert decision.consent_id is not None


async def test_specific_grant_beats_wildcard_when_both_present(reach_db):
    """If a specific grant and a wildcard both match, evaluator picks
    the specific one (more auditable)."""
    recipient = PrincipalRef("acme", "user", "mario")
    await grant_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name=ANY_NAME,
    )
    specific = await grant_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name="snoopy",
    )
    ctx = _ctx(src_org="bravo", src_type="agent", src_name="snoopy",
               dst_org="acme", dst_type="user", dst_name="mario")
    decision = await evaluate_reach_quadrant(reach_db, ctx)
    assert decision.allowed
    assert decision.consent_id == specific.consent_id


async def test_list_active_consents(reach_db):
    recipient = PrincipalRef("acme", "user", "mario")
    await grant_consent(
        reach_db, recipient=recipient,
        source_org_id="bravo", source_principal_type="agent",
        source_name="snoopy",
    )
    await grant_consent(
        reach_db, recipient=recipient,
        source_org_id="charlie", source_principal_type="user",
        source_name="anna",
    )
    rows = await list_active_consents(reach_db, recipient)
    assert len(rows) == 2
    src_orgs = sorted(r.source_org_id for r in rows)
    assert src_orgs == ["bravo", "charlie"]


# ── audit chain integrity ──────────────────────────────────────────


async def test_audit_row_emitted_per_evaluation(reach_db):
    ctx = _ctx()
    await evaluate_reach_quadrant(reach_db, ctx)
    rows = (await reach_db.execute(
        select(AuditLog).where(AuditLog.event_type == "policy.reach_evaluated")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].principal_type == "agent"
    assert rows[0].result == "ok"


async def test_chain_intact_after_mixed_evaluations(reach_db):
    """Run a batch of evaluations across all quadrants and verify the
    audit chain still passes."""
    ctxs = [
        _ctx(),  # A2A intra
        _ctx(src_org="acme", dst_org="bravo"),  # A2A cross deny
        _ctx(src_type="agent", dst_type="user", dst_name="mario"),  # A2U
        _ctx(src_type="user", src_name="mario", dst_type="user", dst_name="anna"),  # U2U intra
    ]
    for ctx in ctxs:
        await evaluate_reach_quadrant(reach_db, ctx)

    is_valid, total, broken_id = await verify_chain(reach_db, org_id="acme")
    assert is_valid is True, f"chain broken at id {broken_id}"
    assert total == len(ctxs)
