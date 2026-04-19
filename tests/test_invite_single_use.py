"""Audit F-B-17 — invite-CA tokens must be strictly single-use.

The fix mirrors the F-B-4 / F-D-3 atomic-consume pattern on bootstrap
tokens (PR #189, ``consume_bootstrap_token_and_set_password``): a single
``UPDATE ... WHERE used = FALSE ... RETURNING *`` is the only write that
can claim the token, so two concurrent callers can never both win. The
previous implementation did the same UPDATE but then explicitly rolled
back ``used=False`` on expired races — that branch could mask a sibling
consume attempt under clock drift. This file locks in:

  * Second consume of an already-consumed token → None.
  * Concurrent double-consume against the same DB row → exactly one
    winner, the other returns None.
  * Expired tokens never consume (and no rollback can re-open them).
  * Cross-type abuse (org-join token used for attach-ca, or vice versa)
    returns None even when the token is fresh.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta

import pytest

from app.onboarding.invite_store import (
    INVITE_TYPE_ATTACH_CA,
    INVITE_TYPE_ORG_JOIN,
    InviteToken,
    create_invite,
    validate_and_consume,
)

pytestmark = pytest.mark.asyncio


async def test_attach_ca_invite_second_consume_returns_none(db_session):
    """First consume wins, second attempt against the same token returns
    None (row is now used=True)."""
    rec, plaintext = await create_invite(
        db_session, label="f-b-17-single",
        invite_type=INVITE_TYPE_ATTACH_CA, linked_org_id="org-a",
    )
    first = await validate_and_consume(
        db_session, plaintext, "org-a", expected_type=INVITE_TYPE_ATTACH_CA,
    )
    assert first is not None
    assert first.id == rec.id
    assert first.used is True

    second = await validate_and_consume(
        db_session, plaintext, "org-a", expected_type=INVITE_TYPE_ATTACH_CA,
    )
    assert second is None


async def test_attach_ca_invite_concurrent_consume_exactly_one_winner():
    """Two sessions racing on the same token → one wins, the other None.

    Uses two independent AsyncSessions against the shared test engine so
    the UPDATE statements genuinely compete at the DB layer rather than
    inside the same in-memory transaction.
    """
    from tests.conftest import TestSessionLocal

    async with TestSessionLocal() as setup_db:
        rec, plaintext = await create_invite(
            setup_db, label="f-b-17-race",
            invite_type=INVITE_TYPE_ATTACH_CA, linked_org_id="org-race",
        )

    async def _consume() -> object | None:
        # Each task opens its own session so commits compete at the DB.
        async with TestSessionLocal() as s:
            return await validate_and_consume(
                s, plaintext, "org-race", expected_type=INVITE_TYPE_ATTACH_CA,
            )

    results = await asyncio.gather(
        _consume(), _consume(), _consume(), _consume(),
    )
    winners = [r for r in results if r is not None]
    losers = [r for r in results if r is None]
    assert len(winners) == 1, (
        f"expected exactly one winner, got {len(winners)}: {results}"
    )
    assert len(losers) == 3

    # DB row must show used=True and used_by_org_id stamped.
    async with TestSessionLocal() as s:
        from sqlalchemy import select
        res = await s.execute(select(InviteToken).where(InviteToken.id == rec.id))
        fresh = res.scalar_one()
        assert fresh.used is True
        assert fresh.used_by_org_id == "org-race"


async def test_attach_ca_invite_expired_never_consumes(db_session):
    """An expired token must not consume — and subsequent attempts must
    still see the row as non-used (no rollback revival)."""
    from sqlalchemy import update as sa_update

    rec, plaintext = await create_invite(
        db_session, label="f-b-17-expired",
        invite_type=INVITE_TYPE_ATTACH_CA, linked_org_id="org-exp",
    )

    # Force the record into the past so the UPDATE's expires_at > now
    # predicate excludes it.
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    await db_session.execute(
        sa_update(InviteToken)
        .where(InviteToken.id == rec.id)
        .values(expires_at=past)
    )
    await db_session.commit()

    result = await validate_and_consume(
        db_session, plaintext, "org-exp", expected_type=INVITE_TYPE_ATTACH_CA,
    )
    assert result is None

    # Re-fetch — row must still be used=False (no accidental consume)
    # and no lingering side-effects from a rollback branch.
    from sqlalchemy import select
    res = await db_session.execute(
        select(InviteToken).where(InviteToken.id == rec.id)
    )
    fresh = res.scalar_one()
    assert fresh.used is False
    assert fresh.used_by_org_id is None


async def test_org_join_token_rejected_on_attach_path(db_session):
    """Cross-type abuse: a fresh org-join token cannot be used to consume
    on the attach-ca path even though the hash matches."""
    _, plaintext = await create_invite(
        db_session, label="f-b-17-xtype", invite_type=INVITE_TYPE_ORG_JOIN,
    )
    result = await validate_and_consume(
        db_session, plaintext, "any-org",
        expected_type=INVITE_TYPE_ATTACH_CA,
    )
    assert result is None


async def test_attach_ca_token_bound_to_org(db_session):
    """An attach-ca token locked to org-A cannot consume against org-B."""
    _, plaintext = await create_invite(
        db_session, label="f-b-17-bind",
        invite_type=INVITE_TYPE_ATTACH_CA, linked_org_id="org-correct",
    )
    wrong = await validate_and_consume(
        db_session, plaintext, "org-wrong",
        expected_type=INVITE_TYPE_ATTACH_CA,
    )
    assert wrong is None

    # Correct org still works afterwards (the failed wrong-org consume
    # must not have flipped used=True).
    right = await validate_and_consume(
        db_session, plaintext, "org-correct",
        expected_type=INVITE_TYPE_ATTACH_CA,
    )
    assert right is not None
    assert right.used is True


async def test_revoked_token_cannot_consume(db_session):
    """A revoked token with revoked=True must not consume on either path."""
    from sqlalchemy import update as sa_update

    rec, plaintext = await create_invite(
        db_session, label="f-b-17-revoked",
        invite_type=INVITE_TYPE_ATTACH_CA, linked_org_id="org-rev",
    )
    await db_session.execute(
        sa_update(InviteToken)
        .where(InviteToken.id == rec.id)
        .values(revoked=True)
    )
    await db_session.commit()

    result = await validate_and_consume(
        db_session, plaintext, "org-rev",
        expected_type=INVITE_TYPE_ATTACH_CA,
    )
    assert result is None
