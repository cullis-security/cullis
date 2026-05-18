"""ADR-020 Phase 4 — user inbox primitive tests.

Covers store.py end-to-end:
  * enqueue gates on reach (denied raises ReachDeniedError, audit
    row already written by the reach evaluator)
  * enqueue persists with consent_id when a grant authorised it
  * idempotency: same (recipient, idempotency_key) collapses
  * fetch_for_recipient ordering, pagination, archive filter
  * mark_delivered transition (online vs offline) + idempotent
  * mark_archived idempotent
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from app.broker.db_models import UserInboxMessage
from app.db.audit import AuditLog
from app.inbox import (
    DeliveryState,
    enqueue,
    fetch_for_recipient,
    mark_archived,
    mark_delivered,
)
from app.inbox.store import ReachDeniedError
from app.policy.reach import (
    PrincipalRef,
    ReachConsent,
    grant_consent,
)
from tests.conftest import TestSessionLocal

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.xdist_group(name="serial_user_inbox"),
]


@pytest_asyncio.fixture
async def inbox_db():
    """Clean session with inbox + reach + audit emptied before/after."""
    async with TestSessionLocal() as session:
        await session.execute(delete(UserInboxMessage))
        await session.execute(delete(ReachConsent))
        await session.execute(delete(AuditLog))
        await session.commit()
    async with TestSessionLocal() as session:
        yield session
    async with TestSessionLocal() as session:
        await session.execute(delete(UserInboxMessage))
        await session.execute(delete(ReachConsent))
        await session.execute(delete(AuditLog))
        await session.commit()


def _user(name: str, org: str = "acme") -> PrincipalRef:
    return PrincipalRef(org, "user", name)


def _agent(name: str, org: str = "acme") -> PrincipalRef:
    return PrincipalRef(org, "agent", name)


# ── enqueue: reach gate ─────────────────────────────────────────────


async def test_enqueue_a2u_denied_raises(inbox_db):
    """A2U intra-org without consent must NOT land a row."""
    with pytest.raises(ReachDeniedError) as excinfo:
        await enqueue(
            inbox_db,
            sender=_agent("snoopy"),
            recipient=_user("mario"),
            body="hello",
        )
    assert "consented" in excinfo.value.decision.reason
    rows = (await inbox_db.execute(select(UserInboxMessage))).scalars().all()
    assert rows == []


async def test_enqueue_a2u_consent_unblocks(inbox_db):
    sender = _agent("snoopy")
    recipient = _user("mario")
    grant = await grant_consent(
        inbox_db,
        recipient=recipient,
        source_org_id=sender.org_id,
        source_principal_type="agent",
        source_name="snoopy",
    )
    delivery = await enqueue(
        inbox_db,
        sender=sender, recipient=recipient,
        subject="ciao Mario",
        body="hai un report da rivedere",
    )
    assert delivery.inserted is True
    assert delivery.decision.allowed
    row = (await inbox_db.execute(select(UserInboxMessage))).scalar_one()
    assert row.subject == "ciao Mario"
    assert row.delivery_state == DeliveryState.QUEUED.value
    assert row.consent_id == grant.consent_id


async def test_enqueue_u2u_intra_org_default_allow(inbox_db):
    delivery = await enqueue(
        inbox_db,
        sender=_user("mario"), recipient=_user("anna"),
        body="ho una domanda",
    )
    assert delivery.inserted
    rows = (await inbox_db.execute(select(UserInboxMessage))).scalars().all()
    assert len(rows) == 1
    assert rows[0].sender_principal_type == "user"
    assert rows[0].recipient_principal_type == "user"


async def test_enqueue_u2u_cross_org_default_deny(inbox_db):
    with pytest.raises(ReachDeniedError):
        await enqueue(
            inbox_db,
            sender=_user("mario", "acme"),
            recipient=_user("anna", "bravo"),
            body="cross-org without addressbook",
        )


async def test_enqueue_u2a_with_ownership_resolver(inbox_db):
    async def owns(user, agent):
        return user.name == "mario" and agent.name == "mario-laptop"

    delivery = await enqueue(
        inbox_db,
        sender=_user("mario"),
        recipient=_agent("mario-laptop"),
        body="agente sveglia",
        ownership_resolver=owns,
    )
    assert delivery.inserted
    assert delivery.decision.allowed


# ── idempotency ─────────────────────────────────────────────────────


async def test_enqueue_idempotency_collapses_duplicates(inbox_db):
    sender = _user("mario")
    recipient = _user("anna")
    d1 = await enqueue(
        inbox_db, sender=sender, recipient=recipient,
        body="msg 1", idempotency_key="abc-123",
    )
    d2 = await enqueue(
        inbox_db, sender=sender, recipient=recipient,
        body="msg 1 retry", idempotency_key="abc-123",
    )
    assert d1.inserted is True
    assert d2.inserted is False
    assert d1.msg_id == d2.msg_id

    rows = (await inbox_db.execute(select(UserInboxMessage))).scalars().all()
    assert len(rows) == 1


async def test_enqueue_no_idempotency_key_creates_distinct_rows(inbox_db):
    sender = _user("mario")
    recipient = _user("anna")
    d1 = await enqueue(inbox_db, sender=sender, recipient=recipient, body="m1")
    d2 = await enqueue(inbox_db, sender=sender, recipient=recipient, body="m2")
    assert d1.msg_id != d2.msg_id
    rows = (await inbox_db.execute(select(UserInboxMessage))).scalars().all()
    assert len(rows) == 2


# ── fetch ───────────────────────────────────────────────────────────


async def test_fetch_for_recipient_orders_by_enqueued_at(inbox_db):
    recipient = _user("mario")
    for sender_name, body in [("anna", "first"), ("bob", "second"), ("anna", "third")]:
        await enqueue(
            inbox_db, sender=_user(sender_name), recipient=recipient, body=body,
        )
    rows = await fetch_for_recipient(inbox_db, recipient=recipient)
    bodies = [r.body for r in rows]
    assert bodies == ["first", "second", "third"]


async def test_fetch_for_recipient_cursor_pagination(inbox_db):
    recipient = _user("mario")
    sent = []
    for body in ["a", "b", "c", "d"]:
        d = await enqueue(
            inbox_db, sender=_user("anna"), recipient=recipient, body=body,
        )
        sent.append(d.msg_id)

    page1 = await fetch_for_recipient(inbox_db, recipient=recipient, limit=2)
    assert [r.body for r in page1] == ["a", "b"]

    cursor = page1[-1].msg_id
    page2 = await fetch_for_recipient(
        inbox_db, recipient=recipient, since_msg_id=cursor, limit=10,
    )
    assert [r.body for r in page2] == ["c", "d"]


async def test_fetch_for_recipient_excludes_archived_by_default(inbox_db):
    recipient = _user("mario")
    d1 = await enqueue(inbox_db, sender=_user("anna"), recipient=recipient, body="a")
    await enqueue(inbox_db, sender=_user("anna"), recipient=recipient, body="b")
    await mark_archived(inbox_db, msg_id=d1.msg_id)

    visible = await fetch_for_recipient(inbox_db, recipient=recipient)
    assert [r.body for r in visible] == ["b"]

    with_archive = await fetch_for_recipient(
        inbox_db, recipient=recipient, include_archived=True,
    )
    assert sorted(r.body for r in with_archive) == ["a", "b"]


async def test_fetch_for_recipient_filters_by_full_principal(inbox_db):
    """Two users in same org, name disambiguates."""
    mario = _user("mario")
    anna = _user("anna")
    await enqueue(inbox_db, sender=_user("bob"), recipient=mario, body="for mario")
    await enqueue(inbox_db, sender=_user("bob"), recipient=anna, body="for anna")

    mario_inbox = await fetch_for_recipient(inbox_db, recipient=mario)
    assert [r.body for r in mario_inbox] == ["for mario"]
    anna_inbox = await fetch_for_recipient(inbox_db, recipient=anna)
    assert [r.body for r in anna_inbox] == ["for anna"]


# ── mark_delivered / mark_archived ─────────────────────────────────


async def test_mark_delivered_offline(inbox_db):
    d = await enqueue(
        inbox_db, sender=_user("anna"), recipient=_user("mario"), body="hi",
    )
    flipped = await mark_delivered(inbox_db, msg_id=d.msg_id, online=False)
    assert flipped is True

    row = (await inbox_db.execute(
        select(UserInboxMessage).where(UserInboxMessage.msg_id == d.msg_id)
    )).scalar_one()
    assert row.delivery_state == DeliveryState.DELIVERED_OFFLINE.value
    assert row.delivered_at is not None


async def test_mark_delivered_online_then_idempotent(inbox_db):
    d = await enqueue(
        inbox_db, sender=_user("anna"), recipient=_user("mario"), body="hi",
    )
    first = await mark_delivered(inbox_db, msg_id=d.msg_id, online=True)
    second = await mark_delivered(inbox_db, msg_id=d.msg_id, online=True)
    assert first is True
    # Second call is a no-op (already not in QUEUED state).
    assert second is False


async def test_mark_archived_idempotent(inbox_db):
    d = await enqueue(
        inbox_db, sender=_user("anna"), recipient=_user("mario"), body="hi",
    )
    first = await mark_archived(inbox_db, msg_id=d.msg_id)
    second = await mark_archived(inbox_db, msg_id=d.msg_id)
    assert first is True
    assert second is False


# ── audit chain integrity ──────────────────────────────────────────


async def test_audit_row_emitted_on_denied_enqueue(inbox_db):
    """Even a denied send leaves an audit trace via reach evaluator."""
    with pytest.raises(ReachDeniedError):
        await enqueue(
            inbox_db,
            sender=_agent("snoopy"),
            recipient=_user("mario"),
            body="spam",
        )
    rows = (await inbox_db.execute(
        select(AuditLog).where(AuditLog.event_type == "policy.reach_evaluated")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].result == "denied"


# ─────────────────────────────────────────────────────────────────────────────
# REST router (with DPoP/JWT overridden out)
# ─────────────────────────────────────────────────────────────────────────────


from httpx import AsyncClient, ASGITransport

from app.main import app
from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload


def _fake_token(*, agent_id: str, org: str, principal_type: str = "user") -> TokenPayload:
    name = agent_id.split("::", 1)[-1]
    return TokenPayload(
        sub=f"spiffe://cullis.test/{org}/{principal_type}/{name}",
        agent_id=agent_id,
        org=org,
        exp=9_999_999_999,
        iat=1_000_000_000,
        jti=f"jti-{agent_id}",
        scope=[],
        cnf={"jkt": "fake-jkt"},
    )


@pytest.fixture
def authed_user(request):
    """Override get_current_agent with a user/mario principal.

    Marker ``@pytest.mark.user_principal('acme', 'mario')`` lets a test
    swap to a different fake user.
    """
    org = "acme"
    name = "mario"
    marker = request.node.get_closest_marker("user_principal")
    if marker is not None:
        org, name = marker.args
    token = _fake_token(agent_id=f"{org}::{name}", org=org, principal_type="user")
    app.dependency_overrides[get_current_agent] = lambda: token
    yield token
    app.dependency_overrides.pop(get_current_agent, None)


@pytest.fixture
def authed_agent_principal():
    """Override with an agent (not user) principal — for A2U send tests."""
    token = _fake_token(agent_id="acme::snoopy", org="acme", principal_type="agent")
    app.dependency_overrides[get_current_agent] = lambda: token
    yield token
    app.dependency_overrides.pop(get_current_agent, None)


@pytest_asyncio.fixture
async def http_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ── /v1/inbox/send ─────────────────────────────────────────────────


async def test_router_send_u2u_intra_org_201(http_client, authed_user, inbox_db):
    resp = await http_client.post("/v1/inbox/send", json={
        "recipient_org_id": "acme",
        "recipient_principal_type": "user",
        "recipient_name": "anna",
        "subject": "ciao",
        "body": "domanda?",
    })
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["inserted"] is True
    assert body["quadrant"] == "U2U"

    # The row exists in the DB.
    rows = (await inbox_db.execute(select(UserInboxMessage))).scalars().all()
    assert len(rows) == 1
    assert rows[0].sender_name == "mario"
    assert rows[0].recipient_name == "anna"


async def test_router_send_a2u_without_consent_403(http_client, authed_agent_principal, inbox_db):
    resp = await http_client.post("/v1/inbox/send", json={
        "recipient_org_id": "acme",
        "recipient_principal_type": "user",
        "recipient_name": "mario",
        "body": "spam",
    })
    assert resp.status_code == 403
    assert resp.json()["detail"]["quadrant"] == "A2U"


async def test_router_send_idempotent(http_client, authed_user, inbox_db):
    payload = {
        "recipient_org_id": "acme",
        "recipient_principal_type": "user",
        "recipient_name": "anna",
        "body": "msg",
        "idempotency_key": "abc-1",
    }
    r1 = await http_client.post("/v1/inbox/send", json=payload)
    r2 = await http_client.post("/v1/inbox/send", json=payload)
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["msg_id"] == r2.json()["msg_id"]
    assert r1.json()["inserted"] is True
    assert r2.json()["inserted"] is False


# ── GET /v1/inbox ─────────────────────────────────────────────────


async def test_router_list_returns_messages_for_caller(http_client, authed_user, inbox_db):
    # Seed one message addressed to mario directly via the store.
    mario = _user("mario")
    await enqueue(inbox_db, sender=_user("anna"), recipient=mario, body="for you")
    # And one for anna (must NOT show up).
    await enqueue(
        inbox_db, sender=_user("mario"), recipient=_user("anna"), body="elsewhere",
    )

    resp = await http_client.get("/v1/inbox")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["body"] == "for you"
    assert items[0]["delivery_state"] == "queued"


async def test_router_list_pagination(http_client, authed_user, inbox_db):
    mario = _user("mario")
    sent = []
    for body in ["a", "b", "c", "d"]:
        d = await enqueue(inbox_db, sender=_user("anna"), recipient=mario, body=body)
        sent.append(d.msg_id)

    page1 = (await http_client.get("/v1/inbox?limit=2")).json()
    assert [it["body"] for it in page1] == ["a", "b"]

    cursor = page1[-1]["msg_id"]
    page2 = (await http_client.get(f"/v1/inbox?since={cursor}&limit=10")).json()
    assert [it["body"] for it in page2] == ["c", "d"]


async def test_router_list_isolation_between_users(http_client, authed_user, inbox_db):
    """Anna's messages are not visible to mario via the router."""
    await enqueue(
        inbox_db, sender=_user("bob"), recipient=_user("anna"), body="for anna only",
    )
    resp = await http_client.get("/v1/inbox")
    assert resp.status_code == 200
    assert resp.json() == []


# ── ack / archive ──────────────────────────────────────────────────


async def test_router_ack(http_client, authed_user, inbox_db):
    d = await enqueue(
        inbox_db, sender=_user("anna"), recipient=_user("mario"), body="hi",
    )
    resp = await http_client.post(f"/v1/inbox/{d.msg_id}/ack?online=true")
    assert resp.status_code == 200
    assert resp.json()["acked"] is True

    row = (await inbox_db.execute(
        select(UserInboxMessage).where(UserInboxMessage.msg_id == d.msg_id)
    )).scalar_one()
    assert row.delivery_state == "delivered_online"


async def test_router_ack_unknown_msg_404(http_client, authed_user, inbox_db):
    resp = await http_client.post("/v1/inbox/does-not-exist/ack")
    assert resp.status_code == 404


async def test_router_ack_not_recipient_404(http_client, authed_user, inbox_db):
    """Calling ack for a message not addressed to the caller → 404 (no leak)."""
    d = await enqueue(
        inbox_db, sender=_user("bob"), recipient=_user("anna"), body="for anna",
    )
    resp = await http_client.post(f"/v1/inbox/{d.msg_id}/ack")
    assert resp.status_code == 404


async def test_router_archive(http_client, authed_user, inbox_db):
    d = await enqueue(
        inbox_db, sender=_user("anna"), recipient=_user("mario"), body="hi",
    )
    resp = await http_client.post(f"/v1/inbox/{d.msg_id}/archive")
    assert resp.status_code == 200
    assert resp.json()["archived"] is True

    row = (await inbox_db.execute(
        select(UserInboxMessage).where(UserInboxMessage.msg_id == d.msg_id)
    )).scalar_one()
    assert row.delivery_state == "archived"


async def test_router_archive_excluded_from_list_default(http_client, authed_user, inbox_db):
    mario = _user("mario")
    await enqueue(inbox_db, sender=_user("anna"), recipient=mario, body="visible")
    archived = await enqueue(
        inbox_db, sender=_user("anna"), recipient=mario, body="hidden",
    )
    await mark_archived(inbox_db, msg_id=archived.msg_id)

    visible = (await http_client.get("/v1/inbox")).json()
    assert len(visible) == 1
    assert visible[0]["body"] == "visible"

    with_archive = (await http_client.get("/v1/inbox?include_archived=true")).json()
    assert sorted(it["body"] for it in with_archive) == ["hidden", "visible"]
