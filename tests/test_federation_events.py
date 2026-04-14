"""ADR-001 Phase 4a — federation event log + SSE stream tests."""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from app.broker.federation import (
    EVENT_AGENT_REGISTERED,
    EVENT_AGENT_REVOKED,
    EVENT_BINDING_GRANTED,
    EVENT_BINDING_REVOKED,
    EVENT_POLICY_REMOVED,
    EVENT_POLICY_UPDATED,
    FederationEvent,
    list_events_since,
    publish_federation_event,
)
from app.main import app
from tests.conftest import TestSessionLocal


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def clean_federation():
    # Also point the federation tail loop at the in-memory test engine
    # so the SSE tail tick can read the same tables the test writes to.
    import app.broker.federation_router as fr
    original_factory = fr._tail_session_factory
    fr._tail_session_factory = TestSessionLocal
    async with TestSessionLocal() as s:
        await s.execute(delete(FederationEvent))
        await s.commit()
    try:
        yield
    finally:
        fr._tail_session_factory = original_factory
        async with TestSessionLocal() as s:
            await s.execute(delete(FederationEvent))
            await s.commit()


# ── publish_federation_event ──────────────────────────────────────


async def test_publish_assigns_monotonic_seq_per_org(clean_federation):
    async with TestSessionLocal() as db:
        a1 = await publish_federation_event(
            db, org_id="acme", event_type=EVENT_AGENT_REGISTERED,
            payload={"agent_id": "a1"},
        )
        a2 = await publish_federation_event(
            db, org_id="acme", event_type=EVENT_AGENT_REVOKED,
            payload={"agent_id": "a1"},
        )
        b1 = await publish_federation_event(
            db, org_id="bravo", event_type=EVENT_AGENT_REGISTERED,
            payload={"agent_id": "b1"},
        )
        await db.commit()
    assert a1.seq == 1
    assert a2.seq == 2
    # Bravo starts its own sequence, unaffected by acme.
    assert b1.seq == 1


async def test_list_events_since_filters_and_orders(clean_federation):
    async with TestSessionLocal() as db:
        for i in range(5):
            await publish_federation_event(
                db, org_id="acme", event_type=EVENT_AGENT_REGISTERED,
                payload={"i": i},
            )
        await publish_federation_event(
            db, org_id="bravo", event_type=EVENT_AGENT_REGISTERED,
            payload={"i": 99},
        )
        await db.commit()

    async with TestSessionLocal() as db:
        evs = await list_events_since(db, org_id="acme", since_seq=2)
    seqs = [e.seq for e in evs]
    assert seqs == [3, 4, 5]  # strictly > 2, ordered asc
    # No cross-org leak.
    for e in evs:
        assert e.org_id == "acme"


async def test_list_events_respects_limit(clean_federation):
    async with TestSessionLocal() as db:
        for i in range(10):
            await publish_federation_event(
                db, org_id="acme", event_type=EVENT_AGENT_REGISTERED,
                payload={"i": i},
            )
        await db.commit()

    async with TestSessionLocal() as db:
        evs = await list_events_since(db, org_id="acme", since_seq=0, limit=3)
    assert len(evs) == 3
    assert [e.seq for e in evs] == [1, 2, 3]


# ── as_dict round-trip ─────────────────────────────────────────────


async def test_payload_round_trips_as_json(clean_federation):
    payload = {"agent_id": "zeta", "capabilities": ["kyc.read", "kyc.write"]}
    async with TestSessionLocal() as db:
        ev = await publish_federation_event(
            db, org_id="acme", event_type=EVENT_AGENT_REGISTERED,
            payload=payload,
        )
        await db.commit()
    d = ev.as_dict()
    assert d["seq"] == ev.seq
    assert d["event_type"] == EVENT_AGENT_REGISTERED
    assert d["payload"] == payload
    # created_at is tz-aware ISO.
    assert "T" in d["created_at"]


# ── SSE endpoint — auth filtering ─────────────────────────────────


async def test_sse_endpoint_rejects_missing_token(clean_federation):
    """Without the DPoP dependency override, the endpoint must 401 —
    proving the stream is gated on an authenticated org-scoped caller."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        resp = await c.get("/v1/broker/federation/events/stream")
    assert resp.status_code == 401


def test_parse_since_prefers_last_event_id_header():
    """Resume semantics: the SSE Last-Event-ID header (spec-standard)
    wins over the query param, and malformed headers fall back cleanly."""
    from starlette.requests import Request
    from app.broker.federation_router import _parse_since

    def _req(headers: dict[str, str]) -> Request:
        scope = {
            "type": "http",
            "headers": [
                (k.lower().encode(), v.encode())
                for k, v in headers.items()
            ],
        }
        return Request(scope)

    assert _parse_since(_req({"Last-Event-ID": "42"}), since_seq=0) == 42
    assert _parse_since(_req({"Last-Event-ID": "42"}), since_seq=5) == 42
    assert _parse_since(_req({}), since_seq=7) == 7
    # Malformed header → fall back to query param.
    assert _parse_since(_req({"Last-Event-ID": "abc"}), since_seq=9) == 9
    # Negative values clamp to 0.
    assert _parse_since(_req({}), since_seq=-1) == 0


# ── Emit-site wiring ───────────────────────────────────────────────


async def test_register_agent_emits_federation_event(clean_federation):
    from app.registry.org_store import register_org
    from app.registry.store import register_agent

    async with TestSessionLocal() as db:
        await register_org(db, "phi", "Phi Inc", secret="s")
        await register_agent(
            db, agent_id="phi::worker", org_id="phi",
            display_name="Worker", capabilities=["ingest"], metadata={},
        )

    async with TestSessionLocal() as db:
        evs = await list_events_since(db, org_id="phi", since_seq=0)
    types = [e.event_type for e in evs]
    assert EVENT_AGENT_REGISTERED in types


async def test_policy_lifecycle_emits_events(clean_federation):
    from app.policy.store import create_policy, deactivate_policy

    async with TestSessionLocal() as db:
        await create_policy(
            db, policy_id="policy-alpha", org_id="omega",
            policy_type="session", rules={"match": "*"},
        )
        await deactivate_policy(db, "policy-alpha")

    async with TestSessionLocal() as db:
        evs = await list_events_since(db, org_id="omega", since_seq=0)
    types = [e.event_type for e in evs]
    assert types == [EVENT_POLICY_UPDATED, EVENT_POLICY_REMOVED]


async def test_binding_lifecycle_emits_events(clean_federation):
    from app.registry.binding_store import (
        approve_binding,
        create_binding,
        revoke_binding,
    )

    async with TestSessionLocal() as db:
        b = await create_binding(db, org_id="sigma", agent_id="sigma::a", scope=["x"])
        await approve_binding(db, b.id, approved_by="admin")
        await revoke_binding(db, b.id)

    async with TestSessionLocal() as db:
        evs = await list_events_since(db, org_id="sigma", since_seq=0)
    types = [e.event_type for e in evs]
    # create_binding is NOT an event (pending status is not a federated
    # state change); only granted/revoked are emitted.
    assert types == [EVENT_BINDING_GRANTED, EVENT_BINDING_REVOKED]
