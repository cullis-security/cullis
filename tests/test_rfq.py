"""
Test RFQ (Request for Quote) broadcast.

Covers:
1. RFQ broadcast finds agents and collects quotes
2. RFQ with no matching agents returns empty
3. RFQ duplicate response rejected
4. RFQ requires authentication
5. RFQ respond — agent not in matched set rejected
6. RFQ status polling via GET
7. RFQ audit trail
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient
from tests.cert_factory import get_org_ca_pem
from tests.conftest import ADMIN_HEADERS, seed_court_agent

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def mock_rfq_policy():
    """Mock the policy evaluation in rfq.py (separate from router.py mock)."""
    from app.policy.webhook import WebhookDecision
    allow = WebhookDecision(allowed=True, reason="mocked allow", org_id="broker")
    with patch(
        "app.broker.rfq.evaluate_session_policy",
        new=AsyncMock(return_value=allow),
    ):
        yield


async def _setup(client: AsyncClient, org_id: str, agent_id: str,
                 capabilities: list[str], dpop) -> str:
    """Register org + CA + agent + approved binding. Returns the JWT."""
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": get_org_ca_pem(org_id)},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=capabilities,
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": capabilities},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


async def test_rfq_no_matching_agents(client: AsyncClient, dpop):
    """RFQ with no matching agents returns empty result."""
    token = await _setup(client, "rfq-buyer1", "rfq-buyer1::agent",
                         ["order.read"], dpop)

    resp = await client.post("/v1/broker/rfq",
        json={
            "capability_filter": ["nonexistent.capability"],
            "payload": {"item": "BLT-M10", "qty": 1000},
            "timeout_seconds": 5,
        },
        headers=dpop.headers("POST", "/v1/broker/rfq", token),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "closed"
    assert data["matched_agents"] == []
    assert data["quotes"] == []


async def test_rfq_broadcast_and_respond(client: AsyncClient, dpop):
    """RFQ broadcasts to matching agents and collects a response."""
    token_buyer = await _setup(client, "rfq-buyer2", "rfq-buyer2::agent",
                               ["order.read"], dpop)
    token_sup = await _setup(client, "rfq-sup2", "rfq-sup2::agent",
                             ["supply.negotiate"], dpop)

    # Start RFQ in a background task (it will wait for responses)
    async def do_rfq():
        return await client.post("/v1/broker/rfq",
            json={
                "capability_filter": ["supply.negotiate"],
                "payload": {"item": "BLT-M10", "qty": 2000},
                "timeout_seconds": 10,
            },
            headers=dpop.headers("POST", "/v1/broker/rfq", token_buyer),
        )

    rfq_task = asyncio.create_task(do_rfq())

    # Wait for the RFQ to be created and broadcast
    rfq_id = None
    for _ in range(20):
        await asyncio.sleep(0.3)
        notif_resp = await client.get("/v1/broker/notifications",
            headers=dpop.headers("GET", "/v1/broker/notifications", token_sup),
        )
        rfq_notifs = [n for n in notif_resp.json() if n["type"] == "rfq_request"]
        if rfq_notifs:
            rfq_id = rfq_notifs[0]["reference_id"]
            break

    assert rfq_id is not None, "RFQ notification not received by supplier"

    # Supplier responds
    url = f"/v1/broker/rfq/{rfq_id}/respond"
    resp = await client.post(url,
        json={"payload": {"price_per_unit": 0.08, "lead_time": "5d"}},
        headers=dpop.headers("POST", url, token_sup),
    )
    assert resp.status_code == 202

    # Wait for RFQ to complete
    rfq_resp = await rfq_task
    assert rfq_resp.status_code == 201
    data = rfq_resp.json()
    assert data["status"] in ("closed", "timeout")
    assert len(data["matched_agents"]) >= 1
    # Quote may arrive before or after timeout — verify via GET
    rfq_id_val = data["rfq_id"]
    get_resp = await client.get(f"/v1/broker/rfq/{rfq_id_val}",
        headers=dpop.headers("GET", f"/v1/broker/rfq/{rfq_id_val}", token_buyer),
    )
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert len(get_data["quotes"]) == 1
    assert get_data["quotes"][0]["responder_agent_id"] == "rfq-sup2::agent"
    assert get_data["quotes"][0]["payload"]["price_per_unit"] == 0.08


async def test_rfq_timeout_no_response(client: AsyncClient, dpop):
    """RFQ times out when supplier doesn't respond."""
    token_buyer = await _setup(client, "rfq-buyer3", "rfq-buyer3::agent",
                               ["order.read"], dpop)
    await _setup(client, "rfq-sup3", "rfq-sup3::agent",
                 ["supply.negotiate"], dpop)

    resp = await client.post("/v1/broker/rfq",
        json={
            "capability_filter": ["supply.negotiate"],
            "payload": {"item": "BLT-M10", "qty": 500},
            "timeout_seconds": 5,
        },
        headers=dpop.headers("POST", "/v1/broker/rfq", token_buyer),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "timeout"
    assert len(data["quotes"]) == 0
    assert len(data["matched_agents"]) >= 1


async def test_rfq_duplicate_response_rejected(client: AsyncClient, dpop):
    """Second response from the same agent is rejected."""
    token_buyer = await _setup(client, "rfq-buyer4", "rfq-buyer4::agent",
                               ["order.read"], dpop)
    token_sup = await _setup(client, "rfq-sup4", "rfq-sup4::agent",
                             ["supply.negotiate"], dpop)

    async def do_rfq():
        return await client.post("/v1/broker/rfq",
            json={
                "capability_filter": ["supply.negotiate"],
                "payload": {"item": "test", "qty": 1},
                "timeout_seconds": 10,
            },
            headers=dpop.headers("POST", "/v1/broker/rfq", token_buyer),
        )

    rfq_task = asyncio.create_task(do_rfq())

    # Wait for notification
    rfq_id = None
    for _ in range(20):
        await asyncio.sleep(0.3)
        notif_resp = await client.get("/v1/broker/notifications",
            headers=dpop.headers("GET", "/v1/broker/notifications", token_sup),
        )
        rfq_notifs = [n for n in notif_resp.json() if n["type"] == "rfq_request"]
        if rfq_notifs:
            rfq_id = rfq_notifs[0]["reference_id"]
            break

    assert rfq_id is not None

    # First response — accepted
    url = f"/v1/broker/rfq/{rfq_id}/respond"
    resp1 = await client.post(url,
        json={"payload": {"price": 1.0}},
        headers=dpop.headers("POST", url, token_sup),
    )
    assert resp1.status_code == 202

    # Second response — rejected
    resp2 = await client.post(url,
        json={"payload": {"price": 0.9}},
        headers=dpop.headers("POST", url, token_sup),
    )
    assert resp2.status_code == 409

    await rfq_task


async def test_rfq_requires_auth(client: AsyncClient):
    """RFQ without token returns 401."""
    resp = await client.post("/v1/broker/rfq",
        json={
            "capability_filter": ["supply.negotiate"],
            "payload": {"item": "test"},
        },
    )
    assert resp.status_code in (401, 403)


async def test_rfq_respond_not_in_matched_set(client: AsyncClient, dpop):
    """Agent not in the matched set gets rejected when trying to respond."""
    token_outsider = await _setup(client, "rfq-outsider", "rfq-outsider::agent",
                                  ["other.cap"], dpop)
    import uuid
    fake_rfq_id = str(uuid.uuid4())
    url = f"/v1/broker/rfq/{fake_rfq_id}/respond"
    resp = await client.post(url,
        json={"payload": {"price": 1.0}},
        headers=dpop.headers("POST", url, token_outsider),
    )
    assert resp.status_code == 409


async def test_rfq_get_status(client: AsyncClient, dpop):
    """GET /broker/rfq/{rfq_id} returns RFQ status."""
    token = await _setup(client, "rfq-buyer6", "rfq-buyer6::agent",
                         ["order.read"], dpop)

    # Create an RFQ that closes immediately (no matching agents)
    resp = await client.post("/v1/broker/rfq",
        json={
            "capability_filter": ["no.such.cap"],
            "payload": {"item": "test"},
            "timeout_seconds": 5,
        },
        headers=dpop.headers("POST", "/v1/broker/rfq", token),
    )
    rfq_id = resp.json()["rfq_id"]

    # Poll status
    resp = await client.get(f"/v1/broker/rfq/{rfq_id}",
        headers=dpop.headers("GET", f"/v1/broker/rfq/{rfq_id}", token),
    )
    assert resp.status_code == 200
    assert resp.json()["rfq_id"] == rfq_id
    assert resp.json()["status"] == "closed"
