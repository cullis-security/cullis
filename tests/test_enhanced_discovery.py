"""
Test enhanced discovery — multi-mode search and capability validation on session creation.

Covers:
1. Search by agent_id (direct lookup)
2. Search by SPIFFE URI
3. Search by org_id
4. Search by glob pattern
5. Combined filters (capability + org)
6. Requires at least one parameter
7. include_own_org flag
8. Session creation validates target capabilities
"""
import pytest
from httpx import AsyncClient
from tests.cert_factory import get_org_ca_pem
from tests.conftest import ADMIN_HEADERS, seed_court_agent

pytestmark = pytest.mark.asyncio


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


async def test_search_by_agent_id(client: AsyncClient, dpop):
    """Direct lookup by agent_id returns the specific agent."""
    token = await _setup(client, "ed-buyer1", "ed-buyer1::agent",
                         ["order.read"], dpop)
    await _setup(client, "ed-sup1", "ed-sup1::agent",
                 ["order.read", "order.write"], dpop)

    resp = await client.get("/v1/federation/agents/search",
        params={"agent_id": "ed-sup1::agent"},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["agents"][0]["agent_id"] == "ed-sup1::agent"


async def test_search_by_spiffe_uri(client: AsyncClient, dpop):
    """Direct lookup by SPIFFE URI returns the correct agent."""
    token = await _setup(client, "ed-buyer2", "ed-buyer2::agent",
                         ["order.read"], dpop)
    await _setup(client, "ed-sup2", "ed-sup2::agent",
                 ["supply.negotiate"], dpop)

    resp = await client.get("/v1/federation/agents/search",
        params={"agent_uri": "spiffe://cullis.local/ed-sup2/agent"},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["agents"][0]["agent_id"] == "ed-sup2::agent"


async def test_search_by_org_id(client: AsyncClient, dpop):
    """Search by org_id returns all agents in that org."""
    token = await _setup(client, "ed-buyer3", "ed-buyer3::agent",
                         ["order.read"], dpop)
    await _setup(client, "ed-org3", "ed-org3::alpha",
                 ["cap.a"], dpop)
    await _setup(client, "ed-org3b", "ed-org3b::beta",
                 ["cap.b"], dpop)

    resp = await client.get("/v1/federation/agents/search",
        params={"org_id": "ed-org3"},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 200
    agent_ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "ed-org3::alpha" in agent_ids
    assert "ed-org3b::beta" not in agent_ids


async def test_search_by_pattern(client: AsyncClient, dpop):
    """Glob pattern matches agent_id."""
    token = await _setup(client, "ed-buyer4", "ed-buyer4::agent",
                         ["order.read"], dpop)
    await _setup(client, "ed-pat", "ed-pat::sales",
                 ["supply.negotiate"], dpop)
    await _setup(client, "ed-pat", "ed-pat::support",
                 ["support.ticket"], dpop)

    resp = await client.get("/v1/federation/agents/search",
        params={"pattern": "ed-pat::*"},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 200
    agent_ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "ed-pat::sales" in agent_ids
    assert "ed-pat::support" in agent_ids


async def test_search_combined_capability_and_org(client: AsyncClient, dpop):
    """Capability + org_id intersection filters correctly."""
    token = await _setup(client, "ed-buyer5", "ed-buyer5::agent",
                         ["order.read"], dpop)
    await _setup(client, "ed-comb", "ed-comb::with-cap",
                 ["supply.negotiate", "order.read"], dpop)
    await _setup(client, "ed-comb", "ed-comb::no-cap",
                 ["support.ticket"], dpop)

    resp = await client.get("/v1/federation/agents/search",
        params={"org_id": "ed-comb", "capability": ["supply.negotiate"]},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 200
    agent_ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "ed-comb::with-cap" in agent_ids
    assert "ed-comb::no-cap" not in agent_ids


async def test_search_requires_at_least_one_param(client: AsyncClient, dpop):
    """No parameters returns 422."""
    token = await _setup(client, "ed-buyer6", "ed-buyer6::agent",
                         ["order.read"], dpop)

    resp = await client.get("/v1/federation/agents/search",
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 422


async def test_search_include_own_org(client: AsyncClient, dpop):
    """With include_own_org=true, own org agents appear in results."""
    token = await _setup(client, "ed-own", "ed-own::agent",
                         ["order.read"], dpop)

    # Without flag — own org excluded
    resp = await client.get("/v1/federation/agents/search",
        params={"capability": ["order.read"]},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    agent_ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "ed-own::agent" not in agent_ids

    # With flag — own org included
    resp = await client.get("/v1/federation/agents/search",
        params={"capability": ["order.read"], "include_own_org": "true"},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    agent_ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "ed-own::agent" in agent_ids


async def test_session_creation_validates_target_capabilities(client: AsyncClient, dpop, db_session):
    """Session denied when target's agent record doesn't advertise the requested capability."""
    import json as _json
    from app.registry.store import get_agent_by_id
    # Setup both with supply.negotiate initially
    token_buyer = await _setup(client, "ed-cap-buyer", "ed-cap-buyer::agent",
                               ["order.read", "supply.negotiate"], dpop)
    await _setup(client, "ed-cap-sup", "ed-cap-sup::agent",
                 ["order.read", "supply.negotiate"], dpop)

    # Now remove supply.negotiate from the target's agent record directly
    agent = await get_agent_by_id(db_session, "ed-cap-sup::agent")
    agent.capabilities_json = _json.dumps(["order.read"])
    await db_session.commit()

    resp = await client.post("/v1/broker/sessions",
        json={
            "target_agent_id": "ed-cap-sup::agent",
            "target_org_id": "ed-cap-sup",
            "requested_capabilities": ["supply.negotiate"],
        },
        headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer),
    )
    assert resp.status_code == 400
    assert "does not advertise" in resp.json()["detail"]
