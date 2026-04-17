"""
Test discovery — GET /registry/agents/search?capability=...

Verifica che:
1. Un agente trova supplier di altre org con le capability richieste
2. La propria org è esclusa dai risultati
3. Capability parziale non restituisce risultati
4. Senza token → 401
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


async def test_discovery_finds_other_org_agents(client: AsyncClient, dpop):
    """Buyer finds supplier from another org with the requested capability."""
    token_buyer = await _setup(client, "disc-buyer", "disc-buyer::agent",
                               ["order.read", "order.write"], dpop)
    await _setup(client, "disc-supplier", "disc-supplier::agent",
                 ["order.read", "order.write"], dpop)

    resp = await client.get("/v1/federation/agents/search",
        params={"capability": ["order.read", "order.write"]},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token_buyer),
    )
    assert resp.status_code == 200
    data = resp.json()
    agent_ids = [a["agent_id"] for a in data["agents"]]
    assert "disc-supplier::agent" in agent_ids


async def test_discovery_excludes_own_org(client: AsyncClient, dpop):
    """Agent does not see its own org in the results."""
    token = await _setup(client, "disc-self", "disc-self::agent",
                         ["order.read"], dpop)
    await _setup(client, "disc-other", "disc-other::agent", ["order.read"], dpop)

    resp = await client.get("/v1/federation/agents/search",
        params={"capability": ["order.read"]},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 200
    agent_ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "disc-self::agent" not in agent_ids
    assert "disc-other::agent" in agent_ids


async def test_discovery_partial_capability_no_match(client: AsyncClient, dpop):
    """Agent with only order.read does not appear when searching for order.write."""
    token_buyer = await _setup(client, "disc-partial-buyer", "disc-partial-buyer::agent",
                               ["order.read", "order.write"], dpop)
    await _setup(client, "disc-partial-sup", "disc-partial-sup::agent",
                 ["order.read"], dpop)  # does not have order.write

    resp = await client.get("/v1/federation/agents/search",
        params={"capability": ["order.read", "order.write"]},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token_buyer),
    )
    assert resp.status_code == 200
    agent_ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "disc-partial-sup::agent" not in agent_ids


async def test_discovery_requires_auth(client: AsyncClient):
    """Senza token → 401."""
    resp = await client.get("/v1/federation/agents/search",
        params={"capability": ["order.read"]},
    )
    assert resp.status_code in (401, 403)
