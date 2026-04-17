"""
Tests for the org ↔ agent binding system.

Verifies that:
- Only agents with "approved" binding can obtain a token
- The session requires an approved binding on the target as well
- The requested capabilities are a subset of the scope of both bindings
"""
import pytest
from httpx import AsyncClient

from tests.cert_factory import make_assertion, get_org_ca_pem
from tests.conftest import ADMIN_HEADERS, seed_court_agent

pytestmark = pytest.mark.asyncio

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

async def _register_org(client: AsyncClient, org_id: str, org_secret: str):
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)


async def _upload_ca(client: AsyncClient, org_id: str, org_secret: str):
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )


async def _register_agent(client: AsyncClient, agent_id: str, org_id: str,
                           capabilities: list[str] | None = None,
                           org_secret: str | None = None):
    secret = org_secret or (org_id + "-secret")
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=capabilities or [],
    )


async def _create_binding(client: AsyncClient, org_id: str, org_secret: str,
                           agent_id: str, scope: list[str]) -> int:
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": scope},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _approve_binding(client: AsyncClient, binding_id: int, org_id: str, org_secret: str):
    resp = await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code == 200, resp.text


async def _revoke_binding(client: AsyncClient, binding_id: int, org_id: str, org_secret: str):
    resp = await client.post(f"/v1/registry/bindings/{binding_id}/revoke",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code == 200, resp.text


async def _get_token(client: AsyncClient, agent_id: str, org_id: str, dpop=None):
    from tests.cert_factory import DPoPHelper
    _dpop = dpop or DPoPHelper()
    assertion = make_assertion(agent_id, org_id)
    proof = _dpop.proof("POST", "/v1/auth/token")
    return await client.post("/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )


# ---------------------------------------------------------------------------
# Test: token issuance with bindings in different states
# ---------------------------------------------------------------------------

async def test_token_denied_no_binding(client: AsyncClient):
    """Agent without binding cannot obtain a token → 403."""
    await _register_org(client, "nb-org", "nb-org-secret")
    await _upload_ca(client, "nb-org", "nb-org-secret")
    await _register_agent(client, "nb-org::agent", "nb-org")
    # No binding created

    resp = await _get_token(client, "nb-org::agent", "nb-org")
    assert resp.status_code == 403
    assert "binding" in resp.json()["detail"].lower()


async def test_token_denied_pending_binding(client: AsyncClient):
    """Agent with 'pending' binding cannot obtain a token → 403."""
    await _register_org(client, "pending-org", "pending-org-secret")
    await _upload_ca(client, "pending-org", "pending-org-secret")
    await _register_agent(client, "pending-org::agent", "pending-org", capabilities=["kyc.read"])
    await _create_binding(client, "pending-org", "pending-org-secret",
                          "pending-org::agent", ["kyc.read"])
    # Binding created but NOT approved

    resp = await _get_token(client, "pending-org::agent", "pending-org")
    assert resp.status_code == 403
    assert "binding" in resp.json()["detail"].lower()


async def test_token_issued_with_approved_binding(client: AsyncClient):
    """Agent with 'approved' binding obtains token → 200 with scope."""
    await _register_org(client, "approved-org", "approved-org-secret")
    await _upload_ca(client, "approved-org", "approved-org-secret")
    await _register_agent(client, "approved-org::agent", "approved-org",
                           capabilities=["kyc.read"])
    bid = await _create_binding(client, "approved-org", "approved-org-secret",
                                 "approved-org::agent", ["kyc.read"])
    await _approve_binding(client, bid, "approved-org", "approved-org-secret")

    resp = await _get_token(client, "approved-org::agent", "approved-org")
    assert resp.status_code == 200
    assert "access_token" in resp.json()


async def test_token_denied_revoked_binding(client: AsyncClient):
    """Agent with 'revoked' binding cannot obtain a token → 403."""
    await _register_org(client, "revoked-org", "revoked-org-secret")
    await _upload_ca(client, "revoked-org", "revoked-org-secret")
    await _register_agent(client, "revoked-org::agent", "revoked-org", capabilities=["kyc.read"])
    bid = await _create_binding(client, "revoked-org", "revoked-org-secret",
                                 "revoked-org::agent", ["kyc.read"])
    await _approve_binding(client, bid, "revoked-org", "revoked-org-secret")
    await _revoke_binding(client, bid, "revoked-org", "revoked-org-secret")

    resp = await _get_token(client, "revoked-org::agent", "revoked-org")
    assert resp.status_code == 403
    assert "binding" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test: sessions with missing binding or insufficient scope
# ---------------------------------------------------------------------------

async def _full_setup(client: AsyncClient, org_id: str, agent_id: str,
                      scope: list[str], dpop=None) -> str:
    """Register org + CA + agent + approved binding, return token."""
    from tests.cert_factory import DPoPHelper
    _dpop = dpop or DPoPHelper()
    org_secret = org_id + "-secret"

    await _register_org(client, org_id, org_secret)
    await _upload_ca(client, org_id, org_secret)
    await _register_agent(client, agent_id, org_id, capabilities=scope)
    bid = await _create_binding(client, org_id, org_secret, agent_id, scope)
    await _approve_binding(client, bid, org_id, org_secret)

    return await _dpop.get_token(client, agent_id, org_id)


async def test_session_denied_target_no_binding(client: AsyncClient, dpop):
    """Session with target that has no approved binding → 403."""
    token_a = await _full_setup(client, "s-org-a", "s-org-a::agent", ["kyc.read"], dpop)

    # Target registered but without binding
    await _register_org(client, "s-org-no-bind", "s-org-no-bind-secret")
    await _register_agent(client, "s-org-no-bind::agent", "s-org-no-bind")

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "s-org-no-bind::agent",
        "target_org_id": "s-org-no-bind",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    assert resp.status_code == 403
    assert "binding" in resp.json()["detail"].lower()


async def test_session_denied_capability_not_in_initiator_scope(client: AsyncClient, dpop):
    """Session with capability outside the initiator's scope → 403."""
    token_a = await _full_setup(client, "scope-a-org", "scope-a-org::agent", ["kyc.read"], dpop)
    await _full_setup(client, "scope-b-org", "scope-b-org::agent", ["kyc.read", "kyc.write"], dpop)

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "scope-b-org::agent",
        "target_org_id": "scope-b-org",
        "requested_capabilities": ["kyc.write"],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    assert resp.status_code == 403
    assert "scope" in resp.json()["detail"].lower()


async def test_session_denied_capability_not_in_target_scope(client: AsyncClient, dpop):
    """Session with capability outside the target's scope → 403."""
    token_a = await _full_setup(client, "sc2-a-org", "sc2-a-org::agent",
                                  ["kyc.read", "kyc.write"], dpop)
    await _full_setup(client, "sc2-b-org", "sc2-b-org::agent", ["kyc.read"], dpop)

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "sc2-b-org::agent",
        "target_org_id": "sc2-b-org",
        "requested_capabilities": ["kyc.write"],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    assert resp.status_code == 403
    assert "scope" in resp.json()["detail"].lower()
