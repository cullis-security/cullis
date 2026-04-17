"""
Test access token revocation (token_invalidated_at watermark).

Coverage:
  1. Self-revoke: token issued before revocation is rejected
  2. New login after self-revoke is accepted
  3. Admin revoke via POST /auth/revoke-agent/{agent_id}
  4. Admin revoke rejects wrong org credentials
  5. Admin revoke rejects cross-org attempts (org A cannot revoke org B agent)
  6. Binding revocation automatically invalidates active access tokens
"""
import pytest
from httpx import AsyncClient

from tests.cert_factory import make_assertion, get_org_ca_pem
from tests.conftest import ADMIN_HEADERS, seed_court_agent

pytestmark = pytest.mark.asyncio


async def _setup_agent(client: AsyncClient, agent_id: str, org_id: str, dpop) -> str:
    """Register org + CA + agent + approved binding. Returns an access token."""
    org_secret = f"{org_id}-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)

    ca_pem = get_org_ca_pem(org_id)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=f'Test {agent_id}',
        capabilities=['test.read'],
    )

    resp = await client.post(
        "/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(
        f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    token = await dpop.get_token(client, agent_id, org_id)
    return token


async def test_self_revoke_rejects_old_token(client: AsyncClient, dpop):
    """After POST /auth/revoke, the same token returns 401 on the next request."""
    token = await _setup_agent(client, "tok-rev-a::agent-1", "tok-rev-a", dpop)

    # Token works before revocation
    resp = await client.get(
        "/v1/federation/agents",
        params={"org_id": "tok-rev-a"},
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp.status_code == 200

    # Self-revoke
    rev = await client.post("/v1/auth/revoke", headers=dpop.headers("POST", "/v1/auth/revoke", token))
    assert rev.status_code == 204

    # Same token is now rejected
    resp2 = await client.get(
        "/v1/federation/agents",
        params={"org_id": "tok-rev-a"},
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp2.status_code == 401
    assert "revoked" in resp2.json()["detail"].lower()


async def test_new_token_accepted_after_self_revoke(client: AsyncClient, dpop):
    """A token obtained via new login after revocation must work normally.

    JWT iat is in integer seconds. We must wait for the next second boundary so
    the new token's iat is strictly greater than token_invalidated_at (which
    is also truncated to the same second as the revoke call).
    """
    import asyncio

    token = await _setup_agent(client, "tok-rev-b::agent-1", "tok-rev-b", dpop)

    # Revoke
    rev = await client.post("/v1/auth/revoke", headers=dpop.headers("POST", "/v1/auth/revoke", token))
    assert rev.status_code == 204

    # Wait for the next second boundary so the new token has a different iat
    await asyncio.sleep(1.1)

    # New login — use DPoP proof for the token request
    new_token_resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": make_assertion("tok-rev-b::agent-1", "tok-rev-b")},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert new_token_resp.status_code == 200
    new_token = new_token_resp.json()["access_token"]

    # New token is accepted
    resp = await client.get(
        "/v1/federation/agents",
        params={"org_id": "tok-rev-b"},
        headers=dpop.headers("GET", "/v1/federation/agents", new_token),
    )
    assert resp.status_code == 200


async def test_admin_revoke_invalidates_agent_tokens(client: AsyncClient, dpop):
    """POST /auth/revoke-agent/{agent_id} with org credentials rejects the agent's token."""
    token = await _setup_agent(client, "tok-rev-c::agent-1", "tok-rev-c", dpop)

    # Token works before admin revoke
    resp = await client.get(
        "/v1/federation/agents",
        params={"org_id": "tok-rev-c"},
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp.status_code == 200

    # Admin revoke — uses X-Org-Id/X-Org-Secret, not Bearer/DPoP
    rev = await client.post(
        "/v1/auth/revoke-agent/tok-rev-c::agent-1",
        headers={"x-org-id": "tok-rev-c", "x-org-secret": "tok-rev-c-secret"},
    )
    assert rev.status_code == 204

    # Token now rejected
    resp2 = await client.get(
        "/v1/federation/agents",
        params={"org_id": "tok-rev-c"},
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp2.status_code == 401
    assert "revoked" in resp2.json()["detail"].lower()


async def test_admin_revoke_wrong_secret(client: AsyncClient, dpop):
    """Admin revoke with wrong org secret returns 403."""
    await _setup_agent(client, "tok-rev-d::agent-1", "tok-rev-d", dpop)

    rev = await client.post(
        "/v1/auth/revoke-agent/tok-rev-d::agent-1",
        headers={"x-org-id": "tok-rev-d", "x-org-secret": "wrong-secret"},
    )
    assert rev.status_code == 403


async def test_admin_revoke_cross_org_rejected(client: AsyncClient, dpop):
    """Org F cannot revoke tokens for an agent belonging to org E.

    Audit F-B-8: response collapses to 404 (same as missing agent) so
    org F cannot enumerate org E's agents by observing 404 vs 403.
    """
    await _setup_agent(client, "tok-rev-e::agent-1", "tok-rev-e", dpop)
    await _setup_agent(client, "tok-rev-f::agent-1", "tok-rev-f", dpop)

    rev = await client.post(
        "/v1/auth/revoke-agent/tok-rev-e::agent-1",
        headers={"x-org-id": "tok-rev-f", "x-org-secret": "tok-rev-f-secret"},
    )
    assert rev.status_code == 404


async def test_admin_revoke_missing_vs_cross_org_indistinguishable(
    client: AsyncClient, dpop,
):
    """Audit F-B-8: the 404 response for 'agent does not exist in any
    org' and 'agent exists but in a different org' must be byte-
    identical — status code and detail body alike. Otherwise an
    attacker with any org_secret can enumerate agents across the whole
    broker fleet.

    Distinct org_ids (``fb8-x``/``fb8-y``) avoid colliding with
    sibling tests in this file that reuse ``tok-rev-*`` org names.
    """
    # org X registered + has an agent, org Y registered without agents.
    await _setup_agent(client, "fb8-x::agent-1", "fb8-x", dpop)

    import bcrypt
    import json
    from app.registry.org_store import OrganizationRecord
    from tests.conftest import TestSessionLocal

    async with TestSessionLocal() as session:
        session.add(OrganizationRecord(
            org_id="fb8-y",
            display_name="fb8-y",
            secret_hash=bcrypt.hashpw(
                b"fb8-y-secret", bcrypt.gensalt(rounds=4),
            ).decode(),
            metadata_json=json.dumps({}),
            status="active",
        ))
        await session.commit()

    # Case 1: agent does not exist anywhere.
    missing = await client.post(
        "/v1/auth/revoke-agent/fb8-y::never-registered",
        headers={"x-org-id": "fb8-y", "x-org-secret": "fb8-y-secret"},
    )
    # Case 2: agent exists but in a different org (fb8-x).
    cross_org = await client.post(
        "/v1/auth/revoke-agent/fb8-x::agent-1",
        headers={"x-org-id": "fb8-y", "x-org-secret": "fb8-y-secret"},
    )

    assert missing.status_code == cross_org.status_code == 404
    assert missing.json() == cross_org.json()


async def test_binding_revocation_invalidates_tokens(client: AsyncClient, dpop):
    """
    When an org revokes a binding, the agent's active access tokens are
    immediately invalidated — no need to wait for token expiry.
    """
    org_id = "tok-rev-g"
    agent_id = "tok-rev-g::agent-1"
    org_secret = f"{org_id}-secret"

    token = await _setup_agent(client, agent_id, org_id, dpop)

    # Token works
    resp = await client.get(
        "/v1/federation/agents",
        params={"org_id": org_id},
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp.status_code == 200

    # Find the binding
    bindings_resp = await client.get(
        "/v1/registry/bindings",
        params={"org_id": org_id},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert bindings_resp.status_code == 200
    binding_id = bindings_resp.json()[0]["id"]

    # Revoke the binding — uses X-Org-Id/X-Org-Secret, not Bearer/DPoP
    rev = await client.post(
        f"/v1/registry/bindings/{binding_id}/revoke",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert rev.status_code == 200
    assert rev.json()["status"] == "revoked"

    # Token is now rejected because binding revocation triggers token invalidation
    resp2 = await client.get(
        "/v1/federation/agents",
        params={"org_id": org_id},
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp2.status_code == 401
    assert "revoked" in resp2.json()["detail"].lower()
