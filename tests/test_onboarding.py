"""
Test onboarding — join request e admin approval.

Verifica:
1. JOIN crea org in stato pending (requires invite token)
2. Org pending non può autenticarsi
3. Admin vede le org pending
4. Admin approva → org diventa active → può autenticarsi
5. Admin rifiuta → org diventa rejected
6. Admin secret sbagliato → 403
7. Join without invite token → 403
"""
import pytest
from httpx import AsyncClient
from tests.cert_factory import make_assertion, get_org_ca_pem

pytestmark = pytest.mark.asyncio

from app.config import get_settings
from tests.conftest import seed_court_agent
ADMIN_SECRET = get_settings().admin_secret


async def _generate_invite(client: AsyncClient, label: str = "") -> str:
    """Generate an invite token via admin API and return the plaintext."""
    resp = await client.post("/v1/admin/invites", json={
        "label": label, "ttl_hours": 72,
    }, headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 201
    return resp.json()["token"]


async def _join(client: AsyncClient, org_id: str, invite_token: str | None = None) -> dict:
    if invite_token is None:
        invite_token = await _generate_invite(client, label=org_id)
    ca_pem = get_org_ca_pem(org_id)
    resp = await client.post("/v1/onboarding/join", json={
        "org_id":         org_id,
        "display_name":   org_id,
        "secret":         org_id + "-secret",
        "ca_certificate": ca_pem,
        "contact_email":  f"admin@{org_id}.test",
        "invite_token":   invite_token,
    })
    return resp


async def test_join_creates_pending_org(client: AsyncClient):
    resp = await _join(client, "join-org-a")
    assert resp.status_code == 202
    assert resp.json()["status"] == "pending"


async def test_pending_org_cannot_login(client: AsyncClient, dpop):
    await _join(client, "join-blocked")
    await seed_court_agent(
        agent_id='join-blocked::agent',
        org_id='join-blocked',
        display_name='test',
        capabilities=[],
    )
    assertion = make_assertion("join-blocked::agent", "join-blocked")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 403
    assert "approved" in resp.json()["detail"]


async def test_admin_sees_pending_orgs(client: AsyncClient):
    await _join(client, "join-pending-list")
    resp = await client.get("/v1/admin/orgs/pending",
                            headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    org_ids = [o["org_id"] for o in resp.json()]
    assert "join-pending-list" in org_ids


async def test_admin_wrong_secret(client: AsyncClient):
    resp = await client.get("/v1/admin/orgs/pending",
                            headers={"x-admin-secret": "wrong"})
    assert resp.status_code == 403


async def test_approve_allows_login(client: AsyncClient, dpop):
    org_id = "join-approve-test"
    agent_id = f"{org_id}::agent"
    org_secret = org_id + "-secret"

    await _join(client, org_id)

    # Approva prima — agents can only be registered for active orgs (#34)
    resp = await client.post(f"/v1/admin/orgs/{org_id}/approve",
                             headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"

    # Register agent after org is active
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=['order.read'],
    )

    # Ora il binding e il login devono funzionare
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code == 201
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    assertion = make_assertion(agent_id, org_id)
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


async def test_reject_blocks_org(client: AsyncClient):
    await _join(client, "join-reject-test")

    resp = await client.post("/v1/admin/orgs/join-reject-test/reject",
                             headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"

    # Verifica stato
    resp = await client.get("/v1/registry/orgs/join-reject-test")
    assert resp.json()["status"] == "rejected"


async def test_join_duplicate_rejected(client: AsyncClient):
    await _join(client, "join-dup")
    resp = await _join(client, "join-dup")
    assert resp.status_code == 409


async def test_join_without_invite_token_rejected(client: AsyncClient):
    """Join request without a valid invite token should be rejected."""
    ca_pem = get_org_ca_pem("join-no-invite")
    resp = await client.post("/v1/onboarding/join", json={
        "org_id":         "join-no-invite",
        "display_name":   "No Invite Org",
        "secret":         "no-invite-secret",
        "ca_certificate": ca_pem,
        "contact_email":  "test@no-invite.test",
        "invite_token":   "invalid-garbage-token",
    })
    assert resp.status_code == 403
    assert "invite" in resp.json()["detail"].lower()


async def test_invite_token_single_use(client: AsyncClient):
    """An invite token can only be used once."""
    token = await _generate_invite(client, label="single-use-test")
    resp = await _join(client, "join-single-a", invite_token=token)
    assert resp.status_code == 202

    # Second use of same token should fail
    ca_pem = get_org_ca_pem("join-single-b")
    resp = await client.post("/v1/onboarding/join", json={
        "org_id":         "join-single-b",
        "display_name":   "Second Use",
        "secret":         "second-secret",
        "ca_certificate": ca_pem,
        "contact_email":  "test@second.test",
        "invite_token":   token,
    })
    assert resp.status_code == 403


async def test_admin_can_list_invites(client: AsyncClient):
    """Admin can list all invite tokens."""
    await _generate_invite(client, label="list-test")
    resp = await client.get("/v1/admin/invites",
                            headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    invites = resp.json()
    assert any(i["label"] == "list-test" for i in invites)
    # Plaintext token should never be returned in list
    assert all(i["token"] is None for i in invites)


async def test_admin_can_revoke_invite(client: AsyncClient):
    """Revoking an invite makes it unusable."""
    resp = await client.post("/v1/admin/invites", json={
        "label": "revoke-test", "ttl_hours": 72,
    }, headers={"x-admin-secret": ADMIN_SECRET})
    invite_id = resp.json()["id"]
    token = resp.json()["token"]

    # Revoke it
    resp = await client.post(f"/v1/admin/invites/{invite_id}/revoke",
                             headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200

    # Try to use revoked token
    ca_pem = get_org_ca_pem("join-revoked")
    resp = await client.post("/v1/onboarding/join", json={
        "org_id":         "join-revoked",
        "display_name":   "Revoked Org",
        "secret":         "revoked-secret",
        "ca_certificate": ca_pem,
        "contact_email":  "test@revoked.test",
        "invite_token":   token,
    })
    assert resp.status_code == 403
