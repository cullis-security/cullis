"""
Test onboarding — join request e admin approval.

Verifica:
1. JOIN crea org in stato pending
2. Org pending non può autenticarsi
3. Admin vede le org pending
4. Admin approva → org diventa active → può autenticarsi
5. Admin rifiuta → org diventa rejected
6. Admin secret sbagliato → 403
"""
import pytest
from httpx import AsyncClient
from tests.cert_factory import make_assertion, get_org_ca_pem

pytestmark = pytest.mark.asyncio

from app.config import get_settings
ADMIN_SECRET = get_settings().admin_secret


async def _join(client: AsyncClient, org_id: str) -> dict:
    ca_pem = get_org_ca_pem(org_id)
    resp = await client.post("/onboarding/join", json={
        "org_id":         org_id,
        "display_name":   org_id,
        "secret":         org_id + "-secret",
        "ca_certificate": ca_pem,
        "contact_email":  f"admin@{org_id}.test",
    })
    return resp


async def test_join_creates_pending_org(client: AsyncClient):
    resp = await _join(client, "join-org-a")
    assert resp.status_code == 202
    assert resp.json()["status"] == "pending"


async def test_pending_org_cannot_login(client: AsyncClient, dpop):
    await _join(client, "join-blocked")
    await client.post("/registry/agents", json={
        "agent_id": "join-blocked::agent", "org_id": "join-blocked",
        "display_name": "test", "capabilities": [],
    })
    assertion = make_assertion("join-blocked::agent", "join-blocked")
    resp = await client.post(
        "/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/auth/token")},
    )
    assert resp.status_code == 403
    assert "approved" in resp.json()["detail"]


async def test_admin_sees_pending_orgs(client: AsyncClient):
    await _join(client, "join-pending-list")
    resp = await client.get("/admin/orgs/pending",
                            headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    org_ids = [o["org_id"] for o in resp.json()]
    assert "join-pending-list" in org_ids


async def test_admin_wrong_secret(client: AsyncClient):
    resp = await client.get("/admin/orgs/pending",
                            headers={"x-admin-secret": "wrong"})
    assert resp.status_code == 403


async def test_approve_allows_login(client: AsyncClient, dpop):
    org_id = "join-approve-test"
    agent_id = f"{org_id}::agent"
    org_secret = org_id + "-secret"

    await _join(client, org_id)
    await client.post("/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["order.read"],
    })

    # Approva
    resp = await client.post(f"/admin/orgs/{org_id}/approve",
                             headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"

    # Ora il binding e il login devono funzionare
    resp = await client.post("/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code == 201
    binding_id = resp.json()["id"]
    await client.post(f"/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    assertion = make_assertion(agent_id, org_id)
    resp = await client.post(
        "/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/auth/token")},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


async def test_reject_blocks_org(client: AsyncClient):
    await _join(client, "join-reject-test")

    resp = await client.post("/admin/orgs/join-reject-test/reject",
                             headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"

    # Verifica stato
    resp = await client.get("/registry/orgs/join-reject-test")
    assert resp.json()["status"] == "rejected"


async def test_join_duplicate_rejected(client: AsyncClient):
    await _join(client, "join-dup")
    resp = await _join(client, "join-dup")
    assert resp.status_code == 409
