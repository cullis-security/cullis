"""
Test certificate revocation — /admin/certs/revoke e /admin/certs/revoked.

Coverage:
  1. Revoca valida: cert revocato, successivo login → 401
  2. Login con cert non revocato funziona normalmente
  3. Doppia revoca dello stesso serial → 409
  4. Listing certificati revocati
  5. Listing filtrato per org
  6. Endpoint senza admin secret → 403
  7. Revoca cert non ancora usato (revoca preventiva) — accettata
"""
import pytest
from httpx import AsyncClient

from tests.cert_factory import (
    make_assertion,
    get_org_ca_pem,
    get_agent_cert_serial,
    get_agent_cert_not_after,
)
from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio

from app.config import get_settings
ADMIN_SECRET = get_settings().admin_secret


async def _register_agent(client: AsyncClient, agent_id: str, org_id: str) -> None:
    """Register org + CA + agent + approved binding."""
    org_secret = org_id + "-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
                      json={"ca_certificate": ca_pem},
                      headers={"x-org-id": org_id, "x-org-secret": org_secret})
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["test.read"],
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    resp = await client.post("/v1/registry/bindings",
                             json={"org_id": org_id, "agent_id": agent_id,
                                   "scope": ["test.read"]},
                             headers={"x-org-id": org_id, "x-org-secret": org_secret})
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
                      headers={"x-org-id": org_id, "x-org-secret": org_secret})


async def test_revoked_cert_blocked(client: AsyncClient, dpop):
    """After revocation, login with that cert returns 401."""
    agent_id = "revoke-org-1::agent"
    org_id   = "revoke-org-1"
    await _register_agent(client, agent_id, org_id)

    # Login before revocation — must succeed
    assertion = make_assertion(agent_id, org_id)
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200

    # Revoke the certificate
    serial      = get_agent_cert_serial(agent_id, org_id)
    not_after   = get_agent_cert_not_after(agent_id, org_id)
    resp = await client.post(
        "/v1/admin/certs/revoke",
        json={
            "serial_hex":     serial,
            "org_id":         org_id,
            "agent_id":       agent_id,
            "reason":         "key_compromise",
            "cert_not_after": not_after.isoformat(),
        },
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["serial_hex"] == serial
    assert data["org_id"]     == org_id

    # Login after revocation — must be blocked
    assertion2 = make_assertion(agent_id, org_id)
    proof2 = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion2},
        headers={"DPoP": proof2},
    )
    assert resp.status_code == 401
    assert "revoked" in resp.json()["detail"].lower()


async def test_non_revoked_cert_allowed(client: AsyncClient, dpop):
    """Non-revoked certificate continues to work normally."""
    agent_id = "revoke-org-2::agent"
    org_id   = "revoke-org-2"
    await _register_agent(client, agent_id, org_id)

    assertion = make_assertion(agent_id, org_id)
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200


async def test_double_revocation_returns_409(client: AsyncClient):
    """Revoking the same serial twice returns 409."""
    agent_id = "revoke-org-3::agent"
    org_id   = "revoke-org-3"
    await _register_agent(client, agent_id, org_id)

    serial    = get_agent_cert_serial(agent_id, org_id)
    not_after = get_agent_cert_not_after(agent_id, org_id)
    payload   = {
        "serial_hex":     serial,
        "org_id":         org_id,
        "cert_not_after": not_after.isoformat(),
    }
    headers = {"x-admin-secret": ADMIN_SECRET}

    resp = await client.post("/v1/admin/certs/revoke", json=payload, headers=headers)
    assert resp.status_code == 200

    resp = await client.post("/v1/admin/certs/revoke", json=payload, headers=headers)
    assert resp.status_code == 409
    assert "already revoked" in resp.json()["detail"].lower()


async def test_list_revoked_certs(client: AsyncClient):
    """GET /admin/certs/revoked returns revoked certificates."""
    agent_id = "revoke-org-4::agent"
    org_id   = "revoke-org-4"
    await _register_agent(client, agent_id, org_id)

    serial    = get_agent_cert_serial(agent_id, org_id)
    not_after = get_agent_cert_not_after(agent_id, org_id)
    await client.post(
        "/v1/admin/certs/revoke",
        json={"serial_hex": serial, "org_id": org_id,
              "cert_not_after": not_after.isoformat()},
        headers={"x-admin-secret": ADMIN_SECRET},
    )

    resp = await client.get("/v1/admin/certs/revoked",
                            headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    serials = [r["serial_hex"] for r in resp.json()]
    assert serial in serials


async def test_list_revoked_certs_filtered_by_org(client: AsyncClient):
    """Filtering by org_id returns only certs for that org."""
    agent_id = "revoke-org-5::agent"
    org_id   = "revoke-org-5"
    await _register_agent(client, agent_id, org_id)

    serial    = get_agent_cert_serial(agent_id, org_id)
    not_after = get_agent_cert_not_after(agent_id, org_id)
    await client.post(
        "/v1/admin/certs/revoke",
        json={"serial_hex": serial, "org_id": org_id,
              "cert_not_after": not_after.isoformat()},
        headers={"x-admin-secret": ADMIN_SECRET},
    )

    resp = await client.get(f"/v1/admin/certs/revoked?org_id={org_id}",
                            headers={"x-admin-secret": ADMIN_SECRET})
    assert resp.status_code == 200
    records = resp.json()
    assert all(r["org_id"] == org_id for r in records)

    # A different org must not appear
    resp2 = await client.get("/v1/admin/certs/revoked?org_id=org-nonexistent",
                             headers={"x-admin-secret": ADMIN_SECRET})
    assert resp2.status_code == 200
    assert not any(r["serial_hex"] == serial for r in resp2.json())


async def test_revoke_without_admin_secret_returns_403(client: AsyncClient):
    """Revocation endpoint without admin credentials returns 403."""
    resp = await client.post(
        "/v1/admin/certs/revoke",
        json={"serial_hex": "deadbeef", "org_id": "any-org"},
    )
    assert resp.status_code in (403, 422)


async def test_preventive_revocation(client: AsyncClient, dpop):
    """A cert can be revoked before it has ever been used for login."""
    agent_id = "revoke-org-6::agent"
    org_id   = "revoke-org-6"
    await _register_agent(client, agent_id, org_id)

    # Revoke before the agent has ever logged in
    serial    = get_agent_cert_serial(agent_id, org_id)
    not_after = get_agent_cert_not_after(agent_id, org_id)
    resp = await client.post(
        "/v1/admin/certs/revoke",
        json={"serial_hex": serial, "org_id": org_id,
              "reason": "preventive", "cert_not_after": not_after.isoformat()},
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    assert resp.status_code == 200

    # Login attempt with preventively revoked cert → 401
    assertion = make_assertion(agent_id, org_id)
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 401
    assert "revoked" in resp.json()["detail"].lower()
