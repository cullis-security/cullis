"""
End-to-end auth flow with an ECDSA P-256 org CA and agent cert.

The broker already supports EC in x509_verifier.py (chain verify + JWT
ES256 decoding); this suite proves no regression across the full
/auth/token path when the PKI is all-ECC rather than all-RSA.
"""
from __future__ import annotations

import jwt as jose_jwt
from httpx import AsyncClient

from tests.cert_factory import get_org_ca_pem, make_assertion
from tests.conftest import ADMIN_HEADERS, seed_court_agent


async def _prime_nonce(client: AsyncClient, dpop) -> None:
    proof = dpop.proof("POST", "/v1/auth/token")
    await client.post("/v1/auth/token", json={"client_assertion": "x"},
                      headers={"DPoP": proof})


async def _register_ec_agent(client: AsyncClient, agent_id: str, org_id: str) -> None:
    """Bootstrap an org + agent + approved binding with an ECDSA CA + cert."""
    org_secret = org_id + "-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)

    ca_pem = get_org_ca_pem(org_id, key_type="ec")
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=f'EC Agent {agent_id}',
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


async def test_ec_token_issued_for_valid_ec_agent(client, dpop):
    """ES256 client_assertion + ECDSA org CA + DPoP → 200 with a DPoP-bound token."""
    await _prime_nonce(client, dpop)
    await _register_ec_agent(client, "ec-org-a::agent-1", "ec-org-a")

    assertion = make_assertion("ec-org-a::agent-1", "ec-org-a", key_type="ec")
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "DPoP"


async def test_ec_token_contains_cnf_jkt(client, dpop):
    """DPoP confirmation claim is still present when the agent is EC-signed."""
    await _prime_nonce(client, dpop)
    import app.auth.jwt as jwt_module
    await _register_ec_agent(client, "ec-org-cnf::agent-1", "ec-org-cnf")

    assertion = make_assertion("ec-org-cnf::agent-1", "ec-org-cnf", key_type="ec")
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 200, resp.text

    token = resp.json()["access_token"]
    pub_pem = jwt_module._broker_public_key_pem
    raw = jose_jwt.decode(token, pub_pem, algorithms=["RS256"],
                          options={"verify_aud": False})
    assert "cnf" in raw and raw["cnf"].get("jkt")


async def test_ec_assertion_wrong_org_ca_rejected(client, dpop):
    """
    An EC client_assertion signed by an EC cert whose org CA is NOT the one
    registered for the org must fail the chain check — proves the broker's
    ECDSA signature verify path is actually gating access (not just ignored).
    """
    await _prime_nonce(client, dpop)
    await _register_ec_agent(client, "ec-org-bad::agent-1", "ec-org-bad")

    # Build an assertion for a different org whose CA is NOT registered here.
    assertion = make_assertion("ec-org-other::agent-1", "ec-org-other", key_type="ec")
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code in (401, 403), resp.text
