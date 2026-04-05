"""
Tests for the JWKS endpoint and kid in JWT header.
"""
import pytest
from jose import jwt as jose_jwt

from tests.conftest import ADMIN_HEADERS


@pytest.mark.asyncio
async def test_jwks_endpoint_returns_valid_jwk(client):
    """GET /.well-known/jwks.json returns a valid JWKS with RSA key."""
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200

    data = resp.json()
    assert "keys" in data
    assert len(data["keys"]) == 1

    jwk = data["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert "kid" in jwk
    assert "n" in jwk
    assert "e" in jwk


@pytest.mark.asyncio
async def test_jwks_no_auth_required(client):
    """JWKS endpoint is public — no Authorization header needed."""
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_jwks_cache_control(client):
    """JWKS response should be cacheable (not no-store)."""
    resp = await client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    assert "public" in resp.headers.get("cache-control", "")
    assert "max-age=3600" in resp.headers.get("cache-control", "")


@pytest.mark.asyncio
async def test_jwks_no_dpop_nonce(client):
    """JWKS response should not include DPoP-Nonce header."""
    resp = await client.get("/.well-known/jwks.json")
    assert "DPoP-Nonce" not in resp.headers


@pytest.mark.asyncio
async def test_kid_in_jwt_matches_jwks(client, dpop):
    """The kid in a freshly issued JWT must match the kid in the JWKS."""
    from tests.cert_factory import get_org_ca_pem

    # Register org + agent + binding (same pattern as test_auth.py)
    org_id = "jwksorg"
    org_secret = org_id + "-secret"
    agent_id = f"{org_id}::agent"
    hdrs = {"x-org-id": org_id, "x-org-secret": org_secret}

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem}, headers=hdrs)
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": "A", "capabilities": ["test.read"],
    }, headers=hdrs)
    resp = await client.post("/v1/registry/bindings", json={
        "org_id": org_id, "agent_id": agent_id, "scope": ["test.read"],
    }, headers=hdrs)
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers=hdrs)

    # Get token via DPoPHelper
    access_token = await dpop.get_token(client, agent_id, org_id)

    # Extract kid from JWT header (unverified)
    header = jose_jwt.get_unverified_header(access_token)
    assert "kid" in header

    # Get kid from JWKS
    jwks_resp = await client.get("/.well-known/jwks.json")
    jwks_kid = jwks_resp.json()["keys"][0]["kid"]

    assert header["kid"] == jwks_kid


def test_compute_kid_deterministic():
    """compute_kid must return the same value for the same key."""
    from app.auth.jwks import compute_kid
    from tests.cert_factory import init_broker_keys

    _, pub_pem = init_broker_keys()
    kid1 = compute_kid(pub_pem)
    kid2 = compute_kid(pub_pem)
    assert kid1 == kid2
    assert len(kid1) > 10  # sanity check — base64url SHA-256 is 43 chars
