"""
Test authentication — /auth/token with client_assertion x509 + DPoP proof.

Coverage:
  1.  Token issued for valid agent with correct client_assertion + DPoP proof
  2.  token_type is "DPoP" and cnf.jkt is present in decoded token
  3.  client_assertion with wrong signature → 401
  4.  Unregistered agent (but technically valid cert) → 401
  5.  Org in cert ≠ agent's org in registry → 403
  6.  Replay attack on client_assertion jti → 401
  7.  jti absent in client_assertion → 401
  8.  Missing DPoP header → 422 (required header)
  9.  DPoP proof with wrong htm → 401
  10. DPoP proof with wrong htu → 401
  11. DPoP proof jti replay → 401
  12. DPoP proof with expired iat → 401
  13. Authenticated endpoint rejects plain Bearer token → 401
  14. Authenticated endpoint rejects missing DPoP proof header → 401
  15. Authenticated endpoint rejects proof with wrong ath → 401
  16. Certificate thumbprint pinning: first login pins cert
  17. Certificate thumbprint pinning: same cert login succeeds
  18. Certificate thumbprint pinning: different cert rejected (Rogue CA)
  19. Certificate thumbprint pinning: rotation allows new cert
  20. Certificate thumbprint pinning: old cert rejected after rotation
"""
import base64
import datetime
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient
import jwt as jose_jwt

from tests.cert_factory import (
    make_assertion, get_org_ca_pem,
    make_assertion_alternate,
)
from tests.conftest import ADMIN_HEADERS, seed_court_agent

pytestmark = pytest.mark.asyncio


async def _prime_nonce(client: AsyncClient, dpop) -> None:
    """Make a throw-away request to get the server nonce into the DPoPHelper."""
    resp = await client.get("/health")
    dpop._update_nonce(resp)


async def _register_agent(client: AsyncClient, agent_id: str, org_id: str):
    """Register org + upload CA + agent + approved binding."""
    org_secret = org_id + "-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)

    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=f'Test Agent {agent_id}',
        capabilities=['test.read'],
    )

    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Token issuance
# ─────────────────────────────────────────────────────────────────────────────

async def test_token_issued_for_valid_agent(client: AsyncClient, dpop):
    """Registered agent + CA uploaded + binding approved + DPoP → 200 with DPoP token."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-a::agent-1", "auth-org-a")

    assertion = make_assertion("auth-org-a::agent-1", "auth-org-a")
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "DPoP"
    assert data["expires_in"] > 0


async def test_token_contains_cnf_jkt(client: AsyncClient, dpop):
    """Issued token must include cnf.jkt bound to the DPoP key."""
    await _prime_nonce(client, dpop)
    import app.auth.jwt as jwt_module
    await _register_agent(client, "auth-org-cnf::agent-1", "auth-org-cnf")

    assertion = make_assertion("auth-org-cnf::agent-1", "auth-org-cnf")
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 200

    token = resp.json()["access_token"]
    pub_pem = jwt_module._broker_public_key_pem
    raw = jose_jwt.decode(token, pub_pem, algorithms=["RS256"],
                          options={"verify_aud": False})
    assert "cnf" in raw
    assert "jkt" in raw["cnf"]
    assert len(raw["cnf"]["jkt"]) > 0


async def test_token_denied_wrong_signature(client: AsyncClient, dpop):
    """client_assertion signed with a different key than the cert → 401."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-a::agent-2", "auth-org-a")

    from tests.cert_factory import make_agent_cert
    _, agent_cert = make_agent_cert("auth-org-a::agent-2", "auth-org-a")
    cert_der = agent_cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode()]

    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_key_pem = wrong_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": "auth-org-a::agent-2",
        "iss": "auth-org-a::agent-2",
        "aud": "agent-trust-broker",
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    bad_assertion = jose_jwt.encode(payload, wrong_key_pem, algorithm="RS256",
                                    headers={"x5c": x5c})

    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": bad_assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 401


async def test_token_denied_unknown_agent(client: AsyncClient, dpop):
    """Unregistered agent but with technically valid cert → 401."""
    await _prime_nonce(client, dpop)
    org_id = "auth-org-c"
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    assertion = make_assertion("auth-org-c::ghost-999", org_id)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 401


async def test_token_denied_org_mismatch(client: AsyncClient, dpop):
    """Cert O='org-evil' but agent registered under 'auth-org-b' → 403."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-b::agent-1", "auth-org-b")

    assertion = make_assertion("auth-org-b::agent-1", "org-evil")
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 403


async def test_token_denied_jti_replay(client: AsyncClient, dpop):
    """Same client_assertion JTI sent twice → second is 401."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-d::agent-1", "auth-org-d")

    fixed_jti = str(uuid.uuid4())
    assertion = make_assertion("auth-org-d::agent-1", "auth-org-d", jti=fixed_jti)

    dpop_proof1 = dpop.proof("POST", "/v1/auth/token")
    resp1 = await client.post("/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof1},
    )
    assert resp1.status_code == 200

    dpop_proof2 = dpop.proof("POST", "/v1/auth/token")
    resp2 = await client.post("/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof2},
    )
    assert resp2.status_code == 401
    assert "replay" in resp2.json()["detail"].lower()


async def test_token_denied_missing_jti(client: AsyncClient, dpop):
    """client_assertion without jti field → 401."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-e::agent-1", "auth-org-e")

    assertion = make_assertion("auth-org-e::agent-1", "auth-org-e", jti=None)
    dpop_proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 401
    assert "jti" in resp.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# DPoP proof validation on the token endpoint
# ─────────────────────────────────────────────────────────────────────────────

async def test_token_denied_missing_dpop_header(client: AsyncClient):
    """No DPoP header → 422 (required header missing)."""
    await _register_agent(client, "auth-org-f::agent-1", "auth-org-f")
    assertion = make_assertion("auth-org-f::agent-1", "auth-org-f")
    resp = await client.post("/v1/auth/token", json={"client_assertion": assertion})
    assert resp.status_code == 422


async def test_token_denied_dpop_wrong_htm(client: AsyncClient, dpop):
    """DPoP proof with htm='GET' instead of 'POST' → 401."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-g::agent-1", "auth-org-g")
    assertion = make_assertion("auth-org-g::agent-1", "auth-org-g")
    dpop_proof = dpop.proof("GET", "/v1/auth/token")  # wrong method
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 401
    assert "htm" in resp.json()["detail"].lower()


async def test_token_denied_dpop_wrong_htu(client: AsyncClient, dpop):
    """DPoP proof with wrong URL → 401."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-h::agent-1", "auth-org-h")
    assertion = make_assertion("auth-org-h::agent-1", "auth-org-h")
    dpop_proof = dpop.proof("POST", "/wrong/endpoint")  # wrong path
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 401
    assert "htu" in resp.json()["detail"].lower()


async def test_token_denied_dpop_jti_replay(client: AsyncClient, dpop):
    """Same DPoP proof JTI used twice → second is 401."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-i::agent-1", "auth-org-i")
    assertion1 = make_assertion("auth-org-i::agent-1", "auth-org-i")
    assertion2 = make_assertion("auth-org-i::agent-1", "auth-org-i")

    fixed_dpop_jti = str(uuid.uuid4())
    dpop_proof = dpop.proof("POST", "/v1/auth/token", jti=fixed_dpop_jti)

    resp1 = await client.post("/v1/auth/token",
        json={"client_assertion": assertion1},
        headers={"DPoP": dpop_proof},
    )
    assert resp1.status_code == 200

    resp2 = await client.post("/v1/auth/token",
        json={"client_assertion": assertion2},
        headers={"DPoP": dpop_proof},
    )
    assert resp2.status_code == 401
    assert "replay" in resp2.json()["detail"].lower()


async def test_token_denied_dpop_expired_iat(client: AsyncClient, dpop):
    """DPoP proof with iat more than 60s in the past → 401."""
    await _prime_nonce(client, dpop)
    await _register_agent(client, "auth-org-j::agent-1", "auth-org-j")
    assertion = make_assertion("auth-org-j::agent-1", "auth-org-j")
    dpop_proof = dpop.proof("POST", "/v1/auth/token", iat_offset=-120)  # 2 min ago
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 401
    assert "iat" in resp.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# DPoP proof validation on authenticated endpoints
# ─────────────────────────────────────────────────────────────────────────────

async def test_authenticated_endpoint_rejects_bearer(client: AsyncClient, dpop):
    """Authenticated endpoint rejects Authorization: Bearer → 401."""
    await _register_agent(client, "auth-org-k::agent-1", "auth-org-k")
    token = await dpop.get_token(client, "auth-org-k::agent-1", "auth-org-k")

    # Plain Bearer — no DPoP
    resp = await client.get(
        "/v1/broker/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "DPoP" in resp.json()["detail"]


async def test_authenticated_endpoint_rejects_missing_dpop_proof(client: AsyncClient, dpop):
    """Authorization: DPoP <token> without DPoP proof header → 401."""
    await _register_agent(client, "auth-org-l::agent-1", "auth-org-l")
    token = await dpop.get_token(client, "auth-org-l::agent-1", "auth-org-l")

    resp = await client.get(
        "/v1/broker/sessions",
        headers={"Authorization": f"DPoP {token}"},
        # No DPoP header
    )
    assert resp.status_code == 401
    assert "proof" in resp.json()["detail"].lower()


async def test_authenticated_endpoint_rejects_wrong_ath(client: AsyncClient, dpop):
    """DPoP proof with ath computed on a different token → 401."""
    await _register_agent(client, "auth-org-m::agent-1", "auth-org-m")
    token = await dpop.get_token(client, "auth-org-m::agent-1", "auth-org-m")

    # Proof signed over a fake token value — ath mismatch
    wrong_proof = dpop.proof("GET", "/v1/broker/sessions", access_token="fake-token-value")
    resp = await client.get(
        "/v1/broker/sessions",
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": wrong_proof,
        },
    )
    assert resp.status_code == 401
    assert "ath" in resp.json()["detail"].lower()


async def test_authenticated_endpoint_accepts_valid_dpop(client: AsyncClient, dpop):
    """Valid DPoP token + correct proof → authenticated endpoint responds 200."""
    await _register_agent(client, "auth-org-n::agent-1", "auth-org-n")
    token = await dpop.get_token(client, "auth-org-n::agent-1", "auth-org-n")

    resp = await client.get(
        "/v1/broker/sessions",
        headers=dpop.headers("GET", "/v1/broker/sessions", token),
    )
    assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# Certificate Thumbprint Pinning (anti Rogue CA)
# ─────────────────────────────────────────────────────────────────────────────

async def test_first_login_pins_thumbprint(client: AsyncClient, dpop):
    """First login should pin the certificate thumbprint in the agent record."""
    agent_id = "pin-org-a::agent-pin1"
    org_id = "pin-org-a"
    await _register_agent(client, agent_id, org_id)

    token = await dpop.get_token(client, agent_id, org_id)
    assert token  # login succeeded

    # Verify thumbprint is stored
    from app.db.database import AsyncSessionLocal
    from app.registry.store import get_agent_by_id
    async with AsyncSessionLocal() as db:
        agent = await get_agent_by_id(db, agent_id)
        assert agent is not None
        assert agent.cert_thumbprint is not None
        assert len(agent.cert_thumbprint) == 64  # SHA-256 hex


async def test_same_cert_login_succeeds(client: AsyncClient, dpop):
    """Re-login with the same certificate should succeed (idempotent)."""
    agent_id = "pin-org-b::agent-pin2"
    org_id = "pin-org-b"
    await _register_agent(client, agent_id, org_id)

    # First login — pins cert
    token1 = await dpop.get_token(client, agent_id, org_id)
    assert token1

    # Second login — same cert (from cache), should succeed
    from tests.cert_factory import DPoPHelper
    dpop2 = DPoPHelper()
    token2 = await dpop2.get_token(client, agent_id, org_id)
    assert token2


async def test_different_cert_rejected(client: AsyncClient, dpop):
    """A different certificate for the same agent should be rejected (Rogue CA attack)."""
    agent_id = "pin-org-c::agent-pin3"
    org_id = "pin-org-c"
    await _register_agent(client, agent_id, org_id)

    # First login — pins cert
    token = await dpop.get_token(client, agent_id, org_id)
    assert token

    # Build assertion with a DIFFERENT cert (same identity, different key)
    alt_assertion, _ = make_assertion_alternate(agent_id, org_id)
    from tests.cert_factory import DPoPHelper
    dpop2 = DPoPHelper()
    dpop_proof = dpop2.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": alt_assertion},
        headers={"DPoP": dpop_proof},
    )
    # May get 401 for nonce first — retry
    if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
        dpop2._update_nonce(resp)
        alt_assertion, _ = make_assertion_alternate(agent_id, org_id)
        dpop_proof = dpop2.proof("POST", "/v1/auth/token")
        resp = await client.post(
            "/v1/auth/token",
            json={"client_assertion": alt_assertion},
            headers={"DPoP": dpop_proof},
        )
    assert resp.status_code == 401
    assert "thumbprint mismatch" in resp.json()["detail"].lower()


async def test_rotate_then_new_cert_accepted(client: AsyncClient, dpop):
    """After rotation, the new certificate should be accepted.

    ADR-010 Phase 6a-4 removed the ``POST /v1/registry/agents/{id}/rotate-cert``
    HTTP endpoint — cert rotation is now an internal operation invoked by
    Mastio publish/re-publish flows, not an org_secret-auth HTTP hop. The
    behavioural assertion stays: ``rotate_agent_cert()`` in the store flips
    the thumbprint and subsequent logins with the new cert succeed.
    """
    from app.registry.store import rotate_agent_cert
    from tests.conftest import TestSessionLocal

    agent_id = "pin-org-d::agent-pin4"
    org_id = "pin-org-d"
    await _register_agent(client, agent_id, org_id)

    # First login — pins cert
    token = await dpop.get_token(client, agent_id, org_id)
    assert token

    # Generate alternate cert
    _, alt_cert_pem = make_assertion_alternate(agent_id, org_id)

    # Rotate via the store layer directly.
    async with TestSessionLocal() as session:
        new_thumbprint = await rotate_agent_cert(session, agent_id, alt_cert_pem)
    assert len(new_thumbprint) == 64

    # Login with the alternate cert should now succeed
    alt_assertion, _ = make_assertion_alternate(agent_id, org_id)
    from tests.cert_factory import DPoPHelper
    dpop3 = DPoPHelper()
    dpop_proof = dpop3.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": alt_assertion},
        headers={"DPoP": dpop_proof},
    )
    if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
        dpop3._update_nonce(resp)
        alt_assertion, _ = make_assertion_alternate(agent_id, org_id)
        dpop_proof = dpop3.proof("POST", "/v1/auth/token")
        resp = await client.post(
            "/v1/auth/token",
            json={"client_assertion": alt_assertion},
            headers={"DPoP": dpop_proof},
        )
    assert resp.status_code == 200


async def test_old_cert_rejected_after_rotation(client: AsyncClient, dpop):
    """After rotation, the original certificate should be rejected.

    ADR-010 Phase 6a-4 — see ``test_rotate_then_new_cert_accepted`` for
    the endpoint-deletion rationale. This test invokes the store helper
    directly; the broker-side thumbprint pin behaviour is unchanged.
    """
    from app.registry.store import rotate_agent_cert
    from tests.conftest import TestSessionLocal

    agent_id = "pin-org-e::agent-pin5"
    org_id = "pin-org-e"
    await _register_agent(client, agent_id, org_id)

    # First login — pins original cert
    token = await dpop.get_token(client, agent_id, org_id)
    assert token

    # Rotate to alternate cert via store layer.
    _, alt_cert_pem = make_assertion_alternate(agent_id, org_id)
    async with TestSessionLocal() as session:
        await rotate_agent_cert(session, agent_id, alt_cert_pem)

    # Try to login with the ORIGINAL cert — should fail
    from tests.cert_factory import DPoPHelper
    dpop4 = DPoPHelper()
    assertion = make_assertion(agent_id, org_id)
    dpop_proof = dpop4.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
        dpop4._update_nonce(resp)
        assertion = make_assertion(agent_id, org_id)
        dpop_proof = dpop4.proof("POST", "/v1/auth/token")
        resp = await client.post(
            "/v1/auth/token",
            json={"client_assertion": assertion},
            headers={"DPoP": dpop_proof},
        )
    assert resp.status_code == 401
    assert "thumbprint mismatch" in resp.json()["detail"].lower()
