"""
Test rate limiting — verifies that limits are enforced.

Tests reset the limiter before each run to avoid interference
with other tests that use the same agents/orgs.
"""
import pytest
from httpx import AsyncClient

from app.rate_limit.limiter import rate_limiter
from tests.cert_factory import make_assertion, get_org_ca_pem, sign_message
from tests.conftest import ADMIN_HEADERS, seed_court_agent

pytestmark = pytest.mark.asyncio

RL_ORG = "rl-org"
RL_AGENT = "rl-org::agent"
RL_SECRET = "rl-org-secret"

RL_ORG_B = "rl-org-b"
RL_AGENT_B = "rl-org-b::agent"
RL_SECRET_B = "rl-org-b-secret"


def _reset_limiter() -> None:
    """Flush all limiter buckets between tests."""
    rate_limiter._windows.clear()


async def _setup_agent(client: AsyncClient, agent_id: str, org_id: str, secret: str, dpop) -> str:
    """Register org + agent + binding + policy; return access token."""
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=agent_id,
        capabilities=['order.read'],
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read"]},
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    await client.post("/v1/policy/rules",
        json={
            "policy_id": f"{org_id}::allow-all",
            "org_id": org_id,
            "policy_type": "session",
            "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
        },
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


async def test_auth_token_rate_limit(client: AsyncClient, dpop):
    """POST /auth/token: 429 after 10 requests from the same IP in the same window."""
    _reset_limiter()

    # Register the org only once
    await client.post("/v1/registry/orgs", json={
        "org_id": "rl-token-org", "display_name": "rl-token-org", "secret": "s",
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem("rl-token-org")
    await client.post("/v1/registry/orgs/rl-token-org/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": "rl-token-org", "x-org-secret": "s"},
    )
    await seed_court_agent(
        agent_id='rl-token-org::agent',
        org_id='rl-token-org',
        display_name='x',
        capabilities=[],
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": "rl-token-org", "agent_id": "rl-token-org::agent", "scope": []},
        headers={"x-org-id": "rl-token-org", "x-org-secret": "s"},
    )
    await client.post(f"/v1/registry/bindings/{resp.json()['id']}/approve",
        headers={"x-org-id": "rl-token-org", "x-org-secret": "s"},
    )

    # 10 valid requests → all 200
    for _ in range(10):
        assertion = make_assertion("rl-token-org::agent", "rl-token-org")
        r = await client.post(
            "/v1/auth/token",
            json={"client_assertion": assertion},
            headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
        )
        assert r.status_code == 200

    # The eleventh must be blocked
    assertion = make_assertion("rl-token-org::agent", "rl-token-org")
    r = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop.proof("POST", "/v1/auth/token")},
    )
    assert r.status_code == 429


async def test_message_rate_limit(client: AsyncClient, dpop):
    """POST /broker/sessions/{id}/messages: 429 after 60 messages/min per agent."""
    _reset_limiter()

    token_a = await _setup_agent(client, RL_AGENT, RL_ORG, RL_SECRET, dpop)
    token_b = await _setup_agent(client, RL_AGENT_B, RL_ORG_B, RL_SECRET_B, dpop)

    # Create and activate session
    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": RL_AGENT_B,
        "target_org_id": RL_ORG_B,
        "requested_capabilities": ["order.read"],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]

    await client.post(
        f"/v1/broker/sessions/{session_id}/accept",
        headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b),
    )

    import uuid

    # 60 messages → accepted
    for _ in range(60):
        nonce = str(uuid.uuid4())
        _sig, _ts = sign_message(RL_AGENT, RL_ORG, session_id, RL_AGENT, nonce, {"x": 1})
        r = await client.post(
            f"/v1/broker/sessions/{session_id}/messages",
            json={
                "session_id": session_id,
                "sender_agent_id": RL_AGENT,
                "payload": {"x": 1},
                "nonce": nonce,
                "timestamp": _ts,
                "signature": _sig,
            },
            headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a),
        )
        assert r.status_code == 202

    # The 61st is blocked
    nonce = str(uuid.uuid4())
    _sig, _ts = sign_message(RL_AGENT, RL_ORG, session_id, RL_AGENT, nonce, {"x": 1})
    r = await client.post(
        f"/v1/broker/sessions/{session_id}/messages",
        json={
            "session_id": session_id,
            "sender_agent_id": RL_AGENT,
            "payload": {"x": 1},
            "nonce": nonce,
            "timestamp": _ts,
            "signature": _sig,
        },
        headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a),
    )
    assert r.status_code == 429


async def test_session_rate_limit(client: AsyncClient, dpop):
    """POST /broker/sessions: 429 after 20 requests/min per agent."""
    _reset_limiter()

    token_a = await _setup_agent(client, "rl-sess-a::agent", "rl-sess-a", "rl-sess-a-secret", dpop)
    await _setup_agent(client, "rl-sess-b::agent", "rl-sess-b", "rl-sess-b-secret", dpop)

    # 20 requests → pass (some may fail for policy/other reasons, but not for rate limit)
    for _ in range(20):
        await client.post("/v1/broker/sessions", json={
            "target_agent_id": "rl-sess-b::agent",
            "target_org_id": "rl-sess-b",
            "requested_capabilities": [],
        }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))

    # The 21st must be blocked by the rate limiter
    r = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "rl-sess-b::agent",
        "target_org_id": "rl-sess-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    assert r.status_code == 429
