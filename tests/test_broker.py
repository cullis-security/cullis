import uuid
import pytest
from httpx import AsyncClient

from tests.cert_factory import make_assertion, get_org_ca_pem, sign_message, make_encrypted_envelope
from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio


async def _register_and_login(client: AsyncClient, dpop, agent_id: str, org_id: str) -> str:
    """Register org (idempotent) + CA + agent + approved binding, then obtain a DPoP-bound token."""
    org_secret = org_id + "-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["kyc.read", "kyc.write"],
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["kyc.read", "kyc.write"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/policy/rules",
        json={
            "policy_id": f"{org_id}::session-allow-all",
            "org_id": org_id,
            "policy_type": "session",
            "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
        },
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


async def test_session_full_flow(client: AsyncClient, dpop):
    token_a = await _register_and_login(client, dpop, "broker-org-a::agent-1", "broker-org-a")
    token_b = await _register_and_login(client, dpop, "broker-org-b::agent-1", "broker-org-b")

    # A requests a session with B
    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "broker-org-b::agent-1",
        "target_org_id": "broker-org-b",
        "requested_capabilities": ["kyc.read"],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]
    assert resp.json()["status"] == "pending"

    # B accepts
    resp = await client.post(f"/v1/broker/sessions/{session_id}/accept",
                             headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b))
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"

    # A sends a message
    nonce = str(uuid.uuid4())
    _payload = {"type": "kyc_request", "customer_id": "CUST-001"}
    envelope = make_encrypted_envelope(
        "broker-org-a::agent-1", "broker-org-a",
        "broker-org-b::agent-1", "broker-org-b",
        session_id, nonce, _payload,
    )
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages",
                             json=envelope,
                             headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 202


async def test_replay_attack_blocked(client: AsyncClient, dpop):
    token_a = await _register_and_login(client, dpop, "replay-org-a::agent", "replay-org-a")
    token_b = await _register_and_login(client, dpop, "replay-org-b::agent", "replay-org-b")

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "replay-org-b::agent",
        "target_org_id": "replay-org-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    session_id = resp.json()["session_id"]

    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b))

    nonce = str(uuid.uuid4())
    _replay_payload = {"msg": "hello"}
    envelope = make_encrypted_envelope(
        "replay-org-a::agent", "replay-org-a",
        "replay-org-b::agent", "replay-org-b",
        session_id, nonce, _replay_payload,
    )
    msg_path = f"/v1/broker/sessions/{session_id}/messages"

    r1 = await client.post(msg_path, json=envelope,
                           headers=dpop.headers("POST", msg_path, token_a))
    assert r1.status_code == 202

    # Same nonce — must be blocked (fresh DPoP proof to avoid DPoP JTI replay)
    r2 = await client.post(msg_path, json=envelope,
                           headers=dpop.headers("POST", msg_path, token_a))
    assert r2.status_code == 409


async def test_session_close_valid(client: AsyncClient, dpop):
    token_a = await _register_and_login(client, dpop, "close-org-a::agent", "close-org-a")
    token_b = await _register_and_login(client, dpop, "close-org-b::agent", "close-org-b")

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "close-org-b::agent", "target_org_id": "close-org-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b))

    # A closes the session
    resp = await client.post(f"/v1/broker/sessions/{session_id}/close",
                             headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/close", token_a))
    assert resp.status_code == 200
    assert resp.json()["status"] == "closed"


async def test_session_message_after_close(client: AsyncClient, dpop):
    token_a = await _register_and_login(client, dpop, "msgclose-org-a::agent", "msgclose-org-a")
    token_b = await _register_and_login(client, dpop, "msgclose-org-b::agent", "msgclose-org-b")

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "msgclose-org-b::agent", "target_org_id": "msgclose-org-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b))
    await client.post(f"/v1/broker/sessions/{session_id}/close",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/close", token_a))

    # Attempt to send on a closed session — must fail
    _nonce_mc = str(uuid.uuid4())
    _payload_mc = {"text": "ciao"}
    _envelope_mc = make_encrypted_envelope(
        "msgclose-org-a::agent", "msgclose-org-a",
        "msgclose-org-b::agent", "msgclose-org-b",
        session_id, _nonce_mc, _payload_mc,
    )
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages",
                             json=_envelope_mc,
                             headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 409


async def test_non_participant_blocked(client: AsyncClient, dpop):
    token_a = await _register_and_login(client, dpop, "np-org-a::agent", "np-org-a")
    token_b = await _register_and_login(client, dpop, "np-org-b::agent", "np-org-b")
    token_c = await _register_and_login(client, dpop, "np-org-c::agent", "np-org-c")

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "np-org-b::agent", "target_org_id": "np-org-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b))

    # C is not a participant
    _nonce_np = str(uuid.uuid4())
    _payload_np = {"evil": "injection"}
    _envelope_np = make_encrypted_envelope(
        "np-org-c::agent", "np-org-c",
        "np-org-b::agent", "np-org-b",
        session_id, _nonce_np, _payload_np,
    )
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages",
                             json=_envelope_np,
                             headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_c))
    assert resp.status_code == 403
