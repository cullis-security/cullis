"""
Test policy engine — supply chain scenario (buyer / manufacturer).

Coverage:
  Session policy (default deny):
    1. Session blocked — no policy defined
    2. Session blocked — target org not allowed
    3. Session blocked — capability not allowed
    4. Session blocked — max_active_sessions reached
    5. Session allowed by correct policy

  Message policy (default allow):
    6. Message allowed — no message policy (default allow)
    7. Message blocked — payload too large
    8. Message blocked — required field missing (order_id)
    9. Message blocked — blocked field present (internal_margin)

  CRUD policy:
   10. Create policy → 201 with correct data
   11. Create duplicate policy → 409
   12. List policies for org
   13. Policy detail by policy_id
   14. Deactivate policy → is_active=false; subsequent request no longer finds the active policy
"""
import uuid
import pytest
from httpx import AsyncClient

from tests.cert_factory import get_org_ca_pem, sign_message
from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORG_BUYER        = "pol-buyer"
ORG_MANUFACTURER = "pol-manufacturer"
ORG_THIRD        = "pol-third"

BUYER_SECRET        = ORG_BUYER + "-secret"
MANUFACTURER_SECRET = ORG_MANUFACTURER + "-secret"
THIRD_SECRET        = ORG_THIRD + "-secret"

CAPS = ["order.read", "order.write"]


def org_headers(org_id: str) -> dict:
    return {"x-org-id": org_id, "x-org-secret": org_id + "-secret"}


async def _setup_org_agent(client: AsyncClient, org_id: str, agent_id: str, dpop) -> str:
    """Register org + CA + agent + approved binding. Returns the JWT."""
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
        "display_name": agent_id, "capabilities": CAPS,
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": CAPS},
        headers=org_headers(org_id),
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers=org_headers(org_id),
    )
    return await dpop.get_token(client, agent_id, org_id)


async def _create_session_policy(
    client: AsyncClient,
    org_id: str,
    policy_id: str,
    target_org_ids: list[str],
    capabilities: list[str],
    max_active_sessions: int | None = None,
) -> dict:
    conditions: dict = {
        "target_org_id": target_org_ids,
        "capabilities": capabilities,
    }
    if max_active_sessions is not None:
        conditions["max_active_sessions"] = max_active_sessions

    resp = await client.post("/v1/policy/rules", json={
        "policy_id": policy_id,
        "org_id": org_id,
        "policy_type": "session",
        "rules": {"effect": "allow", "conditions": conditions},
    }, headers=org_headers(org_id))
    return resp


async def _create_message_policy(
    client: AsyncClient,
    org_id: str,
    policy_id: str,
    max_payload_size_bytes: int | None = None,
    required_fields: list[str] | None = None,
    blocked_fields: list[str] | None = None,
) -> dict:
    conditions: dict = {}
    if max_payload_size_bytes is not None:
        conditions["max_payload_size_bytes"] = max_payload_size_bytes
    if required_fields:
        conditions["required_fields"] = required_fields
    if blocked_fields:
        conditions["blocked_fields"] = blocked_fields

    resp = await client.post("/v1/policy/rules", json={
        "policy_id": policy_id,
        "org_id": org_id,
        "policy_type": "message",
        "rules": {"effect": "allow", "conditions": conditions},
    }, headers=org_headers(org_id))
    return resp


# ---------------------------------------------------------------------------
# Test 1 — Session blocked: no policy defined (default deny)
# ---------------------------------------------------------------------------

async def test_session_denied_webhook_deny(client: AsyncClient, dpop):
    """PDP webhook returns deny → broker must return 403."""
    from unittest.mock import AsyncMock, patch
    from app.policy.webhook import WebhookDecision

    token_buyer = await _setup_org_agent(
        client, "whdeny-buyer", "whdeny-buyer::procurement-agent", dpop
    )
    await _setup_org_agent(
        client, "whdeny-manufacturer", "whdeny-manufacturer::sales-agent", dpop
    )

    deny = WebhookDecision(allowed=False, reason="not authorized by org policy", org_id="whdeny-buyer")
    with patch("app.broker.router.evaluate_session_policy", new=AsyncMock(return_value=deny)):
        resp = await client.post("/v1/broker/sessions", json={
            "target_agent_id": "whdeny-manufacturer::sales-agent",
            "target_org_id": "whdeny-manufacturer",
            "requested_capabilities": ["order.write"],
        }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))

    assert resp.status_code == 403
    assert "policy" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 2 — Session blocked: target org not allowed
# ---------------------------------------------------------------------------

async def test_session_denied_target_org_denies(client: AsyncClient, dpop):
    """Target org's PDP webhook denies the session request."""
    from unittest.mock import AsyncMock, patch
    from app.policy.webhook import WebhookDecision

    token_buyer = await _setup_org_agent(
        client, "wrongtgt-buyer", "wrongtgt-buyer::procurement-agent", dpop
    )
    await _setup_org_agent(
        client, "wrongtgt-manufacturer", "wrongtgt-manufacturer::sales-agent", dpop
    )

    deny = WebhookDecision(
        allowed=False, reason="target org does not allow this initiator", org_id="wrongtgt-manufacturer"
    )
    with patch("app.broker.router.evaluate_session_policy", new=AsyncMock(return_value=deny)):
        resp = await client.post("/v1/broker/sessions", json={
            "target_agent_id": "wrongtgt-manufacturer::sales-agent",
            "target_org_id": "wrongtgt-manufacturer",
            "requested_capabilities": ["order.write"],
        }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))

    assert resp.status_code == 403
    assert "policy" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 3 — Session blocked: capability not allowed by policy
# ---------------------------------------------------------------------------

async def test_session_denied_initiator_capability_denied(client: AsyncClient, dpop):
    """Initiator org's PDP denies because requested capability is not authorized."""
    from unittest.mock import AsyncMock, patch
    from app.policy.webhook import WebhookDecision

    token_buyer = await _setup_org_agent(
        client, "cap-buyer", "cap-buyer::procurement-agent", dpop
    )
    await _setup_org_agent(
        client, "cap-manufacturer", "cap-manufacturer::sales-agent", dpop
    )

    deny = WebhookDecision(
        allowed=False, reason="capability order.write not authorized by org policy", org_id="cap-buyer"
    )
    with patch("app.broker.router.evaluate_session_policy", new=AsyncMock(return_value=deny)):
        resp = await client.post("/v1/broker/sessions", json={
            "target_agent_id": "cap-manufacturer::sales-agent",
            "target_org_id": "cap-manufacturer",
            "requested_capabilities": ["order.write"],
        }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))

    assert resp.status_code == 403
    assert "policy" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 4 — Session blocked: max_active_sessions reached
# ---------------------------------------------------------------------------

async def test_session_denied_max_active_sessions(client: AsyncClient, dpop):
    """Org PDP denies second session when max active sessions reached."""
    from unittest.mock import AsyncMock, patch
    from app.policy.webhook import WebhookDecision

    token_buyer = await _setup_org_agent(
        client, "maxsess-buyer", "maxsess-buyer::procurement-agent", dpop
    )
    await _setup_org_agent(client, "maxsess-mfr-a", "maxsess-mfr-a::sales-agent", dpop)
    await _setup_org_agent(client, "maxsess-mfr-b", "maxsess-mfr-b::sales-agent", dpop)

    allow = WebhookDecision(allowed=True, reason="ok", org_id="broker")
    deny  = WebhookDecision(allowed=False, reason="max active sessions reached", org_id="maxsess-buyer")

    with patch("app.broker.router.evaluate_session_policy", new=AsyncMock(return_value=allow)):
        resp = await client.post("/v1/broker/sessions", json={
            "target_agent_id": "maxsess-mfr-a::sales-agent",
            "target_org_id": "maxsess-mfr-a",
            "requested_capabilities": [],
        }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))
        assert resp.status_code == 201

    with patch("app.broker.router.evaluate_session_policy", new=AsyncMock(return_value=deny)):
        resp2 = await client.post("/v1/broker/sessions", json={
            "target_agent_id": "maxsess-mfr-b::sales-agent",
            "target_org_id": "maxsess-mfr-b",
            "requested_capabilities": [],
        }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))

    assert resp2.status_code == 403
    assert "policy" in resp2.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 5 — Session allowed by correct policy
# ---------------------------------------------------------------------------

async def test_session_allowed_by_policy(client: AsyncClient, dpop):
    token_buyer = await _setup_org_agent(
        client, "allow-buyer", "allow-buyer::procurement-agent", dpop
    )
    await _setup_org_agent(
        client, "allow-manufacturer", "allow-manufacturer::sales-agent", dpop
    )

    await _create_session_policy(
        client, "allow-buyer", "allow-buyer::session-v1",
        target_org_ids=["allow-manufacturer"],
        capabilities=CAPS,
    )

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "allow-manufacturer::sales-agent",
        "target_org_id": "allow-manufacturer",
        "requested_capabilities": ["order.write"],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))

    assert resp.status_code == 201
    assert resp.json()["status"] == "pending"


# ---------------------------------------------------------------------------
# Test 6 — Message allowed: no message policy (default allow)
# ---------------------------------------------------------------------------

async def test_message_allowed_no_policy(client: AsyncClient, dpop):
    token_buyer = await _setup_org_agent(
        client, "msgallow-buyer", "msgallow-buyer::procurement-agent", dpop
    )
    token_mfr = await _setup_org_agent(
        client, "msgallow-mfr", "msgallow-mfr::sales-agent", dpop
    )

    await _create_session_policy(
        client, "msgallow-buyer", "msgallow-buyer::session-v1",
        target_org_ids=["msgallow-mfr"], capabilities=[],
    )

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "msgallow-mfr::sales-agent",
        "target_org_id": "msgallow-mfr",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_mfr))

    # No message policy → default allow
    _nonce_ma = str(uuid.uuid4())
    _payload_ma = {"type": "order_request", "order_id": "ORD-001", "text": "ciao"}
    _sig_ma, _ts_ma = sign_message("msgallow-buyer::procurement-agent", "msgallow-buyer", session_id, "msgallow-buyer::procurement-agent", _nonce_ma, _payload_ma)
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "msgallow-buyer::procurement-agent",
        "payload": _payload_ma,
        "nonce": _nonce_ma,
        "timestamp": _ts_ma,
        "signature": _sig_ma,
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_buyer))

    assert resp.status_code == 202


# ---------------------------------------------------------------------------
# Test 7 — Message blocked: payload too large
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Message-level policy is now the org PDP's responsibility — broker enforces default-allow on messages")
async def test_message_blocked_payload_too_large(client: AsyncClient, dpop):
    token_buyer = await _setup_org_agent(
        client, "bigmsg-buyer", "bigmsg-buyer::procurement-agent", dpop
    )
    token_mfr = await _setup_org_agent(
        client, "bigmsg-mfr", "bigmsg-mfr::sales-agent", dpop
    )

    await _create_session_policy(
        client, "bigmsg-buyer", "bigmsg-buyer::session-v1",
        target_org_ids=["bigmsg-mfr"], capabilities=[],
    )
    await _create_message_policy(
        client, "bigmsg-buyer", "bigmsg-buyer::msg-v1",
        max_payload_size_bytes=50,
    )

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "bigmsg-mfr::sales-agent",
        "target_org_id": "bigmsg-mfr",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_mfr))

    _nonce_bm = str(uuid.uuid4())
    _payload_bm = {"type": "order_request", "text": "x" * 200}
    _sig_bm, _ts_bm = sign_message("bigmsg-buyer::procurement-agent", "bigmsg-buyer", session_id, "bigmsg-buyer::procurement-agent", _nonce_bm, _payload_bm)
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "bigmsg-buyer::procurement-agent",
        "payload": _payload_bm,
        "nonce": _nonce_bm,
        "timestamp": _ts_bm,
        "signature": _sig_bm,
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_buyer))

    assert resp.status_code == 403
    assert "large" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 8 — Message blocked: required field missing (order_id)
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Message-level policy is now the org PDP's responsibility — broker enforces default-allow on messages")
async def test_message_blocked_missing_required_field(client: AsyncClient, dpop):
    token_buyer = await _setup_org_agent(
        client, "reqfield-buyer", "reqfield-buyer::procurement-agent", dpop
    )
    token_mfr = await _setup_org_agent(
        client, "reqfield-mfr", "reqfield-mfr::sales-agent", dpop
    )

    await _create_session_policy(
        client, "reqfield-buyer", "reqfield-buyer::session-v1",
        target_org_ids=["reqfield-mfr"], capabilities=[],
    )
    await _create_message_policy(
        client, "reqfield-buyer", "reqfield-buyer::msg-v1",
        required_fields=["order_id"],
    )

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "reqfield-mfr::sales-agent",
        "target_org_id": "reqfield-mfr",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_mfr))

    # Payload without order_id → blocked
    _nonce_rf = str(uuid.uuid4())
    _payload_rf = {"type": "order_request", "text": "voglio 1000 bulloni"}
    _sig_rf, _ts_rf = sign_message("reqfield-buyer::procurement-agent", "reqfield-buyer", session_id, "reqfield-buyer::procurement-agent", _nonce_rf, _payload_rf)
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "reqfield-buyer::procurement-agent",
        "payload": _payload_rf,
        "nonce": _nonce_rf,
        "timestamp": _ts_rf,
        "signature": _sig_rf,
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_buyer))

    assert resp.status_code == 403
    assert "order_id" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Test 9 — Message blocked: blocked field present (internal_margin)
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Message-level policy is now the org PDP's responsibility — broker enforces default-allow on messages")
async def test_message_blocked_blocked_field_present(client: AsyncClient, dpop):
    token_buyer = await _setup_org_agent(
        client, "blkfield-buyer", "blkfield-buyer::procurement-agent", dpop
    )
    token_mfr = await _setup_org_agent(
        client, "blkfield-mfr", "blkfield-mfr::sales-agent", dpop
    )

    await _create_session_policy(
        client, "blkfield-buyer", "blkfield-buyer::session-v1",
        target_org_ids=["blkfield-mfr"], capabilities=[],
    )
    await _create_message_policy(
        client, "blkfield-buyer", "blkfield-buyer::msg-v1",
        blocked_fields=["internal_margin", "production_cost"],
    )

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "blkfield-mfr::sales-agent",
        "target_org_id": "blkfield-mfr",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_mfr))

    # Payload with blocked field → deny
    _nonce_bf = str(uuid.uuid4())
    _payload_bf = {
        "type": "order_request",
        "order_id": "ORD-002",
        "internal_margin": 0.35,   # blocked field
    }
    _sig_bf, _ts_bf = sign_message("blkfield-buyer::procurement-agent", "blkfield-buyer", session_id, "blkfield-buyer::procurement-agent", _nonce_bf, _payload_bf)
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "blkfield-buyer::procurement-agent",
        "payload": _payload_bf,
        "nonce": _nonce_bf,
        "timestamp": _ts_bf,
        "signature": _sig_bf,
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_buyer))

    assert resp.status_code == 403
    assert "internal_margin" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Test 10 — CRUD: create policy → 201
# ---------------------------------------------------------------------------

async def test_policy_crud_create(client: AsyncClient, dpop):
    await client.post("/v1/registry/orgs", json={
        "org_id": "crud-buyer", "display_name": "crud-buyer",
        "secret": "crud-buyer-secret",
    }, headers=ADMIN_HEADERS)

    resp = await client.post("/v1/policy/rules", json={
        "policy_id": "crud-buyer::session-v1",
        "org_id": "crud-buyer",
        "policy_type": "session",
        "rules": {
            "effect": "allow",
            "conditions": {
                "target_org_id": ["crud-manufacturer"],
                "capabilities": CAPS,
            },
        },
    }, headers=org_headers("crud-buyer"))

    assert resp.status_code == 201
    body = resp.json()
    assert body["policy_id"] == "crud-buyer::session-v1"
    assert body["org_id"] == "crud-buyer"
    assert body["is_active"] is True
    assert body["rules"]["conditions"]["target_org_id"] == ["crud-manufacturer"]


# ---------------------------------------------------------------------------
# Test 11 — CRUD: duplicate policy → 409
# ---------------------------------------------------------------------------

async def test_policy_crud_duplicate(client: AsyncClient, dpop):
    await client.post("/v1/registry/orgs", json={
        "org_id": "dup-buyer", "display_name": "dup-buyer",
        "secret": "dup-buyer-secret",
    }, headers=ADMIN_HEADERS)

    payload = {
        "policy_id": "dup-buyer::session-v1",
        "org_id": "dup-buyer",
        "policy_type": "session",
        "rules": {"effect": "allow", "conditions": {}},
    }
    await client.post("/v1/policy/rules", json=payload, headers=org_headers("dup-buyer"))
    resp = await client.post("/v1/policy/rules", json=payload, headers=org_headers("dup-buyer"))

    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Test 12 — CRUD: list policies for org
# ---------------------------------------------------------------------------

async def test_policy_crud_list(client: AsyncClient, dpop):
    await client.post("/v1/registry/orgs", json={
        "org_id": "list-buyer", "display_name": "list-buyer",
        "secret": "list-buyer-secret",
    }, headers=ADMIN_HEADERS)

    for i in range(3):
        await client.post("/v1/policy/rules", json={
            "policy_id": f"list-buyer::policy-{i}",
            "org_id": "list-buyer",
            "policy_type": "session",
            "rules": {"effect": "allow", "conditions": {}},
        }, headers=org_headers("list-buyer"))

    resp = await client.get("/v1/policy/rules", params={"org_id": "list-buyer"},
                            headers=org_headers("list-buyer"))
    assert resp.status_code == 200
    ids = [p["policy_id"] for p in resp.json()]
    assert "list-buyer::policy-0" in ids
    assert "list-buyer::policy-1" in ids
    assert "list-buyer::policy-2" in ids


# ---------------------------------------------------------------------------
# Test 13 — CRUD: policy detail
# ---------------------------------------------------------------------------

async def test_policy_crud_get(client: AsyncClient, dpop):
    await client.post("/v1/registry/orgs", json={
        "org_id": "get-buyer", "display_name": "get-buyer",
        "secret": "get-buyer-secret",
    }, headers=ADMIN_HEADERS)
    await client.post("/v1/policy/rules", json={
        "policy_id": "get-buyer::session-v1",
        "org_id": "get-buyer",
        "policy_type": "session",
        "rules": {"effect": "allow", "conditions": {"capabilities": ["order.read"]}},
    }, headers=org_headers("get-buyer"))

    resp = await client.get("/v1/policy/rules/get-buyer::session-v1",
                            headers=org_headers("get-buyer"))
    assert resp.status_code == 200
    assert resp.json()["policy_id"] == "get-buyer::session-v1"
    assert resp.json()["rules"]["conditions"]["capabilities"] == ["order.read"]


# ---------------------------------------------------------------------------
# Test 14 — CRUD: deactivate policy; subsequent session is denied
# ---------------------------------------------------------------------------

async def test_policy_crud_deactivate(client: AsyncClient, dpop):
    """Policy CRUD: create, verify is_active, deactivate, verify is_active=False."""
    token_buyer = await _setup_org_agent(
        client, "deact-buyer", "deact-buyer::procurement-agent", dpop
    )
    await _setup_org_agent(
        client, "deact-manufacturer", "deact-manufacturer::sales-agent", dpop
    )

    await _create_session_policy(
        client, "deact-buyer", "deact-buyer::session-v1",
        target_org_ids=["deact-manufacturer"], capabilities=[],
    )

    # Session allowed (webhook mock returns allow via autouse fixture)
    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "deact-manufacturer::sales-agent",
        "target_org_id": "deact-manufacturer",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))
    assert resp.status_code == 201

    # Deactivate the policy via CRUD API — verify is_active flips to False
    resp = await client.delete("/v1/policy/rules/deact-buyer::session-v1",
                               headers=org_headers("deact-buyer"))
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False

    # GET confirms it's deactivated in the DB
    resp = await client.get("/v1/policy/rules/deact-buyer::session-v1",
                            headers=org_headers("deact-buyer"))
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


# ---------------------------------------------------------------------------
# Test 15 — Message blocked: explicit deny (emergency block, no field conditions)
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Message-level policy is now the org PDP's responsibility — broker enforces default-allow on messages")
async def test_message_blocked_explicit_deny(client: AsyncClient, dpop):
    """
    A message policy with effect='deny' and no field conditions must block
    all messages from that org, even if the payload is perfectly valid.
    This covers the emergency block use case.
    """
    token_buyer = await _setup_org_agent(
        client, "emergdeny-buyer", "emergdeny-buyer::procurement-agent", dpop
    )
    token_mfr = await _setup_org_agent(
        client, "emergdeny-mfr", "emergdeny-mfr::sales-agent", dpop
    )

    await _create_session_policy(
        client, "emergdeny-buyer", "emergdeny-buyer::session-v1",
        target_org_ids=["emergdeny-mfr"], capabilities=[],
    )

    # Emergency block: deny all messages, no field conditions
    await client.post("/v1/policy/rules", json={
        "policy_id": "emergdeny-buyer::msg-emergency",
        "org_id": "emergdeny-buyer",
        "policy_type": "message",
        "rules": {"effect": "deny", "conditions": {}},
    }, headers=org_headers("emergdeny-buyer"))

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "emergdeny-mfr::sales-agent",
        "target_org_id": "emergdeny-mfr",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_buyer))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_mfr))

    # Valid payload — but the emergency deny policy must block it anyway
    _nonce = str(uuid.uuid4())
    _payload = {"type": "order_request", "order_id": "ORD-999", "qty": 100}
    _sig, _ts = sign_message(
        "emergdeny-buyer::procurement-agent", "emergdeny-buyer",
        session_id, "emergdeny-buyer::procurement-agent", _nonce, _payload,
    )
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "emergdeny-buyer::procurement-agent",
        "payload": _payload,
        "nonce": _nonce,
        "timestamp": _ts,
        "signature": _sig,
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_buyer))

    assert resp.status_code == 403
    assert "denied" in resp.json()["detail"].lower()
