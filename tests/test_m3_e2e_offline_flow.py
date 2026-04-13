"""M3.8 — end-to-end offline delivery flow.

Exercises the full round-trip:

  1. Agent A sends a message while B is NOT WS-connected
     → broker response is ``{status: "queued", msg_id}`` and the row is
     persisted to ``proxy_message_queue``.
  2. Agent B opens the WS → receives ``auth_ok`` → is drained the
     queued message as ``new_message`` with ``queued: true`` + ``msg_id``.
  3. Agent B POSTs the ack → row flips to ``delivered``.
  4. B reconnects → drain is now empty.
  5. Idempotency: A retries the same send with the same
     ``idempotency_key`` → response is ``{deduped: true}`` and the
     queue still has exactly one row.

Uses Starlette's sync ``TestClient`` because it supports WebSocket
round-trips (the async httpx client used elsewhere does not).
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from starlette.testclient import TestClient

from app.broker import message_queue as mq
from app.broker.db_models import ProxyMessageQueueRecord
from app.db.database import AsyncSessionLocal
from app.main import app
from tests.cert_factory import (
    DPoPHelper, get_org_ca_pem, make_assertion, make_encrypted_envelope,
)
from tests.conftest import ADMIN_HEADERS


_TESTSERVER = "http://testserver"


def _register_login(client: TestClient, org_id: str, agent_id: str, dpop: DPoPHelper) -> str:
    org_secret = org_id + "-secret"
    client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": get_org_ca_pem(org_id)},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["kyc.read"],
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    r = client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["kyc.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    bid = r.json()["id"]
    client.post(f"/v1/registry/bindings/{bid}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret})
    client.post("/v1/policy/rules", json={
        "policy_id": f"{org_id}::session-allow-all",
        "org_id": org_id, "policy_type": "session",
        "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    assertion = make_assertion(agent_id, org_id)
    proof = dpop.proof("POST", f"{_TESTSERVER}/v1/auth/token")
    r = client.post("/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _open_active_session(client: TestClient, dpop_a, dpop_b, token_a, token_b,
                         agent_b: str, org_b: str) -> str:
    url = f"{_TESTSERVER}/v1/broker/sessions"
    hdr_a = dpop_a.headers("POST", url, token_a)
    r = client.post("/v1/broker/sessions", json={
        "target_agent_id": agent_b, "target_org_id": org_b,
        "requested_capabilities": ["kyc.read"],
    }, headers=hdr_a)
    assert r.status_code == 201, r.text
    sid = r.json()["session_id"]

    accept_url = f"{_TESTSERVER}/v1/broker/sessions/{sid}/accept"
    hdr_b = dpop_b.headers("POST", accept_url, token_b)
    r = client.post(f"/v1/broker/sessions/{sid}/accept", headers=hdr_b)
    assert r.status_code == 200, r.text
    return sid


async def _count_rows(agent_id: str, status: int | None = None) -> int:
    async with AsyncSessionLocal() as db:
        q = select(ProxyMessageQueueRecord).where(
            ProxyMessageQueueRecord.recipient_agent_id == agent_id,
        )
        if status is not None:
            q = q.where(ProxyMessageQueueRecord.delivery_status == status)
        return len((await db.execute(q)).scalars().all())


def test_m3_offline_enqueue_then_ack_via_rest():
    """End-to-end REST half of M3: enqueue on offline + ack + idempotency.

    The WS drain half is covered by tests/test_m3_ws_drain.py (unit
    with FakeWS) — keeping the server-side queue ops disabled here
    (per conftest) avoids cross-test SQLite state pollution that the
    real WS drain would trigger via lifespan-started sweeper.
    """
    dpop_a = DPoPHelper()
    dpop_b = DPoPHelper()
    org_a, agent_a = "m3e2e-a", "m3e2e-a::sender"
    org_b, agent_b = "m3e2e-b", "m3e2e-b::recv"

    with TestClient(app) as client:
        token_a = _register_login(client, org_a, agent_a, dpop_a)
        token_b = _register_login(client, org_b, agent_b, dpop_b)
        sid = _open_active_session(
            client, dpop_a, dpop_b, token_a, token_b, agent_b, org_b,
        )

        # ── 1. A sends while B is offline ────────────────────────────
        envelope = make_encrypted_envelope(
            agent_a, org_a, agent_b, org_b,
            sid, str(uuid.uuid4()), {"what": "ping"},
        )
        idem = "e2e-idem-001"
        path = f"/v1/broker/sessions/{sid}/messages?idempotency_key={idem}&ttl_seconds=900"
        r = client.post(path, json=envelope,
                        headers=dpop_a.headers("POST", _TESTSERVER + path, token_a))
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["status"] == "queued"
        assert body["deduped"] is False
        queued_msg_id = body["msg_id"]

        # ── 2. Idempotency: retry with same key → deduped, same msg_id ─
        envelope_retry = make_encrypted_envelope(
            agent_a, org_a, agent_b, org_b,
            sid, str(uuid.uuid4()), {"what": "ping-retry"},
        )
        r = client.post(path, json=envelope_retry,
                        headers=dpop_a.headers("POST", _TESTSERVER + path, token_a))
        assert r.status_code == 202
        assert r.json()["deduped"] is True
        assert r.json()["msg_id"] == queued_msg_id

        # ── 3. B acks the message via REST ───────────────────────────
        ack_path = f"/v1/broker/sessions/{sid}/messages/{queued_msg_id}/ack"
        r = client.post(ack_path, headers=dpop_b.headers("POST", _TESTSERVER + ack_path, token_b))
        assert r.status_code == 204, r.text

        # Row must be DELIVERED now.
        import asyncio
        assert asyncio.run(_count_rows(agent_b, status=mq.DELIVERY_DELIVERED)) == 1
        assert asyncio.run(_count_rows(agent_b, status=mq.DELIVERY_PENDING)) == 0

        # ── 4. Second ack returns 409 (terminal) ─────────────────────
        r = client.post(ack_path, headers=dpop_b.headers("POST", _TESTSERVER + ack_path, token_b))
        assert r.status_code == 409
