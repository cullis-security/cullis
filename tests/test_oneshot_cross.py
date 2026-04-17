"""ADR-008 Phase 1 PR #2 — cross-org sessionless one-shot via broker.

Exercises the broker endpoints ``/v1/broker/oneshot/{forward,inbox,<id>/ack}``
end-to-end: forward + inbox + ack + dedup + tampered signature + TTL
sweep + audit dual-write.

The proxy-side ``oneshot.py`` flip (501 → broker.send_oneshot) stays
covered by the live smoke stack — unit-testing it in-process requires
mounting a full fake broker on top of the proxy's ASGI, which the
smoke flow already does.
"""
from __future__ import annotations

import json
import time
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from cullis_sdk.crypto.message_signer import (
    ONESHOT_ENVELOPE_PROTO_VERSION,
    sign_oneshot_envelope,
)
from tests.cert_factory import DPoPHelper, get_agent_key_pem, get_org_ca_pem
from tests.conftest import ADMIN_HEADERS, TestSessionLocal


pytestmark = pytest.mark.asyncio


# ── Helpers ────────────────────────────────────────────────────────────

async def _register_and_login(
    client: AsyncClient, dpop: DPoPHelper, agent_id: str, org_id: str,
) -> str:
    """Register org + CA + agent + approved binding, then obtain a token."""
    org_secret = org_id + "-secret"

    await client.post(
        "/v1/registry/orgs",
        json={
            "org_id": org_id, "display_name": org_id, "secret": org_secret,
        },
        headers=ADMIN_HEADERS,
    )
    ca_pem = get_org_ca_pem(org_id)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    # ADR-010 Phase 6a-4 — direct-DB seed replaces the removed
    # ``POST /v1/registry/agents`` setup hop.
    from tests.conftest import seed_court_agent

    await seed_court_agent(
        agent_id=agent_id, org_id=org_id,
        display_name=agent_id, capabilities=["oneshot.message"],
    )
    resp = await client.post(
        "/v1/registry/bindings",
        json={
            "org_id": org_id, "agent_id": agent_id,
            "scope": ["oneshot.message"],
        },
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(
        f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


def _build_forward_body(
    sender_agent_id: str,
    sender_org_id: str,
    recipient_agent_id: str,
    payload: dict,
    *,
    correlation_id: str | None = None,
    reply_to: str | None = None,
    timestamp: int | None = None,
    tamper_signature: bool = False,
    capabilities: list[str] | None = None,
) -> tuple[dict, str, str]:
    """Return (body, correlation_id, nonce)."""
    corr = correlation_id or str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time()) if timestamp is None else timestamp
    key_pem = get_agent_key_pem(sender_agent_id, sender_org_id)
    sig = sign_oneshot_envelope(
        key_pem,
        correlation_id=corr,
        sender_agent_id=sender_agent_id,
        nonce=nonce,
        timestamp=ts,
        mode="mtls-only",
        reply_to=reply_to,
        payload=payload,
    )
    if tamper_signature:
        sig = sig[:-4] + ("AAAA" if not sig.endswith("AAAA") else "BBBB")
    body = {
        "recipient_agent_id": recipient_agent_id,
        "correlation_id": corr,
        "reply_to_correlation_id": reply_to,
        "payload": payload,
        "signature": sig,
        "nonce": nonce,
        "timestamp": ts,
        "mode": "mtls-only",
        "ttl_seconds": 300,
        "capabilities": capabilities or [],
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
    }
    return body, corr, nonce


@pytest.fixture(autouse=True)
def _mock_oneshot_pdp():
    """Bypass PDP webhook calls in the one-shot router.

    The shared ``mock_pdp_webhook`` autouse fixture patches the symbol
    imported by ``app.broker.router``; the one-shot router imports its
    own reference that we have to patch separately. Individual tests
    override this with a deny mock when they need to exercise policy.
    """
    from app.policy.webhook import WebhookDecision

    allow = WebhookDecision(allowed=True, reason="mocked allow", org_id="broker")
    with patch(
        "app.broker.oneshot_router.evaluate_session_policy",
        new=AsyncMock(return_value=allow),
    ):
        yield


# ── Tests ──────────────────────────────────────────────────────────────

async def test_cross_org_happy_path(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme1::alice", "acme1")
    token_b = await _register_and_login(client, dpop_b, "globex1::bob", "globex1")

    body, corr, _ = _build_forward_body(
        "acme1::alice", "acme1", "globex1::bob", {"msg": "quote?"},
    )
    r = await client.post(
        "/v1/broker/oneshot/forward",
        json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 202, r.text
    data = r.json()
    assert data["duplicate"] is False
    msg_id = data["msg_id"]

    r2 = await client.get(
        "/v1/broker/oneshot/inbox",
        headers=dpop_b.headers("GET", "/v1/broker/oneshot/inbox", token_b),
    )
    assert r2.status_code == 200
    inbox = r2.json()
    assert inbox["count"] == 1
    msg = inbox["messages"][0]
    assert msg["correlation_id"] == corr
    assert msg["sender_agent_id"] == "acme1::alice"
    assert msg["sender_org_id"] == "acme1"
    assert msg["msg_id"] == msg_id
    envelope = json.loads(msg["envelope_json"])
    assert envelope["payload"] == {"msg": "quote?"}
    assert envelope["mode"] == "mtls-only"


async def test_duplicate_correlation_returns_same_msg_id(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme2::alice", "acme2")
    await _register_and_login(client, dpop_b, "globex2::bob", "globex2")

    corr = str(uuid.uuid4())
    body1, _, _ = _build_forward_body(
        "acme2::alice", "acme2", "globex2::bob", {"n": 1},
        correlation_id=corr,
    )
    body2, _, _ = _build_forward_body(
        "acme2::alice", "acme2", "globex2::bob", {"n": 2},
        correlation_id=corr,  # same corr, different payload/nonce
    )

    r1 = await client.post(
        "/v1/broker/oneshot/forward", json=body1,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r1.status_code == 202
    r2 = await client.post(
        "/v1/broker/oneshot/forward", json=body2,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r2.status_code == 202
    assert r2.json()["duplicate"] is True
    assert r1.json()["msg_id"] == r2.json()["msg_id"]


async def test_ack_flips_status_and_inbox_empties(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme3::alice", "acme3")
    token_b = await _register_and_login(client, dpop_b, "globex3::bob", "globex3")

    body, _, _ = _build_forward_body(
        "acme3::alice", "acme3", "globex3::bob", {"msg": "ack me"},
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    msg_id = r.json()["msg_id"]

    r_ack = await client.post(
        f"/v1/broker/oneshot/{msg_id}/ack",
        headers=dpop_b.headers(
            "POST", f"/v1/broker/oneshot/{msg_id}/ack", token_b,
        ),
    )
    assert r_ack.status_code == 204

    r_inbox = await client.get(
        "/v1/broker/oneshot/inbox",
        headers=dpop_b.headers("GET", "/v1/broker/oneshot/inbox", token_b),
    )
    assert r_inbox.json()["count"] == 0


async def test_ack_second_call_returns_409(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme4::alice", "acme4")
    token_b = await _register_and_login(client, dpop_b, "globex4::bob", "globex4")

    body, _, _ = _build_forward_body(
        "acme4::alice", "acme4", "globex4::bob", {"msg": "x"},
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    msg_id = r.json()["msg_id"]
    path = f"/v1/broker/oneshot/{msg_id}/ack"
    first = await client.post(path, headers=dpop_b.headers("POST", path, token_b))
    assert first.status_code == 204
    second = await client.post(path, headers=dpop_b.headers("POST", path, token_b))
    assert second.status_code == 409


async def test_ack_by_wrong_agent_returns_404(client: AsyncClient):
    dpop_a, dpop_b, dpop_c = DPoPHelper(), DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme5::alice", "acme5")
    await _register_and_login(client, dpop_b, "globex5::bob", "globex5")
    token_c = await _register_and_login(client, dpop_c, "globex5::charlie", "globex5")

    body, _, _ = _build_forward_body(
        "acme5::alice", "acme5", "globex5::bob", {"msg": "for-bob"},
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    msg_id = r.json()["msg_id"]
    path = f"/v1/broker/oneshot/{msg_id}/ack"
    r_ack = await client.post(path, headers=dpop_c.headers("POST", path, token_c))
    assert r_ack.status_code == 404


async def test_forward_rejects_tampered_signature(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme6::alice", "acme6")
    await _register_and_login(client, dpop_b, "globex6::bob", "globex6")

    body, _, _ = _build_forward_body(
        "acme6::alice", "acme6", "globex6::bob", {"x": 1},
        tamper_signature=True,
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 401


async def test_forward_rejects_stale_timestamp(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme7::alice", "acme7")
    await _register_and_login(client, dpop_b, "globex7::bob", "globex7")

    body, _, _ = _build_forward_body(
        "acme7::alice", "acme7", "globex7::bob", {"x": 1},
        timestamp=int(time.time()) - 3600,
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 409


async def test_forward_unknown_recipient_returns_404(client: AsyncClient):
    dpop_a = DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme8::alice", "acme8")

    body, _, _ = _build_forward_body(
        "acme8::alice", "acme8", "ghost::agent", {"x": 1},
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 404


async def test_forward_denied_by_policy(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme9::alice", "acme9")
    await _register_and_login(client, dpop_b, "globex9::bob", "globex9")

    from app.policy.webhook import WebhookDecision

    deny = WebhookDecision(allowed=False, reason="test deny", org_id="globex9")
    body, _, _ = _build_forward_body(
        "acme9::alice", "acme9", "globex9::bob", {"x": 1},
    )
    with patch(
        "app.broker.oneshot_router.evaluate_session_policy",
        new=AsyncMock(return_value=deny),
    ):
        r = await client.post(
            "/v1/broker/oneshot/forward", json=body,
            headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
        )
    assert r.status_code == 403
    assert "test deny" in r.text


async def test_audit_dual_write_on_forward(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "acme10::alice", "acme10")
    await _register_and_login(client, dpop_b, "globex10::bob", "globex10")

    body, corr, _ = _build_forward_body(
        "acme10::alice", "acme10", "globex10::bob", {"ping": True},
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 202

    from app.db.audit import AuditLog

    async with TestSessionLocal() as db:
        all_rows = (
            await db.execute(
                select(AuditLog).where(
                    AuditLog.event_type == "broker.oneshot_forwarded"
                )
            )
        ).scalars().all()
    # In-memory StaticPool keeps prior tests' audit rows — filter to our corr.
    rows = [r for r in all_rows if corr in (r.details or "")]
    assert len(rows) == 2
    orgs = sorted(r.org_id for r in rows)
    assert orgs == ["acme10", "globex10"]
    peer_map = {r.org_id: r.peer_org_id for r in rows}
    assert peer_map["acme10"] == "globex10"
    assert peer_map["globex10"] == "acme10"
    for row in rows:
        assert row.peer_row_hash is not None


async def test_sweeper_expires_ttl_rows(client: AsyncClient, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from app.broker.db_models import BrokerOneShotMessageRecord
    from app.broker.session_sweeper import _sweep_oneshot_queue

    # conftest sets CULLIS_DISABLE_QUEUE_OPS=1 for the shared suite; clear
    # it here so the sweep actually runs against the in-memory DB.
    monkeypatch.delenv("CULLIS_DISABLE_QUEUE_OPS", raising=False)

    now_dt = datetime.now(timezone.utc)
    async with TestSessionLocal() as db:
        row = BrokerOneShotMessageRecord(
            msg_id=str(uuid.uuid4()),
            correlation_id=str(uuid.uuid4()),
            reply_to_correlation_id=None,
            sender_agent_id="acme11::alice",
            sender_org_id="acme11",
            recipient_agent_id="globex11::bob",
            recipient_org_id="globex11",
            envelope_json="{}",
            nonce=str(uuid.uuid4()),
            enqueued_at=now_dt - timedelta(seconds=600),
            ttl_expires_at=now_dt - timedelta(seconds=1),
            delivery_status=0,
        )
        db.add(row)
        await db.commit()
        msg_id = row.msg_id

    await _sweep_oneshot_queue()

    async with TestSessionLocal() as db:
        status_after = (
            await db.execute(
                select(BrokerOneShotMessageRecord.delivery_status).where(
                    BrokerOneShotMessageRecord.msg_id == msg_id
                )
            )
        ).scalar_one()
    assert status_after == 2


# ── Capability scope checks ──────────────────────────────────────────


async def _register_and_login_with_caps(
    client: AsyncClient, dpop: DPoPHelper, agent_id: str, org_id: str,
    caps: list[str],
) -> str:
    """Like _register_and_login but lets the caller choose capabilities."""
    org_secret = org_id + "-secret"
    await client.post(
        "/v1/registry/orgs",
        json={"org_id": org_id, "display_name": org_id, "secret": org_secret},
        headers=ADMIN_HEADERS,
    )
    ca_pem = get_org_ca_pem(org_id)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    # ADR-010 Phase 6a-4 — direct-DB seed replaces the legacy
    # ``POST /v1/registry/agents`` setup hop.
    from tests.conftest import seed_court_agent

    await seed_court_agent(
        agent_id=agent_id, org_id=org_id,
        display_name=agent_id, capabilities=caps,
    )
    resp = await client.post(
        "/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": caps},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(
        f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


async def test_capability_in_scope_accepted(client: AsyncClient):
    """Both sender and recipient have 'order.read' in scope → 202."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login_with_caps(
        client, dpop_a, "cap1::alice", "cap1", ["order.read", "oneshot.message"],
    )
    await _register_and_login_with_caps(
        client, dpop_b, "capt1::bob", "capt1", ["order.read", "oneshot.message"],
    )
    body, _, _ = _build_forward_body(
        "cap1::alice", "cap1", "capt1::bob", {"x": 1},
        capabilities=["order.read"],
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 202, r.text


async def test_capability_not_in_sender_scope_rejected(client: AsyncClient):
    """Sender binding lacks 'kyc.write' → 403."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login_with_caps(
        client, dpop_a, "cap2::alice", "cap2", ["order.read"],
    )
    await _register_and_login_with_caps(
        client, dpop_b, "capt2::bob", "capt2", ["order.read", "kyc.write"],
    )
    body, _, _ = _build_forward_body(
        "cap2::alice", "cap2", "capt2::bob", {"x": 1},
        capabilities=["kyc.write"],
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 403
    assert "kyc.write" in r.text
    assert "your scope" in r.text.lower()


async def test_capability_not_in_recipient_scope_rejected(client: AsyncClient):
    """Recipient binding lacks 'kyc.write' → 403."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login_with_caps(
        client, dpop_a, "cap3::alice", "cap3", ["order.read", "kyc.write"],
    )
    await _register_and_login_with_caps(
        client, dpop_b, "capt3::bob", "capt3", ["order.read"],
    )
    body, _, _ = _build_forward_body(
        "cap3::alice", "cap3", "capt3::bob", {"x": 1},
        capabilities=["kyc.write"],
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 403
    assert "kyc.write" in r.text
    assert "recipient" in r.text.lower()


async def test_empty_capabilities_falls_back_to_sentinel(client: AsyncClient):
    """Empty capabilities list uses sentinel 'oneshot.message' → still works
    when both sides have it in their binding scope (or policy enforcement off).
    """
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(
        client, dpop_a, "cap4::alice", "cap4",
    )
    await _register_and_login(client, dpop_b, "capt4::bob", "capt4")

    body, _, _ = _build_forward_body(
        "cap4::alice", "cap4", "capt4::bob", {"x": 1},
        capabilities=[],
    )
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 202
