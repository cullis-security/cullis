"""
Test session persistence — simulates broker restart.

Verifies that after a simulated restart (in-memory flush + restore from DB):
  1. Active sessions survive
  2. Messages are retrievable via polling
  3. Already-used nonces remain blocked (anti-replay)
  4. Closed sessions are NOT restored
  5. Pending sessions survive
"""
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.broker.db_models import SessionRecord
from app.broker.session import session_store
from app.broker.persistence import restore_sessions
from tests.cert_factory import make_assertion, get_org_ca_pem, sign_message

pytestmark = pytest.mark.asyncio


async def _setup_agent_full(client: AsyncClient, dpop, agent_id: str, org_id: str) -> tuple[str, int]:
    """Register org + CA + agent + binding + policy. Returns (token, binding_id)."""
    org_secret = f"{org_id}-secret"

    await client.post("/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    })
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["order.read", "order.write"],
    })
    resp = await client.post("/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read", "order.write"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/policy/rules",
        json={
            "policy_id": f"{org_id}::allow-all",
            "org_id": org_id,
            "policy_type": "session",
            "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
        },
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    token = await dpop.get_token(client, agent_id, org_id)
    return token, binding_id


async def _setup_agent(client: AsyncClient, dpop, agent_id: str, org_id: str) -> str:
    """Register org + CA + agent + binding + policy, return token."""
    org_secret = org_id + "-secret"

    await client.post("/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    })
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["order.read", "order.write"],
    })
    resp = await client.post("/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read", "order.write"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/policy/rules",
        json={
            "policy_id": f"{org_id}::allow-all",
            "org_id": org_id,
            "policy_type": "session",
            "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
        },
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


def _simulate_restart() -> None:
    """Flush the in-memory store — simulates a broker restart process."""
    session_store._sessions.clear()


async def _restore(db: AsyncSession) -> int:
    return await restore_sessions(db, session_store)


async def test_session_survives_restart(client: AsyncClient, db_session: AsyncSession, dpop):
    """Active session + messages must survive a restart."""
    token_a = await _setup_agent(client, dpop, "persist-org-a::agent", "persist-org-a")
    token_b = await _setup_agent(client, dpop, "persist-org-b::agent", "persist-org-b")

    # Create and activate session
    resp = await client.post("/broker/sessions", json={
        "target_agent_id": "persist-org-b::agent",
        "target_org_id": "persist-org-b",
        "requested_capabilities": ["order.read"],
    }, headers=dpop.headers("POST", "/broker/sessions", token_a))
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]

    await client.post(f"/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/broker/sessions/{session_id}/accept", token_b))

    # Send 2 messages
    nonce_1 = str(uuid.uuid4())
    nonce_2 = str(uuid.uuid4())
    _payload_1 = {"type": "order", "item": "bulloni M8", "qty": 1000}
    _payload_2 = {"type": "order", "item": "viti M6", "qty": 500}
    _sig_1, _ts_1 = sign_message("persist-org-a::agent", "persist-org-a", session_id, "persist-org-a::agent", nonce_1, _payload_1)
    await client.post(f"/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "persist-org-a::agent",
        "payload": _payload_1,
        "nonce": nonce_1,
        "timestamp": _ts_1,
        "signature": _sig_1,
    }, headers=dpop.headers("POST", f"/broker/sessions/{session_id}/messages", token_a))
    _sig_2, _ts_2 = sign_message("persist-org-a::agent", "persist-org-a", session_id, "persist-org-a::agent", nonce_2, _payload_2)
    await client.post(f"/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "persist-org-a::agent",
        "payload": _payload_2,
        "nonce": nonce_2,
        "timestamp": _ts_2,
        "signature": _sig_2,
    }, headers=dpop.headers("POST", f"/broker/sessions/{session_id}/messages", token_a))

    # ── SIMULATED RESTART ─────────────────────────────────────────────────────
    _simulate_restart()
    assert session_store._sessions == {}

    restored = await _restore(db_session)
    assert restored >= 1

    # ── POST-RESTART VERIFICATION ─────────────────────────────────────────────

    # Session still present and active
    resp = await client.get("/broker/sessions",
                            headers=dpop.headers("GET", "/broker/sessions", token_a))
    assert resp.status_code == 200
    sessions = resp.json()
    match = next((s for s in sessions if s["session_id"] == session_id), None)
    assert match is not None, "Session not found after restart"
    assert match["status"] == "active"

    # Messages retrievable via polling (B polls)
    resp = await client.get(f"/broker/sessions/{session_id}/messages",
                            params={"after": -1},
                            headers=dpop.headers("GET", f"/broker/sessions/{session_id}/messages", token_b))
    assert resp.status_code == 200
    msgs = resp.json()
    assert len(msgs) == 2


async def test_nonce_replay_blocked_after_restart(client: AsyncClient, db_session: AsyncSession, dpop):
    """Already-used nonces must remain blocked even after a restart."""
    token_a = await _setup_agent(client, dpop, "persist-replay-a::agent", "persist-replay-a")
    token_b = await _setup_agent(client, dpop, "persist-replay-b::agent", "persist-replay-b")

    resp = await client.post("/broker/sessions", json={
        "target_agent_id": "persist-replay-b::agent",
        "target_org_id": "persist-replay-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/broker/sessions", token_a))
    session_id = resp.json()["session_id"]
    await client.post(f"/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/broker/sessions/{session_id}/accept", token_b))

    nonce = str(uuid.uuid4())
    _payload_pr1 = {"msg": "primo invio"}
    _sig_pr1, _ts_pr1 = sign_message("persist-replay-a::agent", "persist-replay-a", session_id, "persist-replay-a::agent", nonce, _payload_pr1)
    await client.post(f"/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "persist-replay-a::agent",
        "payload": _payload_pr1,
        "nonce": nonce,
        "timestamp": _ts_pr1,
        "signature": _sig_pr1,
    }, headers=dpop.headers("POST", f"/broker/sessions/{session_id}/messages", token_a))

    # Restart
    _simulate_restart()
    await _restore(db_session)

    # Same nonce — must still be blocked
    _payload_pr2 = {"msg": "replay dopo restart"}
    _sig_pr2, _ts_pr2 = sign_message("persist-replay-a::agent", "persist-replay-a", session_id, "persist-replay-a::agent", nonce, _payload_pr2)
    resp = await client.post(f"/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "persist-replay-a::agent",
        "payload": _payload_pr2,
        "nonce": nonce,
        "timestamp": _ts_pr2,
        "signature": _sig_pr2,
    }, headers=dpop.headers("POST", f"/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 409


async def test_closed_session_not_restored(client: AsyncClient, db_session: AsyncSession, dpop):
    """Closed sessions must not be reloaded into memory."""
    token_a = await _setup_agent(client, dpop, "persist-closed-a::agent", "persist-closed-a")
    token_b = await _setup_agent(client, dpop, "persist-closed-b::agent", "persist-closed-b")

    resp = await client.post("/broker/sessions", json={
        "target_agent_id": "persist-closed-b::agent",
        "target_org_id": "persist-closed-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/broker/sessions", token_a))
    session_id = resp.json()["session_id"]
    await client.post(f"/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/broker/sessions/{session_id}/accept", token_b))
    await client.post(f"/broker/sessions/{session_id}/close",
                      headers=dpop.headers("POST", f"/broker/sessions/{session_id}/close", token_a))

    # Restart
    _simulate_restart()
    await _restore(db_session)

    assert session_id not in session_store._sessions


async def test_pending_session_survives_restart(client: AsyncClient, db_session: AsyncSession, dpop):
    """Pending session (not yet accepted) must survive a restart."""
    token_a = await _setup_agent(client, dpop, "persist-pend-a::agent", "persist-pend-a")
    await _setup_agent(client, dpop, "persist-pend-b::agent", "persist-pend-b")

    resp = await client.post("/broker/sessions", json={
        "target_agent_id": "persist-pend-b::agent",
        "target_org_id": "persist-pend-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/broker/sessions", token_a))
    session_id = resp.json()["session_id"]
    assert resp.json()["status"] == "pending"

    # Restart without B having accepted
    _simulate_restart()
    await _restore(db_session)

    assert session_id in session_store._sessions
    assert session_store._sessions[session_id].status.value == "pending"


async def test_session_invalidated_on_revoked_binding(client: AsyncClient, db_session: AsyncSession, dpop):
    """Session must not be restored and must be closed in DB if initiator binding is revoked before restart."""
    org_a, org_b = "persist-revoke-a", "persist-revoke-b"
    agent_a, agent_b = f"{org_a}::agent", f"{org_b}::agent"

    token_a, binding_id_a = await _setup_agent_full(client, dpop, agent_a, org_a)
    token_b, _ = await _setup_agent_full(client, dpop, agent_b, org_b)

    resp = await client.post("/broker/sessions", json={
        "target_agent_id": agent_b,
        "target_org_id": org_b,
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/broker/sessions", token_a))
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]
    await client.post(f"/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/broker/sessions/{session_id}/accept", token_b))

    # Revoke initiator binding while the session is active
    resp = await client.post(f"/registry/bindings/{binding_id_a}/revoke",
        headers={"x-org-id": org_a, "x-org-secret": f"{org_a}-secret"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"

    # Simulate broker restart
    _simulate_restart()
    await _restore(db_session)

    # Session must not be reloaded into memory
    assert session_id not in session_store._sessions

    # Session record must be closed in DB so it won't be retried on future restarts
    result = await db_session.execute(
        select(SessionRecord).where(SessionRecord.session_id == session_id)
    )
    rec = result.scalar_one()
    assert rec.status == "closed"


async def test_session_invalidated_on_deactivated_policy(client: AsyncClient, db_session: AsyncSession, dpop):
    """Session must not be restored and must be closed in DB if the authorizing policy is deactivated before restart."""
    org_a, org_b = "persist-nopol-a", "persist-nopol-b"
    agent_a, agent_b = f"{org_a}::agent", f"{org_b}::agent"
    policy_id = f"{org_a}::allow-all"

    token_a, _ = await _setup_agent_full(client, dpop, agent_a, org_a)
    token_b, _ = await _setup_agent_full(client, dpop, agent_b, org_b)

    resp = await client.post("/broker/sessions", json={
        "target_agent_id": agent_b,
        "target_org_id": org_b,
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/broker/sessions", token_a))
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]
    await client.post(f"/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/broker/sessions/{session_id}/accept", token_b))

    # Deactivate the policy that authorized the session
    resp = await client.delete(f"/policy/rules/{policy_id}",
        headers={"x-org-id": org_a, "x-org-secret": f"{org_a}-secret"},
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False

    # Simulate broker restart
    _simulate_restart()
    await _restore(db_session)

    # Session must not be reloaded into memory
    assert session_id not in session_store._sessions

    # Session record must be closed in DB so it won't be retried on future restarts
    result = await db_session.execute(
        select(SessionRecord).where(SessionRecord.session_id == session_id)
    )
    rec = result.scalar_one()
    assert rec.status == "closed"
