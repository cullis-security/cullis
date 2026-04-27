"""ADR-001 Phase 3c — local message queue + ack + push-vs-queue.

Covers:
  - message_queue.enqueue / fetch_pending / mark_delivered / sweep_expired
  - idempotency key dedupe
  - /send intra path enqueues + pushes when WS connected
  - /messages/{id} intra returns pending rows
  - /sessions/{id}/messages/{msg_id}/ack flips status
  - /send intra path with no WS connection stays queued
  - drain on /v1/local/ws reconnect replays pending
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from mcp_proxy.local import message_queue as local_queue

from tests._mtls_helpers import provision_internal_agent


# ── Unit — message_queue ────────────────────────────────────────────

@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    from mcp_proxy.db import dispose_db, init_db
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    await init_db(url)
    yield url
    await dispose_db()


@pytest.mark.asyncio
async def test_enqueue_and_fetch(proxy_db):
    msg_id, inserted = await local_queue.enqueue(
        session_id="s1",
        sender_agent_id="alice",
        recipient_agent_id="bob",
        payload_ciphertext="hello",
    )
    assert inserted is True
    pending = await local_queue.fetch_pending_for_recipient("bob")
    assert len(pending) == 1
    assert pending[0].msg_id == msg_id
    assert pending[0].sender_agent_id == "alice"


@pytest.mark.asyncio
async def test_idempotency_key_dedupes(proxy_db):
    msg_id_1, inserted_1 = await local_queue.enqueue(
        session_id="s1", sender_agent_id="alice",
        recipient_agent_id="bob", payload_ciphertext="x",
        idempotency_key="k-1",
    )
    msg_id_2, inserted_2 = await local_queue.enqueue(
        session_id="s1", sender_agent_id="alice",
        recipient_agent_id="bob", payload_ciphertext="x",
        idempotency_key="k-1",
    )
    assert inserted_1 is True
    assert inserted_2 is False
    assert msg_id_1 == msg_id_2
    pending = await local_queue.fetch_pending_for_recipient("bob")
    assert len(pending) == 1


@pytest.mark.asyncio
async def test_mark_delivered_flips_status(proxy_db):
    msg_id, _ = await local_queue.enqueue(
        session_id="s1", sender_agent_id="alice",
        recipient_agent_id="bob", payload_ciphertext="x",
    )
    ok = await local_queue.mark_delivered(msg_id, "bob")
    assert ok is True
    pending = await local_queue.fetch_pending_for_recipient("bob")
    assert pending == []


@pytest.mark.asyncio
async def test_mark_delivered_rejects_other_recipient(proxy_db):
    msg_id, _ = await local_queue.enqueue(
        session_id="s1", sender_agent_id="alice",
        recipient_agent_id="bob", payload_ciphertext="x",
    )
    ok = await local_queue.mark_delivered(msg_id, "carol")
    assert ok is False


@pytest.mark.asyncio
async def test_mark_delivered_idempotent(proxy_db):
    msg_id, _ = await local_queue.enqueue(
        session_id="s1", sender_agent_id="alice",
        recipient_agent_id="bob", payload_ciphertext="x",
    )
    assert await local_queue.mark_delivered(msg_id, "bob") is True
    assert await local_queue.mark_delivered(msg_id, "bob") is False


@pytest.mark.asyncio
async def test_sweep_expired_flips_rows(proxy_db):
    msg_id, _ = await local_queue.enqueue(
        session_id="s1", sender_agent_id="alice",
        recipient_agent_id="bob", payload_ciphertext="x",
        ttl_seconds=10,
    )
    # Force expiry via direct UPDATE — avoids sleeping in unit test.
    from mcp_proxy.db import get_db
    from sqlalchemy import text
    past = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    async with get_db() as conn:
        await conn.execute(
            text("UPDATE local_messages SET expires_at=:p WHERE msg_id=:m"),
            {"p": past, "m": msg_id},
        )
    notices = await local_queue.sweep_expired()
    assert len(notices) == 1
    assert notices[0].msg_id == msg_id
    assert await local_queue.fetch_pending_for_recipient("bob") == []


# ── Integration — router /send + /messages + /ack + WS drain ────────

@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _provision(agent_id: str) -> dict[str, str]:
    """Provision a Mastio-internal agent via the mTLS helper.

    Returns the nginx-shaped headers nginx forwards on the mTLS-required
    ``/v1/egress/*`` locations.
    """
    return await provision_internal_agent(agent_id, capabilities=[])


async def _provision_with_api_key(agent_id: str) -> tuple[dict[str, str], str]:
    """Provision via mTLS helper *and* overwrite ``api_key_hash`` with a
    real bcrypt hash of a freshly minted key.

    The legacy ``/v1/local/ws?api_key=...`` upgrade still authenticates by
    api-key (PR-B did not migrate the WebSocket path), so tests that
    exercise the WS drain need the same agent to authenticate both via
    the cert (for /v1/egress/*) and via an api-key (for the WS upgrade).
    Returns ``(headers, raw_api_key)``.
    """
    from sqlalchemy import text
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import get_db

    headers = await _provision(agent_id)
    raw = generate_api_key(agent_id)
    canonical = f"acme::{agent_id}"
    async with get_db() as conn:
        await conn.execute(
            text("UPDATE internal_agents SET api_key_hash = :h WHERE agent_id = :aid"),
            {"h": hash_api_key(raw), "aid": canonical},
        )
    return headers, raw


async def _open_local_session(client: AsyncClient, initiator_headers: dict[str, str], responder: str) -> str:
    resp = await client.post(
        "/v1/egress/sessions",
        headers=initiator_headers,
        json={
            "target_agent_id": responder,
            "target_org_id": "acme",
            "capabilities": [],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["session_id"]


@pytest.mark.asyncio
async def test_send_intra_enqueues_and_polls(proxy_app):
    _, client = proxy_app
    initiator_headers = await _provision("alice")
    responder_headers = await _provision("bob")
    session_id = await _open_local_session(client, initiator_headers, "acme::bob")

    send = await client.post(
        "/v1/egress/send",
        headers=initiator_headers,
        json={
            "session_id": session_id,
            "payload": {"greet": "hi"},
            "recipient_agent_id": "acme::bob",
        },
    )
    assert send.status_code == 200, send.text
    body = send.json()
    assert body["status"] == "sent"
    assert body["delivered_via"] == "queue"
    assert body["duplicate"] is False
    msg_id = body["msg_id"]

    poll = await client.get(
        f"/v1/egress/messages/{session_id}",
        headers=responder_headers,
    )
    assert poll.status_code == 200
    data = poll.json()
    assert data["count"] == 1
    assert data["scope"] == "local"
    assert data["messages"][0]["msg_id"] == msg_id


@pytest.mark.asyncio
async def test_ack_removes_message_from_pending(proxy_app):
    _, client = proxy_app
    initiator_headers = await _provision("alice")
    responder_headers = await _provision("bob")
    session_id = await _open_local_session(client, initiator_headers, "acme::bob")

    send = await client.post(
        "/v1/egress/send",
        headers=initiator_headers,
        json={"session_id": session_id, "payload": {"x": 1}, "recipient_agent_id": "acme::bob"},
    )
    msg_id = send.json()["msg_id"]

    ack = await client.post(
        f"/v1/egress/sessions/{session_id}/messages/{msg_id}/ack",
        headers=responder_headers,
    )
    assert ack.status_code == 200

    poll = await client.get(
        f"/v1/egress/messages/{session_id}",
        headers=responder_headers,
    )
    assert poll.json()["count"] == 0


@pytest.mark.asyncio
async def test_ack_rejects_stranger(proxy_app):
    _, client = proxy_app
    initiator_headers = await _provision("alice")
    await _provision("bob")
    stranger_headers = await _provision("eve")
    session_id = await _open_local_session(client, initiator_headers, "acme::bob")

    send = await client.post(
        "/v1/egress/send",
        headers=initiator_headers,
        json={"session_id": session_id, "payload": {}, "recipient_agent_id": "acme::bob"},
    )
    msg_id = send.json()["msg_id"]

    resp = await client.post(
        f"/v1/egress/sessions/{session_id}/messages/{msg_id}/ack",
        headers=stranger_headers,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_send_idempotency_key_marks_duplicate(proxy_app):
    _, client = proxy_app
    initiator_headers = await _provision("alice")
    await _provision("bob")
    session_id = await _open_local_session(client, initiator_headers, "acme::bob")

    body = {
        "session_id": session_id,
        "payload": {"x": 1},
        "recipient_agent_id": "acme::bob",
        "idempotency_key": "order-42",
    }
    first = await client.post("/v1/egress/send", headers=initiator_headers, json=body)
    second = await client.post("/v1/egress/send", headers=initiator_headers, json=body)
    assert first.json()["duplicate"] is False
    assert second.json()["duplicate"] is True
    assert first.json()["msg_id"] == second.json()["msg_id"]


@pytest.mark.asyncio
async def test_ws_drain_delivers_pending(proxy_app):
    app, client = proxy_app
    initiator_headers = await _provision("alice")
    responder_headers, responder_key = await _provision_with_api_key("bob")
    session_id = await _open_local_session(client, initiator_headers, "acme::bob")

    await client.post(
        "/v1/egress/send",
        headers=initiator_headers,
        json={"session_id": session_id, "payload": {"n": 1}, "recipient_agent_id": "acme::bob"},
    )
    await client.post(
        "/v1/egress/send",
        headers=initiator_headers,
        json={"session_id": session_id, "payload": {"n": 2}, "recipient_agent_id": "acme::bob"},
    )

    tc = TestClient(app, raise_server_exceptions=True)
    with tc.websocket_connect(f"/v1/local/ws?api_key={responder_key}") as ws:
        welcome = ws.receive_json()
        assert welcome["type"] == "connected"
        first = ws.receive_json()
        second = ws.receive_json()
        assert first["queued"] is True
        assert second["queued"] is True
        payloads = sorted([first["payload"]["n"], second["payload"]["n"]])
        assert payloads == [1, 2]
