"""ADR-001 §10 — full intra-org round-trip over mtls-only.

Proves the loop closes: alice sends signed plaintext via the proxy,
bob polls the proxy, the SDK verifies the signature, and bob's
business layer sees the original payload.
"""
from __future__ import annotations

import time
import uuid

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from httpx import ASGITransport, AsyncClient

from cullis_sdk.crypto.message_signer import sign_message, verify_signature
from tests.cert_factory import make_agent_cert


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("PROXY_TRANSPORT_INTRA_ORG", "mtls-only")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _provision_agent(agent_id: str, org_id: str = "acme") -> tuple[str, str, str]:
    """Return (api_key, cert_pem, priv_pem) for a newly provisioned agent."""
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import create_agent

    key, cert = make_agent_cert(f"{org_id}::{agent_id}", org_id, key_type="ec")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    raw = generate_api_key(agent_id)
    await create_agent(
        agent_id=agent_id,
        display_name=agent_id,
        capabilities=["cap.read"],
        api_key_hash=hash_api_key(raw),
        cert_pem=cert_pem,
    )
    return raw, cert_pem, priv_pem


async def _provision_local_target(agent_id: str, cert_pem: str) -> None:
    """Mirror the agent into local_agents so resolve can find its cert."""
    from datetime import datetime, timezone
    from sqlalchemy import text
    from mcp_proxy.db import get_db

    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO local_agents "
                "(agent_id, display_name, capabilities, cert_pem, api_key_hash, "
                " scope, created_at, is_active) "
                "VALUES (:agent_id, :display_name, :capabilities, :cert_pem, "
                " :api_key_hash, :scope, :created_at, :is_active)"
            ),
            {
                "agent_id": agent_id,
                "display_name": agent_id,
                "capabilities": "[]",
                "cert_pem": cert_pem,
                "api_key_hash": None,
                "scope": "local",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": 1,
            },
        )


@pytest.mark.asyncio
async def test_alice_to_bob_intra_org_full_round_trip(proxy_app):
    """Alice signs → proxy verifies + enqueues → bob polls → SDK re-verifies."""
    _, client = proxy_app

    alice_key, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_cert, bob_priv = await _provision_agent("bob")
    await _provision_local_target("bob", bob_cert)
    await _provision_local_target("alice", alice_cert)

    # 1. Alice opens a session targeting bob.
    open_resp = await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": alice_key},
        json={
            "target_agent_id": "bob",
            "target_org_id": "acme",
            "capabilities": ["cap.read"],
        },
    )
    assert open_resp.status_code == 200, open_resp.text
    session_id = open_resp.json()["session_id"]

    # 2. Alice resolves bob and learns the transport.
    resolve = await client.post(
        "/v1/egress/resolve",
        headers={"X-API-Key": alice_key},
        json={"recipient_id": "acme::bob"},
    )
    assert resolve.status_code == 200
    decision = resolve.json()
    assert decision["transport"] == "mtls-only"

    # 3. Alice signs the plaintext and sends via the proxy.
    payload = {"greeting": "hello bob", "n": 42}
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    sig = sign_message(alice_priv, session_id, "alice", nonce, ts, payload, client_seq=0)

    send_resp = await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": alice_key},
        json={
            "session_id": session_id,
            "payload": payload,
            "recipient_agent_id": "acme::bob",
            "mode": "mtls-only",
            "signature": sig,
            "nonce": nonce,
            "timestamp": ts,
            "sender_seq": 0,
        },
    )
    assert send_resp.status_code == 200, send_resp.text

    # 4. Bob polls the proxy.
    poll = await client.get(
        f"/v1/egress/messages/{session_id}",
        headers={"X-API-Key": bob_key},
    )
    assert poll.status_code == 200, poll.text
    body = poll.json()
    assert body["count"] == 1
    frame = body["messages"][0]

    # 5. Proxy returned a parsed mtls-only frame with sender cert bundled.
    assert frame["mode"] == "mtls-only"
    assert frame["sender_agent_id"] == "alice"
    assert frame["sender_cert_pem"] is not None
    assert frame["sender_cert_pem"] == alice_cert
    assert frame["payload"] == payload

    # 6. Bob's SDK would verify the signature using that cert — we inline the
    # helper here to avoid constructing a full CullisClient with ASGI bridging.
    ok = verify_signature(
        frame["sender_cert_pem"],
        frame["signature"],
        frame["session_id"],
        frame["sender_agent_id"],
        frame["nonce"],
        frame["timestamp"],
        frame["payload"],
        client_seq=frame["sender_seq"],
    )
    assert ok is True, "bob must be able to verify alice's signature"


@pytest.mark.asyncio
async def test_receiver_rejects_tampered_frame(proxy_app):
    """If the stored blob gets tampered post-enqueue, SDK verify fails."""
    _, client = proxy_app

    alice_key, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_cert, _ = await _provision_agent("bob")
    await _provision_local_target("bob", bob_cert)

    open_resp = await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": alice_key},
        json={
            "target_agent_id": "bob",
            "target_org_id": "acme",
            "capabilities": [],
        },
    )
    session_id = open_resp.json()["session_id"]

    payload = {"text": "original"}
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    sig = sign_message(alice_priv, session_id, "alice", nonce, ts, payload, client_seq=0)

    await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": alice_key},
        json={
            "session_id": session_id,
            "payload": payload,
            "recipient_agent_id": "acme::bob",
            "mode": "mtls-only",
            "signature": sig,
            "nonce": nonce,
            "timestamp": ts,
            "sender_seq": 0,
        },
    )

    # Tamper the stored blob directly in the DB — simulate proxy compromise.
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    import json as _json
    async with get_db() as conn:
        row = await conn.execute(
            text("SELECT payload_ciphertext FROM local_messages WHERE session_id = :s"),
            {"s": session_id},
        )
        stored = row.scalar_one()
        parsed = _json.loads(stored)
        parsed["payload"] = {"text": "tampered"}
        await conn.execute(
            text("UPDATE local_messages SET payload_ciphertext = :p WHERE session_id = :s"),
            {"p": _json.dumps(parsed), "s": session_id},
        )

    # Bob polls — proxy returns the tampered frame, SDK-side verify must fail.
    poll = await client.get(
        f"/v1/egress/messages/{session_id}",
        headers={"X-API-Key": bob_key},
    )
    frame = poll.json()["messages"][0]
    ok = verify_signature(
        frame["sender_cert_pem"],
        frame["signature"],
        frame["session_id"],
        frame["sender_agent_id"],
        frame["nonce"],
        frame["timestamp"],
        frame["payload"],
        client_seq=frame["sender_seq"],
    )
    assert ok is False, "tampered payload must fail signature verification"
