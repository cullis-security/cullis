"""ADR-008 Phase 1 PR #1 — sessionless one-shot messaging (intra-org).

Covers ``POST /v1/egress/message/send`` + ``GET /v1/egress/message/inbox``
end-to-end: correlation_id lifecycle, reply linking, idempotency,
policy deny, cross-org rejection, audit chain integrity, inbox filter
(session vs one-shot).
"""
from __future__ import annotations

import json
import time
import uuid

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from cullis_sdk.crypto.message_signer import (
    ONESHOT_ENVELOPE_PROTO_VERSION,
    sign_message,
    sign_oneshot_envelope,
)
from tests.cert_factory import make_agent_cert
from tests._mtls_helpers import mtls_headers


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


async def _provision_agent(agent_id: str, org_id: str = "acme") -> tuple[str, dict[str, str], str, str]:
    """Provision an agent with BOTH a real API key and a client cert.

    All ``/v1/egress/*`` routes — sessions, send, and one-shot
    message/{send,inbox} — authenticate via the mTLS client cert under
    ADR-014. The raw api-key is still generated for legacy callers
    (e.g. WS endpoints not yet migrated) but tests on this file no
    longer need it.

    Returns ``(raw_api_key, mtls_headers, cert_pem, priv_pem)`` keyed by
    the canonical ``<org>::<agent_id>``.
    """
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import create_agent

    canonical = f"{org_id}::{agent_id}"
    key, cert = make_agent_cert(canonical, org_id, key_type="ec")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    raw = generate_api_key(agent_id)
    await create_agent(
        agent_id=canonical,
        display_name=agent_id,
        capabilities=["cap.read"],
        api_key_hash=hash_api_key(raw),
        cert_pem=cert_pem,
    )
    return raw, mtls_headers(cert_pem), cert_pem, priv_pem


async def _provision_local_target(agent_id: str, cert_pem: str) -> None:
    """ADR-010 Phase 6b: ensure ``internal_agents`` row carries this cert.

    ``_provision_agent`` already writes the cert via ``create_agent``; the
    UPDATE is idempotent and keeps the old two-step test shape readable.
    """
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        await conn.execute(
            text(
                "UPDATE internal_agents SET cert_pem = :cert_pem "
                "WHERE agent_id = :agent_id"
            ),
            {"agent_id": agent_id, "cert_pem": cert_pem},
        )


def _build_send_body(
    *,
    recipient_id: str,
    payload: dict,
    sender_priv: str,
    sender_agent_id: str,
    correlation_id: str | None = None,
    reply_to: str | None = None,
    ttl_seconds: int = 300,
) -> tuple[dict, str]:
    """Return (body_dict, corr_id) for POST /v1/egress/message/send."""
    corr_id = correlation_id or str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    sig = sign_oneshot_envelope(
        sender_priv,
        correlation_id=corr_id,
        sender_agent_id=sender_agent_id,
        nonce=nonce,
        timestamp=ts,
        mode="mtls-only",
        reply_to=reply_to,
        payload=payload,
    )
    body = {
        "recipient_id": recipient_id,
        "payload": payload,
        "correlation_id": corr_id,
        "reply_to": reply_to,
        "mode": "mtls-only",
        "signature": sig,
        "nonce": nonce,
        "timestamp": ts,
        "ttl_seconds": ttl_seconds,
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
    }
    return body, corr_id


# ── Tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_oneshot_happy_path(proxy_app):
    """alice sends a one-shot → bob's inbox returns it with the correct corr_id."""
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_headers, bob_cert, _ = await _provision_agent("bob")
    await _provision_local_target("acme::bob", bob_cert)
    await _provision_local_target("acme::alice", alice_cert)

    body, corr = _build_send_body(
        recipient_id="acme::bob",
        payload={"text": "hi"},
        sender_priv=alice_priv,
        sender_agent_id="alice",
    )
    r = await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=body,
    )
    assert r.status_code == 200, r.text
    resp = r.json()
    assert resp["correlation_id"] == corr
    assert resp["status"] == "enqueued"
    assert resp["msg_id"]

    inbox = await client.get(
        "/v1/egress/message/inbox",
        headers=bob_headers,
    )
    assert inbox.status_code == 200
    data = inbox.json()
    assert data["count"] == 1
    m = data["messages"][0]
    assert m["correlation_id"] == corr
    assert m["reply_to"] is None
    assert m["sender_agent_id"] == "acme::alice"


@pytest.mark.asyncio
async def test_correlation_id_auto_generated(proxy_app):
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_headers, bob_cert, _ = await _provision_agent("bob")
    await _provision_local_target("acme::bob", bob_cert)
    await _provision_local_target("acme::alice", alice_cert)

    # Build a body without correlation_id; the server generates one and
    # echoes it in the response.
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    # We don't know corr_id upfront, so sign a placeholder and let the
    # server accept a null correlation_id — the verifier is exercised
    # in the happy-path test; here we just assert the metadata flow.
    body = {
        "recipient_id": "acme::bob",
        "payload": {"msg": "auto-corr"},
        "correlation_id": None,
        "reply_to": None,
        "mode": "mtls-only",
        "signature": sign_message(
            alice_priv, "oneshot:auto", "alice", nonce, ts, {"msg": "auto-corr"}, client_seq=0
        ),
        "nonce": nonce,
        "timestamp": ts,
        "ttl_seconds": 300,
    }
    r = await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=body,
    )
    assert r.status_code == 200, r.text
    corr = r.json()["correlation_id"]
    # Must look like a UUID (server generated).
    uuid.UUID(corr)


@pytest.mark.asyncio
async def test_reply_link_persisted(proxy_app):
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_headers, bob_cert, bob_priv = await _provision_agent("bob")
    await _provision_local_target("acme::bob", bob_cert)
    await _provision_local_target("acme::alice", alice_cert)

    # alice → bob
    req_body, req_corr = _build_send_body(
        recipient_id="acme::bob",
        payload={"q": "?"},
        sender_priv=alice_priv,
        sender_agent_id="alice",
    )
    r1 = await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=req_body,
    )
    assert r1.status_code == 200

    # bob replies → alice, reply_to=req_corr
    reply_body, reply_corr = _build_send_body(
        recipient_id="acme::alice",
        payload={"a": "!"},
        sender_priv=bob_priv,
        sender_agent_id="bob",
        reply_to=req_corr,
    )
    r2 = await client.post(
        "/v1/egress/message/send",
        headers=bob_headers,
        json=reply_body,
    )
    assert r2.status_code == 200

    # alice's inbox has the reply with reply_to set.
    inbox = await client.get(
        "/v1/egress/message/inbox",
        headers=alice_headers,
    )
    msgs = inbox.json()["messages"]
    assert len(msgs) == 1
    assert msgs[0]["reply_to"] == req_corr
    assert msgs[0]["correlation_id"] == reply_corr


@pytest.mark.asyncio
async def test_duplicate_correlation_id_idempotent(proxy_app):
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_headers, bob_cert, _ = await _provision_agent("bob")
    await _provision_local_target("acme::bob", bob_cert)
    await _provision_local_target("acme::alice", alice_cert)

    body, corr = _build_send_body(
        recipient_id="acme::bob",
        payload={"n": 1},
        sender_priv=alice_priv,
        sender_agent_id="alice",
        correlation_id="fixed-corr-id",
    )
    r1 = await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=body,
    )
    # Re-sign for a second attempt (new nonce; server dedups on
    # correlation_id via idempotency_key).
    body2, _ = _build_send_body(
        recipient_id="acme::bob",
        payload={"n": 2},  # different payload; duplicate path doesn't care
        sender_priv=alice_priv,
        sender_agent_id="alice",
        correlation_id="fixed-corr-id",
    )
    r2 = await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=body2,
    )
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json()["status"] == "enqueued"
    assert r2.json()["status"] == "duplicate"
    assert r1.json()["msg_id"] == r2.json()["msg_id"]


@pytest.mark.asyncio
async def test_cross_org_without_broker_returns_503(proxy_app):
    """When the proxy has no broker uplink configured (as in this fixture),
    a cross-org send should fail fast with 503.

    ADR-008 Phase 1 PR #2 replaced the hardcoded 501 with a live broker
    forward path; 501 no longer applies. A deployment that never wires
    the bridge surfaces the gap as 503 ("broker uplink not configured").
    Cross-org happy path is covered in tests/test_oneshot_cross.py.
    """
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    await _provision_local_target("acme::alice", alice_cert)

    body, _ = _build_send_body(
        recipient_id="other-org::stranger",
        payload={"n": 1},
        sender_priv=alice_priv,
        sender_agent_id="alice",
    )
    r = await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=body,
    )
    assert r.status_code == 503
    assert "broker" in r.text.lower()


@pytest.mark.asyncio
async def test_unauthorized_sender_is_rejected(proxy_app):
    _, client = proxy_app
    r = await client.post(
        "/v1/egress/message/send",
        json={
            "recipient_id": "acme::bob",
            "payload": {},
            "mode": "mtls-only",
            "signature": "x",
            "nonce": "n",
            "timestamp": int(time.time()),
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_inbox_filters_out_session_rows(proxy_app):
    """Inbox must return ONLY one-shot rows, not session /send rows."""
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_headers, bob_cert, _ = await _provision_agent("bob")
    await _provision_local_target("acme::bob", bob_cert)
    await _provision_local_target("acme::alice", alice_cert)

    # Session-based send first. All /v1/egress/* routes (sessions, send,
    # and the one-shot message endpoints) authenticate via the mTLS
    # client cert under ADR-014.
    open_resp = await client.post(
        "/v1/egress/sessions",
        headers=alice_headers,
        json={
            "target_agent_id": "acme::bob",
            "target_org_id": "acme",
            "capabilities": ["cap.read"],
        },
    )
    session_id = open_resp.json()["session_id"]
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    sig = sign_message(
        alice_priv, session_id, "acme::alice", nonce, ts, {"x": 1}, client_seq=0
    )
    await client.post(
        "/v1/egress/send",
        headers=alice_headers,
        json={
            "session_id": session_id,
            "payload": {"x": 1},
            "recipient_agent_id": "acme::bob",
            "mode": "mtls-only",
            "signature": sig,
            "nonce": nonce,
            "timestamp": ts,
            "sender_seq": 0,
        },
    )

    # Now a one-shot.
    body, corr = _build_send_body(
        recipient_id="acme::bob",
        payload={"only": "oneshot"},
        sender_priv=alice_priv,
        sender_agent_id="alice",
    )
    await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=body,
    )

    inbox = await client.get(
        "/v1/egress/message/inbox",
        headers=bob_headers,
    )
    data = inbox.json()
    assert data["count"] == 1
    assert data["messages"][0]["correlation_id"] == corr


@pytest.mark.asyncio
async def test_audit_chain_integrity_after_3_oneshots(proxy_app):
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_headers, bob_cert, _ = await _provision_agent("bob")
    await _provision_local_target("acme::bob", bob_cert)
    await _provision_local_target("acme::alice", alice_cert)

    for i in range(3):
        body, _ = _build_send_body(
            recipient_id="acme::bob",
            payload={"n": i},
            sender_priv=alice_priv,
            sender_agent_id="alice",
        )
        r = await client.post(
            "/v1/egress/message/send",
            headers=alice_headers,
            json=body,
        )
        assert r.status_code == 200

    from mcp_proxy.local.audit import verify_local_chain
    ok, reason = await verify_local_chain("acme")
    assert ok, f"hash chain broken: {reason}"


@pytest.mark.asyncio
async def test_oneshot_row_is_discriminable_in_db(proxy_app):
    """DB-level invariant: the row flips is_oneshot=1 and session_id=NULL."""
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_headers, bob_cert, _ = await _provision_agent("bob")
    await _provision_local_target("acme::bob", bob_cert)
    await _provision_local_target("acme::alice", alice_cert)

    body, corr = _build_send_body(
        recipient_id="acme::bob",
        payload={"tag": "dbcheck"},
        sender_priv=alice_priv,
        sender_agent_id="alice",
    )
    await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=body,
    )

    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                "SELECT session_id, is_oneshot, correlation_id "
                "FROM local_messages WHERE correlation_id = :c"
            ),
            {"c": corr},
        )).first()
    assert row is not None
    assert row[0] is None      # session_id
    assert row[1] == 1         # is_oneshot
    assert row[2] == corr


@pytest.mark.asyncio
async def test_ttl_boundaries_validated(proxy_app):
    """ttl_seconds < 10 or > 3600 is rejected at pydantic level."""
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, _ = await _provision_agent("alice")
    await _provision_local_target("acme::alice", alice_cert)

    r = await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json={
            "recipient_id": "acme::bob",
            "payload": {"x": 1},
            "mode": "mtls-only",
            "signature": "s",
            "nonce": "n",
            "timestamp": int(time.time()),
            "ttl_seconds": 5,  # below min 10
        },
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_envelope_fields_included_in_stored_blob(proxy_app):
    """The stored envelope carries signature+nonce+timestamp+mode so the
    recipient's verifier can reconstruct the canonical form.
    """
    _, client = proxy_app
    alice_key, alice_headers, alice_cert, alice_priv = await _provision_agent("alice")
    bob_key, bob_headers, bob_cert, _ = await _provision_agent("bob")
    await _provision_local_target("acme::bob", bob_cert)
    await _provision_local_target("acme::alice", alice_cert)

    body, corr = _build_send_body(
        recipient_id="acme::bob",
        payload={"word": "ok"},
        sender_priv=alice_priv,
        sender_agent_id="alice",
    )
    await client.post(
        "/v1/egress/message/send",
        headers=alice_headers,
        json=body,
    )

    inbox = await client.get(
        "/v1/egress/message/inbox",
        headers=bob_headers,
    )
    msg = inbox.json()["messages"][0]
    envelope = json.loads(msg["payload_ciphertext"])
    assert envelope["mode"] == "mtls-only"
    assert envelope["signature"] == body["signature"]
    assert envelope["nonce"] == body["nonce"]
    assert envelope["timestamp"] == body["timestamp"]
    assert envelope["correlation_id"] == corr
    assert envelope["reply_to"] is None
    assert envelope["payload"] == {"word": "ok"}
