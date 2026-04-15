"""ADR-001 §10 — /v1/egress/send with mode=mtls-only (intra-org sign-only).

Covers the proxy-side acceptance path:
  - valid signature + local session → 200, plaintext enqueued
  - missing / invalid signature → 400 or 401
  - sender without cert_pem → 400
  - mode=mtls-only on a cross-org route (no local session) → 400
  - legacy mode=envelope path remains unchanged
"""
from __future__ import annotations

import time
import uuid

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from httpx import ASGITransport, AsyncClient

from cullis_sdk.crypto.message_signer import sign_message
from tests.cert_factory import make_agent_cert


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _provision_signing_agent(agent_id: str, org_id: str = "acme") -> tuple[str, str]:
    """Provision an internal agent carrying an EC signing key.

    Returns (api_key, private_key_pem) — caller signs messages with the
    private key, the proxy verifies against the cert_pem stored on the
    internal_agents row.
    """
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
    return raw, priv_pem


async def _open_local_session(client, api_key, target: str = "acme::peer-bot") -> str:
    """Open an intra-org local session via the proxy API."""
    resp = await client.post(
        "/v1/egress/sessions",
        headers={"X-API-Key": api_key},
        json={
            "target_agent_id": target,
            "target_org_id": "acme",
            "capabilities": ["cap.read"],
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["session_id"]


def _sign_body(
    priv_pem: str,
    session_id: str,
    sender: str,
    payload: dict,
    seq: int = 0,
) -> dict:
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    sig = sign_message(priv_pem, session_id, sender, nonce, ts, payload, client_seq=seq)
    return {"signature": sig, "nonce": nonce, "timestamp": ts, "sender_seq": seq}


@pytest.mark.asyncio
async def test_mtls_only_happy_path(proxy_app):
    app, client = proxy_app
    api_key, priv = await _provision_signing_agent("sender-bot")
    session_id = await _open_local_session(client, api_key)

    payload = {"text": "hello intra-org", "n": 1}
    meta = _sign_body(priv, session_id, "sender-bot", payload)

    resp = await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": api_key},
        json={
            "session_id": session_id,
            "payload": payload,
            "recipient_agent_id": "acme::peer-bot",
            "mode": "mtls-only",
            **meta,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "sent"
    assert body["delivered_via"] == "queue"


@pytest.mark.asyncio
async def test_mtls_only_bad_signature_is_rejected(proxy_app):
    _, client = proxy_app
    api_key, priv = await _provision_signing_agent("sender-bot")
    session_id = await _open_local_session(client, api_key)

    payload = {"text": "hello"}
    meta = _sign_body(priv, session_id, "sender-bot", payload)
    meta["signature"] = "AAAA" + meta["signature"][4:]  # tamper

    resp = await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": api_key},
        json={
            "session_id": session_id,
            "payload": payload,
            "recipient_agent_id": "acme::peer-bot",
            "mode": "mtls-only",
            **meta,
        },
    )
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_mtls_only_missing_nonce_is_rejected(proxy_app):
    _, client = proxy_app
    api_key, priv = await _provision_signing_agent("sender-bot")
    session_id = await _open_local_session(client, api_key)

    payload = {"text": "hello"}
    meta = _sign_body(priv, session_id, "sender-bot", payload)
    meta.pop("nonce")

    resp = await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": api_key},
        json={
            "session_id": session_id,
            "payload": payload,
            "recipient_agent_id": "acme::peer-bot",
            "mode": "mtls-only",
            **meta,
        },
    )
    assert resp.status_code == 400, resp.text
    assert "nonce" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_mtls_only_sender_without_cert_is_rejected(proxy_app):
    _, client = proxy_app
    # Provision an agent via create_agent without cert_pem — api key only.
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import create_agent

    raw = generate_api_key("sender-bot")
    await create_agent(
        agent_id="sender-bot",
        display_name="sender-bot",
        capabilities=["cap.read"],
        api_key_hash=hash_api_key(raw),
        cert_pem=None,
    )
    session_id = await _open_local_session(client, raw)

    # Signature payload doesn't matter — proxy rejects before verifying.
    resp = await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": raw},
        json={
            "session_id": session_id,
            "payload": {"text": "hi"},
            "recipient_agent_id": "acme::peer-bot",
            "mode": "mtls-only",
            "signature": "AAAA",
            "nonce": "n",
            "timestamp": int(time.time()),
        },
    )
    assert resp.status_code == 400, resp.text
    assert "cert" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_mtls_only_rejected_on_cross_org(proxy_app):
    """When the session_id is not in the local store (cross-org),
    mtls-only must be rejected with 400 — broker must never see plaintext."""
    _, client = proxy_app
    api_key, priv = await _provision_signing_agent("sender-bot")

    # Fabricate a valid-looking session_id that is NOT in the local store.
    fake_session = str(uuid.uuid4())
    payload = {"text": "hi"}
    meta = _sign_body(priv, fake_session, "sender-bot", payload)

    resp = await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": api_key},
        json={
            "session_id": fake_session,
            "payload": payload,
            "recipient_agent_id": "other-org::bob",
            "mode": "mtls-only",
            **meta,
        },
    )
    assert resp.status_code == 400, resp.text
    assert "intra-org only" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_legacy_envelope_mode_unchanged(proxy_app):
    """Omitting mode keeps the legacy opaque-ciphertext path working."""
    _, client = proxy_app
    api_key, _ = await _provision_signing_agent("sender-bot")
    session_id = await _open_local_session(client, api_key)

    resp = await client.post(
        "/v1/egress/send",
        headers={"X-API-Key": api_key},
        json={
            "session_id": session_id,
            "payload": {"ciphertext": "opaque-blob-base64=="},
            "recipient_agent_id": "acme::peer-bot",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "sent"
