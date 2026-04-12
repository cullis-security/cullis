"""
Tests for security vulnerability fixes.

Covers:
  - Session nonce capacity limit (DoS protection)
  - Session expiry enforcement on message send
  - Envelope session_id mismatch detection
  - CA certificate validation on upload
  - Cache-Control header presence
  - Revocation race condition (atomic insert)
  - SessionStore.get() returns expired sessions with closed status
"""
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from httpx import AsyncClient

from tests.cert_factory import (
    get_org_ca_pem, make_encrypted_envelope,
)
from app.broker.session import Session, SessionStatus, SessionStore

pytestmark = pytest.mark.asyncio


# ────────────────────────────────────────────────────────────────────────
# Helper — register org + CA + agent + binding + policy + login
# ────────────────────────────────────────────────────────────────────────

async def _setup_agent(client: AsyncClient, dpop, agent_id: str, org_id: str) -> str:
    """Register infrastructure and return a DPoP-bound token."""
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    })
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["test.read", "test.write"],
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read", "test.write"]},
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


# ────────────────────────────────────────────────────────────────────────
# 1. Session nonce capacity limit
# ────────────────────────────────────────────────────────────────────────

def test_session_nonce_capacity_limit():
    """Verify that the nonce cache evicts old entries at capacity (H2 fix)."""
    session = Session(
        session_id="test-session",
        initiator_agent_id="org::a",
        initiator_org_id="org",
        target_agent_id="org::b",
        target_org_id="org",
        requested_capabilities=[],
    )
    # Override the limit to a small number for testing
    session._MAX_NONCES = 5

    # First 5 nonces should be cacheable
    for i in range(5):
        assert session.is_nonce_cached(f"nonce-{i}") is False
        session.cache_nonce(f"nonce-{i}")

    assert len(session.used_nonces) == 5

    # New nonce at capacity: not cached (DB is source of truth)
    assert session.is_nonce_cached("nonce-new") is False

    # Caching it evicts one old entry, stays at cap
    session.cache_nonce("nonce-new")
    assert len(session.used_nonces) == 5
    assert "nonce-new" in session.used_nonces

    # Replayed nonces still in cache should be detected
    # (some old ones may have been evicted)
    cached_count = sum(1 for i in range(5) if session.is_nonce_cached(f"nonce-{i}"))
    assert cached_count == 4  # one was evicted to make room


# ────────────────────────────────────────────────────────────────────────
# 2. SessionStore.get() returns expired sessions (not None)
# ────────────────────────────────────────────────────────────────────────

def test_session_store_returns_expired_session_as_closed():
    """Expired sessions should be returned with status=closed, not None."""
    store = SessionStore(session_ttl_minutes=0)  # TTL of 0 = immediate expiry
    session = store.create(
        initiator_agent_id="org::a",
        initiator_org_id="org",
        target_agent_id="org::b",
        target_org_id="org",
        requested_capabilities=[],
    )
    sid = session.session_id

    # Force expiry by setting expires_at in the past
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

    retrieved = store.get(sid)
    assert retrieved is not None, "Expired session should be returned, not None"
    assert retrieved.status == SessionStatus.closed


# ────────────────────────────────────────────────────────────────────────
# 3. Envelope session_id mismatch
# ────────────────────────────────────────────────────────────────────────

async def test_envelope_session_id_mismatch(client: AsyncClient, dpop):
    """Message envelope session_id must match the URL path session_id."""
    token_a = await _setup_agent(client, dpop, "mismatch-org-a::agent", "mismatch-org-a")
    token_b = await _setup_agent(client, dpop, "mismatch-org-b::agent", "mismatch-org-b")

    # Create and accept a session
    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "mismatch-org-b::agent",
        "target_org_id": "mismatch-org-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    session_id = resp.json()["session_id"]

    await client.post(f"/v1/broker/sessions/{session_id}/accept",
        headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b))

    # Create an envelope with a wrong session_id
    nonce = str(uuid.uuid4())
    payload = {"msg": "test"}
    envelope = make_encrypted_envelope(
        "mismatch-org-a::agent", "mismatch-org-a",
        "mismatch-org-b::agent", "mismatch-org-b",
        session_id, nonce, payload,
    )
    # Tamper with the session_id in the envelope
    envelope["session_id"] = "wrong-session-id"

    msg_path = f"/v1/broker/sessions/{session_id}/messages"
    resp = await client.post(msg_path, json=envelope,
        headers=dpop.headers("POST", msg_path, token_a))
    assert resp.status_code == 400
    assert "session_id" in resp.json()["detail"].lower()


# ────────────────────────────────────────────────────────────────────────
# 4. Cache-Control header is set on API responses
# ────────────────────────────────────────────────────────────────────────

async def test_cache_control_header(client: AsyncClient):
    """All API responses must include Cache-Control: no-store."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"


# ────────────────────────────────────────────────────────────────────────
# 5. CA certificate validation on upload
# ────────────────────────────────────────────────────────────────────────

async def test_ca_cert_upload_rejects_non_ca(client: AsyncClient, dpop):
    """Uploading a non-CA certificate should be rejected."""
    org_id = "ca-val-org"
    org_secret = org_id + "-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    })

    # Create a non-CA (leaf) certificate
    from tests.cert_factory import make_agent_cert
    from cryptography.hazmat.primitives import serialization
    _, leaf_cert = make_agent_cert(f"{org_id}::leaf", org_id)
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()

    resp = await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": leaf_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code == 400
    assert "CA" in resp.json()["detail"]


async def test_ca_cert_upload_rejects_invalid_pem(client: AsyncClient):
    """Uploading garbage as a CA certificate should be rejected."""
    org_id = "ca-bad-org"
    org_secret = org_id + "-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    })

    resp = await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": "not-a-valid-pem-certificate"},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert resp.status_code == 400


# ────────────────────────────────────────────────────────────────────────
# 6. Session expiry enforcement on message send
# ────────────────────────────────────────────────────────────────────────

async def test_message_on_expired_session(client: AsyncClient, dpop):
    """Messages on expired sessions must be rejected with 409."""
    token_a = await _setup_agent(client, dpop, "exp-org-a::agent", "exp-org-a")
    token_b = await _setup_agent(client, dpop, "exp-org-b::agent", "exp-org-b")

    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": "exp-org-b::agent",
        "target_org_id": "exp-org-b",
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    session_id = resp.json()["session_id"]

    await client.post(f"/v1/broker/sessions/{session_id}/accept",
        headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b))

    # Force the session to be expired
    from app.broker.session import session_store
    session = session_store.get(session_id)
    assert session is not None
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

    nonce = str(uuid.uuid4())
    payload = {"msg": "test"}
    envelope = make_encrypted_envelope(
        "exp-org-a::agent", "exp-org-a",
        "exp-org-b::agent", "exp-org-b",
        session_id, nonce, payload,
    )
    msg_path = f"/v1/broker/sessions/{session_id}/messages"
    resp = await client.post(msg_path, json=envelope,
        headers=dpop.headers("POST", msg_path, token_a))
    # Should be rejected — session is expired
    assert resp.status_code == 409


# ────────────────────────────────────────────────────────────────────────
# 7. Webhook SSRF — loopback URLs rejected
# ────────────────────────────────────────────────────────────────────────

def test_webhook_ssrf_localhost_blocked(monkeypatch):
    """Webhook URLs pointing to localhost/loopback must be rejected.

    The project's `.env` sets POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=true for the
    Docker demo network, which would let loopback URLs through. This test
    temporarily forces the guard back on to exercise the production path.
    """
    from app.config import get_settings
    from app.policy.webhook import _validate_and_resolve_webhook_url

    # Force the production posture regardless of .env.
    get_settings().policy_webhook_allow_private_ips = False
    try:
        with pytest.raises(ValueError, match="loopback"):
            _validate_and_resolve_webhook_url("http://localhost:8080/pdp")

        with pytest.raises(ValueError, match="loopback"):
            _validate_and_resolve_webhook_url("http://127.0.0.1:8080/pdp")

        with pytest.raises(ValueError, match="loopback"):
            _validate_and_resolve_webhook_url("http://[::1]:8080/pdp")
    finally:
        # Restore whatever the settings had (re-read from .env).
        get_settings.cache_clear()


# ────────────────────────────────────────────────────────────────────────
# 8. SSRF DNS pinning preserves original hostname (not IP) in URL
# ────────────────────────────────────────────────────────────────────────

async def test_webhook_dns_pinning_preserves_hostname():
    """DNS pinning transport connects to the pinned IP but keeps the original URL
    so that TLS SNI uses the real hostname for certificate validation."""
    from app.policy.webhook import _PinnedDNSBackend
    import httpcore

    # Create a pinned backend pointing to a specific IP
    backend = _PinnedDNSBackend("93.184.216.34", 443)

    # Verify that connect_tcp receives the pinned IP, not the original host
    _original_connect = httpcore.AnyIOBackend.connect_tcp

    connected_hosts = []

    async def spy_connect(self, host, port, **kwargs):
        connected_hosts.append(host)
        raise ConnectionRefusedError("test — not actually connecting")

    import unittest.mock
    with unittest.mock.patch.object(httpcore.AnyIOBackend, "connect_tcp", spy_connect):
        try:
            await backend.connect_tcp("webhook.example.com", 443)
        except ConnectionRefusedError:
            pass

    assert connected_hosts == ["93.184.216.34"], \
        f"Expected pinned IP, got {connected_hosts}"


# ────────────────────────────────────────────────────────────────────────
# 9. WebSocket rejects agent with revoked binding
# ────────────────────────────────────────────────────────────────────────

def test_ws_binding_revoked_rejected():
    """An agent whose binding is revoked must get auth_error on WebSocket connect."""
    from starlette.testclient import TestClient
    from app.main import app
    from tests.cert_factory import make_assertion, get_org_ca_pem, DPoPHelper
    from tests.conftest import ADMIN_HEADERS

    _TESTSERVER = "http://testserver"
    dpop = DPoPHelper()

    with TestClient(app) as client:
        org_id = "ws-revoke-org"
        agent_id = f"{org_id}::agent"
        org_secret = f"{org_id}-secret"

        # Setup org + agent + binding
        client.post("/v1/registry/orgs", json={
            "org_id": org_id, "display_name": org_id, "secret": org_secret,
        }, headers=ADMIN_HEADERS)
        ca_pem = get_org_ca_pem(org_id)
        client.post(f"/v1/registry/orgs/{org_id}/certificate",
            json={"ca_certificate": ca_pem},
            headers={"x-org-id": org_id, "x-org-secret": org_secret},
        )
        client.post("/v1/registry/agents", json={
            "agent_id": agent_id, "org_id": org_id,
            "display_name": agent_id, "capabilities": ["order.read"],
        }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
        resp = client.post("/v1/registry/bindings",
            json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read"]},
            headers={"x-org-id": org_id, "x-org-secret": org_secret},
        )
        binding_id = resp.json()["id"]
        client.post(f"/v1/registry/bindings/{binding_id}/approve",
            headers={"x-org-id": org_id, "x-org-secret": org_secret},
        )

        # Get token while binding is active
        assertion = make_assertion(agent_id, org_id)
        dpop_proof = dpop.proof("POST", f"{_TESTSERVER}/v1/auth/token")
        resp = client.post(
            "/v1/auth/token",
            json={"client_assertion": assertion},
            headers={"DPoP": dpop_proof},
        )
        assert resp.status_code == 200
        token = resp.json()["access_token"]

        # Revoke the binding
        resp = client.post(f"/v1/registry/bindings/{binding_id}/revoke",
            headers={"x-org-id": org_id, "x-org-secret": org_secret},
        )
        assert resp.status_code == 200, f"Revoke failed: {resp.text}"

        # Try to connect via WebSocket — should be rejected
        ws_proof = dpop.proof("GET", f"{_TESTSERVER}/v1/broker/ws", access_token=token)
        with client.websocket_connect("/v1/broker/ws") as ws:
            ws.send_json({"type": "auth", "token": token, "dpop_proof": ws_proof})
            data = ws.receive_json()

    assert data["type"] == "auth_error"
    assert "binding" in data["detail"].lower() or "revoked" in data["detail"].lower()


# ────────────────────────────────────────────────────────────────────────
# 10. Audit log hash chain serialization under concurrency
# ────────────────────────────────────────────────────────────────────────

async def test_audit_chain_concurrent_inserts():
    """Concurrent audit log inserts must produce a valid hash chain.

    The _audit_chain_lock serializes access, preventing two coroutines from
    reading the same previous_hash and forking the chain. We verify by
    scheduling multiple coroutines that contend on the lock and then
    checking chain integrity.

    Note: SQLite StaticPool shares a single connection, so we use the same
    session for all inserts to avoid connection-level conflicts.
    """
    import asyncio
    from app.db.audit import log_event, verify_chain
    from tests.conftest import TestSessionLocal

    # Use a shared session (SQLite StaticPool limitation)
    async with TestSessionLocal() as db:
        # Create multiple tasks that will contend on the audit chain lock
        tasks = []
        for i in range(10):
            tasks.append(
                log_event(db, f"concurrent.test.{i}", "ok", agent_id=f"agent-{i}")
            )
        # asyncio.gather schedules all coroutines; the lock serializes them
        await asyncio.gather(*tasks)

    # Verify the chain is intact (no bifurcation)
    async with TestSessionLocal() as db:
        is_valid, total, broken_id = await verify_chain(db)

    assert is_valid, f"Hash chain broken at entry {broken_id} (checked {total} entries)"
    assert total >= 10, f"Expected at least 10 entries, got {total}"
