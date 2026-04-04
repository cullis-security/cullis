"""
Test firma crittografica dei messaggi inter-agente con E2E encryption.

Con E2E il broker verifica la firma esterna sul ciphertext (integrità trasporto).
La firma interna sul plaintext è verificabile solo dal destinatario dopo la decifratura.

Verifica che:
  1. Envelope E2E valido → 202
  2. Campo signature mancante → 422
  3. Ciphertext manomesso dopo la firma → 401
  4. Firma esterna con session_id sbagliato → 401
  5. Firma esterna con nonce sbagliato → 401
  6. Firma esterna da un altro agente → 401
  7. Signature salvata nel DB e recuperabile via polling
  8. Firma esterna verificabile post-hoc con la pubkey del cert
"""
import base64
import json
import uuid

import pytest
from httpx import AsyncClient

from app.auth.message_signer import sign_message as _sign, verify_message_signature
from app.e2e_crypto import encrypt_for_agent
from tests.cert_factory import (
    make_assertion, get_org_ca_pem, sign_message, get_agent_key_pem, make_agent_cert,
    get_agent_pubkey_pem, make_encrypted_envelope,
)
from tests.conftest import ADMIN_HEADERS
from cryptography.hazmat.primitives import hashes, serialization

pytestmark = pytest.mark.asyncio

# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

async def _setup(client: AsyncClient, agent_id: str, org_id: str, dpop) -> str:
    """Register org + CA + agent + binding + policy; return access token."""
    secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={"org_id": org_id, "display_name": org_id, "secret": secret}, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["order.read"],
    }, headers={"x-org-id": org_id, "x-org-secret": secret})
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read"]},
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    await client.post(f"/v1/registry/bindings/{resp.json()['id']}/approve",
        headers={"x-org-id": org_id, "x-org-secret": secret},
    )
    await client.post("/v1/policy/rules", json={
        "policy_id": f"{org_id}::allow-all",
        "org_id": org_id, "policy_type": "session",
        "rules": {"effect": "allow", "conditions": {"target_org_id": [], "capabilities": []}},
    }, headers={"x-org-id": org_id, "x-org-secret": secret})
    return await dpop.get_token(client, agent_id, org_id)


async def _open_active_session(client, token_a, token_b, agent_b_id, org_b, dpop) -> str:
    resp = await client.post("/v1/broker/sessions", json={
        "target_agent_id": agent_b_id,
        "target_org_id": org_b,
        "requested_capabilities": [],
    }, headers=dpop.headers("POST", "/v1/broker/sessions", token_a))
    session_id = resp.json()["session_id"]
    await client.post(f"/v1/broker/sessions/{session_id}/accept",
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/accept", token_b))
    return session_id


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — valid signature → 202
# ─────────────────────────────────────────────────────────────────────────────

async def test_valid_signature_accepted(client: AsyncClient, dpop):
    token_a = await _setup(client, "sig-valid-a::agent", "sig-valid-a", dpop)
    token_b = await _setup(client, "sig-valid-b::agent", "sig-valid-b", dpop)
    session_id = await _open_active_session(client, token_a, token_b, "sig-valid-b::agent", "sig-valid-b", dpop)

    nonce = str(uuid.uuid4())
    payload = {"type": "order", "qty": 100}
    envelope = make_encrypted_envelope(
        "sig-valid-a::agent", "sig-valid-a",
        "sig-valid-b::agent", "sig-valid-b",
        session_id, nonce, payload,
    )
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages",
                             json=envelope,
                             headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 202


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — missing signature field → 422
# ─────────────────────────────────────────────────────────────────────────────

async def test_missing_signature_rejected(client: AsyncClient, dpop):
    token_a = await _setup(client, "sig-miss-a::agent", "sig-miss-a", dpop)
    token_b = await _setup(client, "sig-miss-b::agent", "sig-miss-b", dpop)
    session_id = await _open_active_session(client, token_a, token_b, "sig-miss-b::agent", "sig-miss-b", dpop)

    nonce = str(uuid.uuid4())
    recipient_pubkey = get_agent_pubkey_pem("sig-miss-b::agent", "sig-miss-b")
    cipher_blob = encrypt_for_agent(recipient_pubkey, {"type": "order"}, "fake-inner-sig", session_id, "sig-miss-a::agent")
    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "sig-miss-a::agent",
        "payload": cipher_blob,
        "nonce": nonce,
        # no "signature" field
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — payload tampered after signing → 401
# ─────────────────────────────────────────────────────────────────────────────

async def test_tampered_payload_rejected(client: AsyncClient, dpop):
    """Ciphertext manomesso dopo la firma esterna → il broker rileva la discrepanza → 401."""
    token_a = await _setup(client, "sig-tamp-a::agent", "sig-tamp-a", dpop)
    token_b = await _setup(client, "sig-tamp-b::agent", "sig-tamp-b", dpop)
    session_id = await _open_active_session(client, token_a, token_b, "sig-tamp-b::agent", "sig-tamp-b", dpop)

    nonce = str(uuid.uuid4())
    payload = {"type": "order", "qty": 100}
    envelope = make_encrypted_envelope(
        "sig-tamp-a::agent", "sig-tamp-a",
        "sig-tamp-b::agent", "sig-tamp-b",
        session_id, nonce, payload,
    )
    # Manometti il ciphertext dopo la firma esterna
    envelope["payload"]["ciphertext"] = base64.b64encode(b"manomesso" * 20).decode()

    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages",
                             json=envelope,
                             headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — signature produced with wrong session_id → 401
# ─────────────────────────────────────────────────────────────────────────────

async def test_wrong_session_id_in_signature_rejected(client: AsyncClient, dpop):
    """Firma esterna prodotta con session_id sbagliato → il broker la rifiuta → 401."""
    token_a = await _setup(client, "sig-sess-a::agent", "sig-sess-a", dpop)
    token_b = await _setup(client, "sig-sess-b::agent", "sig-sess-b", dpop)
    session_id = await _open_active_session(client, token_a, token_b, "sig-sess-b::agent", "sig-sess-b", dpop)

    nonce = str(uuid.uuid4())
    payload = {"type": "order"}
    wrong_session_id = str(uuid.uuid4())

    recipient_pubkey = get_agent_pubkey_pem("sig-sess-b::agent", "sig-sess-b")
    inner_sig, _ts = sign_message("sig-sess-a::agent", "sig-sess-a", session_id, "sig-sess-a::agent", nonce, payload)
    cipher_blob = encrypt_for_agent(recipient_pubkey, payload, inner_sig, session_id, "sig-sess-a::agent")
    # Firma esterna usa session_id sbagliato
    outer_sig, _ = sign_message("sig-sess-a::agent", "sig-sess-a", wrong_session_id, "sig-sess-a::agent", nonce, cipher_blob)

    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "sig-sess-a::agent",
        "payload": cipher_blob,
        "nonce": nonce,
        "timestamp": _ts,
        "signature": outer_sig,
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — signature produced with wrong nonce → 401
# ─────────────────────────────────────────────────────────────────────────────

async def test_wrong_nonce_in_signature_rejected(client: AsyncClient, dpop):
    """Firma esterna prodotta con nonce sbagliato → il broker la rifiuta → 401."""
    token_a = await _setup(client, "sig-nonce-a::agent", "sig-nonce-a", dpop)
    token_b = await _setup(client, "sig-nonce-b::agent", "sig-nonce-b", dpop)
    session_id = await _open_active_session(client, token_a, token_b, "sig-nonce-b::agent", "sig-nonce-b", dpop)

    real_nonce = str(uuid.uuid4())
    wrong_nonce = str(uuid.uuid4())
    payload = {"type": "order"}

    recipient_pubkey = get_agent_pubkey_pem("sig-nonce-b::agent", "sig-nonce-b")
    inner_sig, _ts = sign_message("sig-nonce-a::agent", "sig-nonce-a", session_id, "sig-nonce-a::agent", real_nonce, payload)
    cipher_blob = encrypt_for_agent(recipient_pubkey, payload, inner_sig, session_id, "sig-nonce-a::agent")
    # Firma esterna usa il nonce sbagliato
    outer_sig, _ = sign_message("sig-nonce-a::agent", "sig-nonce-a", session_id, "sig-nonce-a::agent", wrong_nonce, cipher_blob)

    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "sig-nonce-a::agent",
        "payload": cipher_blob,
        "nonce": real_nonce,
        "timestamp": _ts,
        "signature": outer_sig,
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — signature from another agent → 401
# ─────────────────────────────────────────────────────────────────────────────

async def test_signature_from_wrong_agent_rejected(client: AsyncClient, dpop):
    """B firma la firma esterna, ma il messaggio viene inviato da A — il broker usa il cert di A → 401."""
    token_a = await _setup(client, "sig-cross-a::agent", "sig-cross-a", dpop)
    token_b = await _setup(client, "sig-cross-b::agent", "sig-cross-b", dpop)
    session_id = await _open_active_session(client, token_a, token_b, "sig-cross-b::agent", "sig-cross-b", dpop)

    nonce = str(uuid.uuid4())
    payload = {"type": "order"}

    recipient_pubkey = get_agent_pubkey_pem("sig-cross-b::agent", "sig-cross-b")
    inner_sig, _ts = sign_message("sig-cross-a::agent", "sig-cross-a", session_id, "sig-cross-a::agent", nonce, payload)
    cipher_blob = encrypt_for_agent(recipient_pubkey, payload, inner_sig, session_id, "sig-cross-a::agent")
    # B firma la firma esterna invece di A — il broker usa il cert di A per verificare
    outer_sig_by_b, _ = sign_message("sig-cross-b::agent", "sig-cross-b", session_id,
                                      "sig-cross-a::agent", nonce, cipher_blob)

    resp = await client.post(f"/v1/broker/sessions/{session_id}/messages", json={
        "session_id": session_id,
        "sender_agent_id": "sig-cross-a::agent",
        "payload": cipher_blob,
        "nonce": nonce,
        "timestamp": _ts,
        "signature": outer_sig_by_b,
    }, headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))
    assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Test 7 — signature saved to DB and retrievable via polling
# ─────────────────────────────────────────────────────────────────────────────

async def test_signature_persisted_and_retrievable(client: AsyncClient, dpop):
    """La firma esterna deve essere presente nel messaggio restituito dal polling."""
    token_a = await _setup(client, "sig-poll-a::agent", "sig-poll-a", dpop)
    token_b = await _setup(client, "sig-poll-b::agent", "sig-poll-b", dpop)
    session_id = await _open_active_session(client, token_a, token_b, "sig-poll-b::agent", "sig-poll-b", dpop)

    nonce = str(uuid.uuid4())
    payload = {"type": "order", "qty": 42}
    envelope = make_encrypted_envelope(
        "sig-poll-a::agent", "sig-poll-a",
        "sig-poll-b::agent", "sig-poll-b",
        session_id, nonce, payload,
    )

    await client.post(f"/v1/broker/sessions/{session_id}/messages",
                      json=envelope,
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))

    # B recupera il messaggio: il payload è ancora il ciphertext, la firma è quella esterna
    resp = await client.get(f"/v1/broker/sessions/{session_id}/messages",
                            params={"after": -1},
                            headers=dpop.headers("GET", f"/v1/broker/sessions/{session_id}/messages", token_b))
    assert resp.status_code == 200
    msgs = resp.json()
    assert len(msgs) == 1
    assert msgs[0]["signature"] == envelope["signature"]
    # Il payload persistito è il ciphertext blob
    assert "ciphertext" in msgs[0]["payload"]


# ─────────────────────────────────────────────────────────────────────────────
# Test 8 — signature verifiable post-hoc with cert's public key
# ─────────────────────────────────────────────────────────────────────────────

async def test_signature_verifiable_with_public_key(client: AsyncClient, dpop):
    """
    La firma esterna sul ciphertext è verificabile post-hoc con il cert del mittente.
    Simula un auditor esterno che verifica un messaggio dal log di audit.
    """
    agent_id = "sig-audit-a::agent"
    org_id = "sig-audit-a"

    token_a = await _setup(client, agent_id, org_id, dpop)
    token_b = await _setup(client, "sig-audit-b::agent", "sig-audit-b", dpop)
    session_id = await _open_active_session(client, token_a, token_b, "sig-audit-b::agent", "sig-audit-b", dpop)

    nonce = str(uuid.uuid4())
    payload = {"type": "order", "qty": 100, "item": "bulloni M8"}
    envelope = make_encrypted_envelope(
        agent_id, org_id,
        "sig-audit-b::agent", "sig-audit-b",
        session_id, nonce, payload,
    )

    await client.post(f"/v1/broker/sessions/{session_id}/messages",
                      json=envelope,
                      headers=dpop.headers("POST", f"/v1/broker/sessions/{session_id}/messages", token_a))

    # Recupera il messaggio via polling
    resp = await client.get(f"/v1/broker/sessions/{session_id}/messages",
                            params={"after": -1},
                            headers=dpop.headers("GET", f"/v1/broker/sessions/{session_id}/messages", token_b))
    msg = resp.json()[0]

    # Verifica la firma esterna con il cert del mittente (come farebbe un auditor)
    agent_key, agent_cert = make_agent_cert(agent_id, org_id)
    cert_pem = agent_cert.public_bytes(serialization.Encoding.PEM).decode()

    # La firma copre il ciphertext blob — deve passare senza eccezioni
    verify_message_signature(
        cert_pem,
        msg["signature"],
        session_id,
        msg["sender_agent_id"],
        msg["nonce"],
        envelope["timestamp"],  # timestamp usato al momento della firma
        msg["payload"],  # è il ciphertext blob
    )

    # Una firma falsificata deve essere rifiutata
    from fastapi import HTTPException
    fake_sig = base64.b64encode(b"fakesignature" * 20).decode()
    with pytest.raises(HTTPException) as exc_info:
        verify_message_signature(cert_pem, fake_sig, session_id, agent_id, nonce, envelope["timestamp"], msg["payload"])
    assert exc_info.value.status_code == 401
