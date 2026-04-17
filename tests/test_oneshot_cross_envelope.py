"""ADR-008 Phase 1 PR #3 — cross-org envelope E2E + SDK req/resp helper.

Three groups:

A. Broker accepts ``mode=envelope`` with opaque cipher_blob payload.
B. SDK crypto roundtrip — encrypt_for_agent + decrypt_oneshot + inner
   signature verification + AAD binding.
C. ``send_oneshot_and_wait`` contract via mocked proxy HTTP.

End-to-end proxy↔broker↔proxy via ASGI transport is already covered by
``demo_network/smoke.sh``; unit-testing the full path in-process would
require mounting a fake broker on top of the proxy app. These tests
focus on the correctness gates that unit testing is best at.
"""
from __future__ import annotations

import json
import time
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient

from cullis_sdk.client import CullisClient
from cullis_sdk.crypto.e2e import (
    decrypt_from_agent,
    encrypt_for_agent,
    verify_inner_signature,
)
from cullis_sdk.crypto.message_signer import (
    ONESHOT_ENVELOPE_PROTO_VERSION,
    sign_message,
    sign_oneshot_envelope,
)
from tests.cert_factory import (
    DPoPHelper,
    get_agent_key_pem,
    get_agent_pubkey_pem,
)
from tests.test_oneshot_cross import (  # reuse helpers from PR #2 suite
    _register_and_login,
    _mock_oneshot_pdp,  # noqa — autouse fixture re-exported for patch scope
)


pytestmark = pytest.mark.asyncio


# ── Helpers ────────────────────────────────────────────────────────────

def _make_cipher_blob(
    *,
    recipient_pubkey_pem: str,
    correlation_id: str,
    sender_agent_id: str,
    sender_key_pem: str,
    payload: dict,
    nonce: str,
    timestamp: int,
    reply_to: str | None = None,
) -> tuple[dict, str, str]:
    """Return (cipher_blob, inner_signature, outer_envelope_signature).

    Outer signature is v2: covers full envelope (mode=envelope, reply_to,
    correlation_id, nonce, timestamp, cipher_blob).
    """
    inner_sig = sign_message(
        sender_key_pem,
        f"oneshot:{correlation_id}",
        sender_agent_id,
        nonce,
        timestamp,
        payload,
        client_seq=0,
    )
    cipher_blob = encrypt_for_agent(
        recipient_pubkey_pem, payload, inner_sig,
        f"oneshot:{correlation_id}", sender_agent_id, client_seq=0,
    )
    outer_sig = sign_oneshot_envelope(
        sender_key_pem,
        correlation_id=correlation_id,
        sender_agent_id=sender_agent_id,
        nonce=nonce,
        timestamp=timestamp,
        mode="envelope",
        reply_to=reply_to,
        payload=cipher_blob,
    )
    return cipher_blob, inner_sig, outer_sig


# ── Group A — broker accepts envelope mode ────────────────────────────

async def test_broker_accepts_envelope_mode(client: AsyncClient):
    """Broker stores an envelope cipher_blob as opaque payload and serves
    it back unchanged through /inbox."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(
        client, dpop_a, "env1::alice", "env1",
    )
    token_b = await _register_and_login(
        client, dpop_b, "envt1::bob", "envt1",
    )

    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("env1::alice", "env1")
    bob_pubkey = get_agent_pubkey_pem("envt1::bob", "envt1")

    cipher_blob, _inner, outer_sig = _make_cipher_blob(
        recipient_pubkey_pem=bob_pubkey,
        correlation_id=corr,
        sender_agent_id="env1::alice",
        sender_key_pem=alice_priv,
        payload={"msg": "confidential"},
        nonce=nonce,
        timestamp=ts,
    )

    body = {
        "recipient_agent_id": "envt1::bob",
        "correlation_id": corr,
        "reply_to_correlation_id": None,
        "payload": cipher_blob,
        "signature": outer_sig,
        "nonce": nonce,
        "timestamp": ts,
        "mode": "envelope",
        "ttl_seconds": 300,
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
    }
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers(
            "POST", "/v1/broker/oneshot/forward", token_a,
        ),
    )
    assert r.status_code == 202, r.text

    r2 = await client.get(
        "/v1/broker/oneshot/inbox",
        headers=dpop_b.headers("GET", "/v1/broker/oneshot/inbox", token_b),
    )
    assert r2.status_code == 200
    inbox = r2.json()["messages"]
    assert len(inbox) == 1
    returned_envelope = json.loads(inbox[0]["envelope_json"])
    assert returned_envelope["mode"] == "envelope"
    # Broker faithfully echoes the opaque cipher_blob.
    assert returned_envelope["payload"] == cipher_blob


async def test_broker_rejects_tampered_outer_signature_envelope(
    client: AsyncClient,
):
    """Outer signature still verified even when payload is opaque."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(
        client, dpop_a, "env2::alice", "env2",
    )
    await _register_and_login(client, dpop_b, "envt2::bob", "envt2")

    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("env2::alice", "env2")
    bob_pubkey = get_agent_pubkey_pem("envt2::bob", "envt2")

    cipher_blob, _i, outer_sig = _make_cipher_blob(
        recipient_pubkey_pem=bob_pubkey,
        correlation_id=corr,
        sender_agent_id="env2::alice",
        sender_key_pem=alice_priv,
        payload={"x": 1},
        nonce=nonce,
        timestamp=ts,
    )
    # Flip a byte in the b64url signature
    bad_sig = outer_sig[:-4] + ("AAAA" if not outer_sig.endswith("AAAA") else "BBBB")

    body = {
        "recipient_agent_id": "envt2::bob",
        "correlation_id": corr,
        "reply_to_correlation_id": None,
        "payload": cipher_blob,
        "signature": bad_sig,
        "nonce": nonce,
        "timestamp": ts,
        "mode": "envelope",
        "ttl_seconds": 300,
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
    }
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers(
            "POST", "/v1/broker/oneshot/forward", token_a,
        ),
    )
    assert r.status_code == 401


# ── Group B — SDK crypto roundtrip ─────────────────────────────────────

async def test_sdk_decrypt_oneshot_envelope_roundtrip(client: AsyncClient):
    """encrypt_for_agent + decrypt_oneshot returns matching plaintext and
    verifies inner signature against the broker registry cert."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    await _register_and_login(client, dpop_a, "env3::alice", "env3")
    await _register_and_login(client, dpop_b, "envt3::bob", "envt3")

    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("env3::alice", "env3")
    bob_priv = get_agent_key_pem("envt3::bob", "envt3")
    bob_pubkey = get_agent_pubkey_pem("envt3::bob", "envt3")

    payload = {"quote": 42, "currency": "EUR"}
    cipher_blob, inner_sig, _outer = _make_cipher_blob(
        recipient_pubkey_pem=bob_pubkey,
        correlation_id=corr,
        sender_agent_id="env3::alice",
        sender_key_pem=alice_priv,
        payload=payload,
        nonce=nonce,
        timestamp=ts,
    )

    envelope_json = json.dumps({
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
        "mode": "envelope",
        "payload": cipher_blob,
        "signature": _outer,
        "nonce": nonce,
        "timestamp": ts,
        "correlation_id": corr,
        "reply_to": None,
    }, separators=(",", ":"), sort_keys=True)
    inbox_row = {
        "msg_id": str(uuid.uuid4()),
        "correlation_id": corr,
        "reply_to": None,
        "sender_agent_id": "env3::alice",
        "payload_ciphertext": envelope_json,
        "idempotency_key": f"oneshot:{corr}",
        "enqueued_at": "2026-04-16T00:00:00+00:00",
        "expires_at": None,
    }

    # Construct a Bob client, swap its HTTP stack to talk to the broker ASGI.
    bob_client = CullisClient("http://test", verify_tls=False)
    bob_client._signing_key_pem = bob_priv
    # Pre-seed pubkey cache so decrypt_oneshot doesn't need a live broker.
    alice_cert_pem = _alice_cert_pem = _get_alice_cert_pem = None
    from tests.cert_factory import make_agent_cert
    from cryptography.hazmat.primitives import serialization
    _, alice_cert = make_agent_cert("env3::alice", "env3")
    alice_cert_pem = alice_cert.public_bytes(
        serialization.Encoding.PEM,
    ).decode()
    bob_client._pubkey_cache["env3::alice"] = (alice_cert_pem, time.time())

    decoded = bob_client.decrypt_oneshot(inbox_row)
    assert decoded["mode"] == "envelope"
    assert decoded["sender_verified"] is True
    assert decoded["payload"] == payload
    bob_client.close()


async def test_sdk_decrypt_rejects_tampered_inner_signature(
    client: AsyncClient,
):
    """Swap inner_sig inside the cipher_blob → verify_inner_signature raises.

    We exercise this at the crypto helper level directly: build a valid
    cipher_blob, decrypt to get plaintext + inner_sig, flip a byte,
    call verify_inner_signature → ValueError.
    """
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("env4::alice", "env4")
    bob_priv = get_agent_key_pem("envt4::bob", "envt4")
    bob_pubkey = get_agent_pubkey_pem("envt4::bob", "envt4")
    from tests.cert_factory import make_agent_cert
    from cryptography.hazmat.primitives import serialization
    _, alice_cert = make_agent_cert("env4::alice", "env4")
    alice_cert_pem = alice_cert.public_bytes(
        serialization.Encoding.PEM,
    ).decode()

    cipher_blob, inner_sig, _outer = _make_cipher_blob(
        recipient_pubkey_pem=bob_pubkey,
        correlation_id=corr,
        sender_agent_id="env4::alice",
        sender_key_pem=alice_priv,
        payload={"ok": True},
        nonce=nonce,
        timestamp=ts,
    )
    plaintext, _ = decrypt_from_agent(
        bob_priv, cipher_blob, f"oneshot:{corr}", "env4::alice", client_seq=0,
    )

    tampered = inner_sig[:-4] + ("AAAA" if not inner_sig.endswith("AAAA") else "BBBB")
    with pytest.raises(ValueError):
        verify_inner_signature(
            alice_cert_pem, tampered,
            f"oneshot:{corr}", "env4::alice", nonce, ts, plaintext,
            client_seq=0,
        )


async def test_aad_binding_rejects_wrong_correlation_id(
    client: AsyncClient,
):
    """AAD = ``oneshot:<corr>|sender|0`` pins the cipher_blob to that
    correlation_id. Decrypting with a different corr must fail.
    """
    corr_real = str(uuid.uuid4())
    corr_attacker = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("env5::alice", "env5")
    bob_priv = get_agent_key_pem("envt5::bob", "envt5")
    bob_pubkey = get_agent_pubkey_pem("envt5::bob", "envt5")

    cipher_blob, _i, _o = _make_cipher_blob(
        recipient_pubkey_pem=bob_pubkey,
        correlation_id=corr_real,
        sender_agent_id="env5::alice",
        sender_key_pem=alice_priv,
        payload={"secret": True},
        nonce=nonce,
        timestamp=ts,
    )

    # Try to decrypt the blob under a wrong AAD (different corr)
    with pytest.raises(Exception):
        decrypt_from_agent(
            bob_priv, cipher_blob,
            f"oneshot:{corr_attacker}", "env5::alice", client_seq=0,
        )


async def test_broker_cannot_decrypt_envelope(client: AsyncClient):
    """Decrypting a cipher_blob with a non-recipient key must fail."""
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("env6::alice", "env6")
    bob_pubkey = get_agent_pubkey_pem("envt6::bob", "envt6")
    # Use alice's own priv to simulate an attacker with broker-equivalent powers
    attacker_priv = alice_priv

    cipher_blob, _i, _o = _make_cipher_blob(
        recipient_pubkey_pem=bob_pubkey,
        correlation_id=corr,
        sender_agent_id="env6::alice",
        sender_key_pem=alice_priv,
        payload={"secret": True},
        nonce=nonce,
        timestamp=ts,
    )
    with pytest.raises(Exception):
        decrypt_from_agent(
            attacker_priv, cipher_blob,
            f"oneshot:{corr}", "env6::alice", client_seq=0,
        )


# ── Group C — send_oneshot_and_wait contract ─────────────────────────

def test_send_oneshot_and_wait_returns_reply():
    """Mock the proxy HTTP surface: /resolve + /message/send + /inbox.
    The helper should loop polling until a row with matching reply_to
    appears, then return the decrypted plaintext.
    """
    alice_priv = get_agent_key_pem("env7::alice", "env7")
    bob_priv = get_agent_key_pem("envt7::bob", "envt7")
    bob_pubkey = get_agent_pubkey_pem("envt7::bob", "envt7")
    from tests.cert_factory import make_agent_cert
    from cryptography.hazmat.primitives import serialization
    _, bob_cert = make_agent_cert("envt7::bob", "envt7")
    bob_cert_pem = bob_cert.public_bytes(serialization.Encoding.PEM).decode()

    # Client posing as Alice (sender). send_oneshot_and_wait will:
    #   1. POST /resolve
    #   2. POST /message/send
    #   3. loop GET /inbox until it sees a row with reply_to=corr
    alice = CullisClient("http://mock-proxy", verify_tls=False)
    alice._signing_key_pem = alice_priv
    alice._proxy_api_key = "fake-api-key"
    alice._proxy_agent_id = "env7::alice"
    alice._proxy_org_id = "env7"

    # Seed Alice's pubkey cache so decrypt_oneshot finds Bob's cert when
    # verifying his inner signature on the reply.
    alice._pubkey_cache["envt7::bob"] = (bob_cert_pem, time.time())

    # Pre-compute Bob's reply ciphertext + outer envelope.
    #   Alice sends: payload={"q": "price?"}, corr=C
    #   Bob replies: payload={"a": 100}, reply_to=C, new corr=C2
    def _build_reply_row(request_corr: str) -> dict:
        reply_corr = str(uuid.uuid4())
        reply_nonce = str(uuid.uuid4())
        reply_ts = int(time.time())
        # Alice's pubkey to encrypt toward her
        alice_pubkey = get_agent_pubkey_pem("env7::alice", "env7")
        reply_plain = {"a": 100}
        inner = sign_message(
            bob_priv, f"oneshot:{reply_corr}", "envt7::bob",
            reply_nonce, reply_ts, reply_plain, client_seq=0,
        )
        cipher = encrypt_for_agent(
            alice_pubkey, reply_plain, inner,
            f"oneshot:{reply_corr}", "envt7::bob", client_seq=0,
        )
        outer = sign_oneshot_envelope(
            bob_priv,
            correlation_id=reply_corr,
            sender_agent_id="envt7::bob",
            nonce=reply_nonce,
            timestamp=reply_ts,
            mode="envelope",
            reply_to=request_corr,
            payload=cipher,
        )
        env = {
            "v": ONESHOT_ENVELOPE_PROTO_VERSION,
            "mode": "envelope",
            "payload": cipher,
            "signature": outer,
            "nonce": reply_nonce,
            "timestamp": reply_ts,
            "correlation_id": reply_corr,
            "reply_to": request_corr,
        }
        return {
            "msg_id": str(uuid.uuid4()),
            "correlation_id": reply_corr,
            "reply_to": request_corr,
            "sender_agent_id": "envt7::bob",
            "payload_ciphertext": json.dumps(env, separators=(",", ":"), sort_keys=True),
            "idempotency_key": f"oneshot:{reply_corr}",
            "enqueued_at": "2026-04-16T00:00:00+00:00",
            "expires_at": None,
        }

    captured: dict[str, str] = {}

    def _fake_post(url: str, *args, **kwargs):
        body = kwargs.get("json", {})
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.headers = {}
        if url.endswith("/v1/egress/resolve"):
            resp.json.return_value = {
                "path": "cross-org",
                "target_agent_id": "envt7::bob",
                "target_org_id": "envt7",
                "target_spiffe": None,
                "transport": "envelope",
                "egress_inspection": False,
                "target_cert_pem": bob_pubkey,
            }
            return resp
        if url.endswith("/v1/egress/message/send"):
            captured["corr"] = body["correlation_id"]
            resp.json.return_value = {
                "correlation_id": body["correlation_id"],
                "msg_id": str(uuid.uuid4()),
                "status": "enqueued",
            }
            return resp
        raise AssertionError(f"unexpected POST: {url}")

    call_count = {"inbox": 0}
    reply_row_container: dict[str, dict] = {}

    def _fake_get(url: str, *args, **kwargs):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.headers = {}
        if url.endswith("/v1/egress/message/inbox"):
            call_count["inbox"] += 1
            # Return the reply only on the second poll so we exercise
            # the loop.
            if call_count["inbox"] >= 2:
                if "row" not in reply_row_container:
                    reply_row_container["row"] = _build_reply_row(
                        captured["corr"],
                    )
                resp.json.return_value = {
                    "messages": [reply_row_container["row"]], "count": 1,
                }
            else:
                resp.json.return_value = {"messages": [], "count": 0}
            return resp
        raise AssertionError(f"unexpected GET: {url}")

    alice._http = MagicMock()
    alice._http.post.side_effect = _fake_post
    alice._http.get.side_effect = _fake_get

    result = alice.send_oneshot_and_wait(
        "envt7::bob", {"q": "price?"},
        timeout=5.0, poll_interval=0.1,
    )

    assert result["reply"] == {"a": 100}
    assert result["sender"] == "envt7::bob"
    assert result["mode"] == "envelope"
    assert result["sender_verified"] is True
    assert call_count["inbox"] >= 2


def test_send_oneshot_and_wait_timeout():
    """No matching reply within timeout → TimeoutError."""
    alice_priv = get_agent_key_pem("env8::alice", "env8")
    bob_pubkey = get_agent_pubkey_pem("envt8::bob", "envt8")

    alice = CullisClient("http://mock-proxy", verify_tls=False)
    alice._signing_key_pem = alice_priv
    alice._proxy_api_key = "fake-api-key"
    alice._proxy_agent_id = "env8::alice"

    def _fake_post(url: str, *args, **kwargs):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.headers = {}
        if url.endswith("/v1/egress/resolve"):
            resp.json.return_value = {
                "path": "cross-org",
                "target_agent_id": "envt8::bob",
                "target_org_id": "envt8",
                "target_spiffe": None,
                "transport": "envelope",
                "egress_inspection": False,
                "target_cert_pem": bob_pubkey,
            }
            return resp
        if url.endswith("/v1/egress/message/send"):
            body = kwargs.get("json", {})
            resp.json.return_value = {
                "correlation_id": body["correlation_id"],
                "msg_id": str(uuid.uuid4()),
                "status": "enqueued",
            }
            return resp
        raise AssertionError(url)

    def _fake_get(url: str, *args, **kwargs):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.headers = {}
        resp.json.return_value = {"messages": [], "count": 0}
        return resp

    alice._http = MagicMock()
    alice._http.post.side_effect = _fake_post
    alice._http.get.side_effect = _fake_get

    with pytest.raises(TimeoutError):
        alice.send_oneshot_and_wait(
            "envt8::bob", {"q": "?"},
            timeout=0.5, poll_interval=0.1,
        )


# ── Group D — /resolve populates target_cert_pem cross-org ───────────

async def test_proxy_resolve_populates_target_cert_pem_cross_org(tmp_path, monkeypatch):
    """Proxy /resolve hits BrokerBridge.get_peer_public_key on cross-org."""
    from httpx import ASGITransport as _ASGIT, AsyncClient as _AC
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import create_agent

    db_file = tmp_path / "resolve.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "resolveorg")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app

    fake_bridge = MagicMock()
    fake_bridge.get_peer_public_key = AsyncMock(return_value="-----FAKE CERT-----")
    fake_bridge.shutdown = AsyncMock()

    transport = _ASGIT(app=app)
    async with _AC(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            app.state.broker_bridge = fake_bridge
            raw = generate_api_key("alice")
            await create_agent(
                agent_id="alice",
                display_name="alice",
                capabilities=["oneshot.message"],
                api_key_hash=hash_api_key(raw),
                cert_pem="-----X-----",
            )
            r = await cli.post(
                "/v1/egress/resolve",
                headers={"X-API-Key": raw},
                json={"recipient_id": "other::bob"},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["path"] == "cross-org"
            assert body["transport"] == "envelope"
            assert body["target_cert_pem"] == "-----FAKE CERT-----"
            fake_bridge.get_peer_public_key.assert_awaited_once_with(
                "alice", "other::bob",
            )
    get_settings.cache_clear()


async def test_proxy_resolve_fails_closed_on_bridge_error(tmp_path, monkeypatch):
    """If BrokerBridge.get_peer_public_key raises, /resolve returns 502."""
    from httpx import ASGITransport as _ASGIT, AsyncClient as _AC
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import create_agent

    db_file = tmp_path / "resolve_fail.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "resolvefailorg")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app

    fake_bridge = MagicMock()
    fake_bridge.get_peer_public_key = AsyncMock(
        side_effect=RuntimeError("broker down"),
    )
    fake_bridge.shutdown = AsyncMock()

    transport = _ASGIT(app=app)
    async with _AC(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            app.state.broker_bridge = fake_bridge
            raw = generate_api_key("alice")
            await create_agent(
                agent_id="alice",
                display_name="alice",
                capabilities=["oneshot.message"],
                api_key_hash=hash_api_key(raw),
                cert_pem="-----X-----",
            )
            r = await cli.post(
                "/v1/egress/resolve",
                headers={"X-API-Key": raw},
                json={"recipient_id": "other::bob"},
            )
    assert r.status_code == 502
    assert "peer public key" in r.text.lower()
    get_settings.cache_clear()
