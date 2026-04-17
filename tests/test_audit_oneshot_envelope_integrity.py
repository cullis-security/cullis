"""Regression tests for audit findings F-A-1 and F-A-3 (EUDI-class).

F-A-1: ``decrypt_oneshot`` used to default ``mode`` to ``"mtls-only"``
and return the attacker-controlled ``envelope["payload"]`` verbatim
with ``sender_verified=False``. Callers of ``send_oneshot_and_wait``
never checked the flag, so a broker or DB-adjacent attacker could
downgrade a legitimate envelope-mode message to ``mtls-only`` with
arbitrary plaintext.

F-A-3: The broker's outer signature covered only ``body.payload``.
Every other field the broker persisted (``mode``, ``signature`` slot,
``nonce``, ``timestamp``, ``correlation_id``, ``reply_to``) lived
outside the signed region, so a broker-side actor could rewrite any of
them undetected.

v2 fix: outer signature now covers the full envelope and verification
is unconditional on the recipient side. v1 envelopes are hard-rejected.
"""
from __future__ import annotations

import json
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from httpx import AsyncClient

from cullis_sdk.client import CullisClient
from cullis_sdk.crypto.e2e import encrypt_for_agent
from cullis_sdk.crypto.message_signer import (
    ONESHOT_ENVELOPE_PROTO_VERSION,
    sign_message,
    sign_oneshot_envelope,
)
from tests.cert_factory import (
    DPoPHelper,
    get_agent_key_pem,
    get_agent_pubkey_pem,
    make_agent_cert,
)

# Reuse the broker test helpers (register + login, PDP mock autouse).
from tests.test_oneshot_cross import (
    _mock_oneshot_pdp,  # noqa: F401 — autouse fixture re-exported for patch scope
    _register_and_login,
)


pytestmark = pytest.mark.asyncio


# ── Shared helpers ────────────────────────────────────────────────────


def _alice_cert_pem(agent_id: str = "audit1::alice", org_id: str = "audit1") -> str:
    _, cert = make_agent_cert(agent_id, org_id)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _seed_client(
    sender_agent_id: str,
    sender_org_id: str,
    *,
    recipient_priv_pem: str | None = None,
) -> CullisClient:
    """Build an SDK client with its pubkey cache pre-seeded for the sender."""
    sender_cert_pem = _alice_cert_pem(sender_agent_id, sender_org_id)
    client = CullisClient("http://test", verify_tls=False)
    if recipient_priv_pem is not None:
        client._signing_key_pem = recipient_priv_pem
    client._pubkey_cache[sender_agent_id] = (sender_cert_pem, time.time())
    return client


def _mtls_envelope(
    *,
    sender_agent_id: str,
    sender_org_id: str,
    correlation_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
    reply_to: str | None = None,
) -> dict:
    """Build a v2 mtls-only envelope signed correctly."""
    sender_priv = get_agent_key_pem(sender_agent_id, sender_org_id)
    sig = sign_oneshot_envelope(
        sender_priv,
        correlation_id=correlation_id,
        sender_agent_id=sender_agent_id,
        nonce=nonce,
        timestamp=timestamp,
        mode="mtls-only",
        reply_to=reply_to,
        payload=payload,
    )
    return {
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
        "mode": "mtls-only",
        "payload": payload,
        "signature": sig,
        "nonce": nonce,
        "timestamp": timestamp,
        "correlation_id": correlation_id,
        "reply_to": reply_to,
    }


def _envelope_envelope(
    *,
    sender_agent_id: str,
    sender_org_id: str,
    recipient_pubkey_pem: str,
    correlation_id: str,
    nonce: str,
    timestamp: int,
    payload: dict,
    reply_to: str | None = None,
) -> tuple[dict, dict]:
    """Build a v2 envelope-mode envelope (returns the dict envelope + plaintext)."""
    sender_priv = get_agent_key_pem(sender_agent_id, sender_org_id)
    inner_sig = sign_message(
        sender_priv,
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
        sender_priv,
        correlation_id=correlation_id,
        sender_agent_id=sender_agent_id,
        nonce=nonce,
        timestamp=timestamp,
        mode="envelope",
        reply_to=reply_to,
        payload=cipher_blob,
    )
    return ({
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
        "mode": "envelope",
        "payload": cipher_blob,
        "signature": outer_sig,
        "nonce": nonce,
        "timestamp": timestamp,
        "correlation_id": correlation_id,
        "reply_to": reply_to,
    }, payload)


def _inbox_row(envelope: dict, *, sender_agent_id: str) -> dict:
    return {
        "msg_id": str(uuid.uuid4()),
        "correlation_id": envelope["correlation_id"],
        "reply_to": envelope.get("reply_to"),
        "sender_agent_id": sender_agent_id,
        "payload_ciphertext": json.dumps(envelope, separators=(",", ":"), sort_keys=True),
        "idempotency_key": f"oneshot:{envelope['correlation_id']}",
        "enqueued_at": "2026-04-17T00:00:00+00:00",
        "expires_at": None,
    }


# ── F-A-1: attacker-rewritten mtls-only with no signature ─────────────


async def test_decrypt_rejects_unsigned_mtls_only_envelope():
    """Attacker replaces a legit envelope-mode row with ``mode=mtls-only``
    + arbitrary plaintext and no (or invalid) signature. Must raise.
    """
    sender = "audit1::alice"
    client = _seed_client(sender, "audit1")

    attacker_envelope = {
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
        "mode": "mtls-only",
        "payload": {"attacker_wrote": "wire-transfer EUR 1,000,000"},
        # No signature at all — simulates the exact F-A-1 exploit.
        "signature": "",
        "nonce": str(uuid.uuid4()),
        "timestamp": int(time.time()),
        "correlation_id": str(uuid.uuid4()),
        "reply_to": None,
    }
    row = _inbox_row(attacker_envelope, sender_agent_id=sender)

    with pytest.raises(ValueError):
        client.decrypt_oneshot(row)
    client.close()


async def test_decrypt_rejects_missing_mode_envelope():
    """Audit F-A-1 direct hit: v1 SDK defaulted to ``mtls-only`` when
    ``mode`` was absent. v2 must reject.
    """
    sender = "audit1b::alice"
    client = _seed_client(sender, "audit1b")

    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    # Build a valid envelope then strip the mode field.
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="audit1b",
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"ok": True},
    )
    env.pop("mode")
    row = _inbox_row({**env, "mode": "__missing__", "correlation_id": corr}, sender_agent_id=sender)
    # Strip the artificial field for the real inbox payload
    env_json = json.dumps({k: v for k, v in env.items()}, separators=(",", ":"), sort_keys=True)
    row["payload_ciphertext"] = env_json

    with pytest.raises(ValueError):
        client.decrypt_oneshot(row)
    client.close()


async def test_decrypt_rejects_v1_envelope_protocol_version():
    """v1 envelopes (pre-fix) are hard-rejected."""
    sender = "audit1c::alice"
    client = _seed_client(sender, "audit1c")

    corr = str(uuid.uuid4())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="audit1c",
        correlation_id=corr, nonce=str(uuid.uuid4()),
        timestamp=int(time.time()),
        payload={"ok": True},
    )
    env.pop("v")  # v1 had no v field
    row = _inbox_row(env, sender_agent_id=sender)

    with pytest.raises(ValueError, match="envelope version"):
        client.decrypt_oneshot(row)
    client.close()


# ── F-A-3: broker-side tamper of envelope fields ──────────────────────


async def test_decrypt_rejects_flipped_mode():
    """Attacker flips ``mode`` from ``envelope`` → ``mtls-only`` while
    leaving the outer signature untouched. v2 covers ``mode`` in the
    signed canonical form, so verification must fail.
    """
    sender = "audit2::alice"
    recipient_org = "audit2r"
    recipient = f"{recipient_org}::bob"
    # Build a valid envelope-mode message.
    recipient_pubkey = get_agent_pubkey_pem(recipient, recipient_org)
    client = _seed_client(
        sender, "audit2",
        recipient_priv_pem=get_agent_key_pem(recipient, recipient_org),
    )

    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    env, _ = _envelope_envelope(
        sender_agent_id=sender, sender_org_id="audit2",
        recipient_pubkey_pem=recipient_pubkey,
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"secret": "legit plaintext"},
    )
    # Broker-side tamper: flip mode to downgrade.
    tampered = {**env, "mode": "mtls-only"}
    row = _inbox_row(tampered, sender_agent_id=sender)

    with pytest.raises(ValueError, match="signature"):
        client.decrypt_oneshot(row)
    client.close()


async def test_decrypt_rejects_flipped_correlation_id():
    sender = "audit3::alice"
    client = _seed_client(sender, "audit3")

    corr_real = str(uuid.uuid4())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="audit3",
        correlation_id=corr_real,
        nonce=str(uuid.uuid4()), timestamp=int(time.time()),
        payload={"msg": "legit"},
    )
    # Row corr matches, envelope corr flipped → mismatch detected OR
    # signature detected. Either way, must raise.
    env_tampered = {**env, "correlation_id": str(uuid.uuid4())}
    row = _inbox_row(env_tampered, sender_agent_id=sender)
    row["correlation_id"] = corr_real  # outer row still claims real corr

    with pytest.raises(ValueError):
        client.decrypt_oneshot(row)
    client.close()


async def test_decrypt_rejects_flipped_reply_to():
    sender = "audit4::alice"
    client = _seed_client(sender, "audit4")

    corr = str(uuid.uuid4())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="audit4",
        correlation_id=corr,
        nonce=str(uuid.uuid4()), timestamp=int(time.time()),
        payload={"msg": "legit"},
        reply_to=None,
    )
    # Broker-side tamper: inject a reply_to so a response is mis-linked.
    env_tampered = {**env, "reply_to": str(uuid.uuid4())}
    row = _inbox_row(env_tampered, sender_agent_id=sender)

    with pytest.raises(ValueError, match="signature"):
        client.decrypt_oneshot(row)
    client.close()


async def test_decrypt_rejects_flipped_timestamp():
    sender = "audit5::alice"
    client = _seed_client(sender, "audit5")

    corr = str(uuid.uuid4())
    ts = int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="audit5",
        correlation_id=corr,
        nonce=str(uuid.uuid4()), timestamp=ts,
        payload={"msg": "legit"},
    )
    env_tampered = {**env, "timestamp": ts - 86400}
    row = _inbox_row(env_tampered, sender_agent_id=sender)

    with pytest.raises(ValueError, match="signature"):
        client.decrypt_oneshot(row)
    client.close()


async def test_decrypt_rejects_flipped_nonce():
    sender = "audit6::alice"
    client = _seed_client(sender, "audit6")

    corr = str(uuid.uuid4())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="audit6",
        correlation_id=corr,
        nonce=str(uuid.uuid4()), timestamp=int(time.time()),
        payload={"msg": "legit"},
    )
    env_tampered = {**env, "nonce": str(uuid.uuid4())}
    row = _inbox_row(env_tampered, sender_agent_id=sender)

    with pytest.raises(ValueError, match="signature"):
        client.decrypt_oneshot(row)
    client.close()


async def test_decrypt_rejects_flipped_payload():
    sender = "audit7::alice"
    client = _seed_client(sender, "audit7")

    corr = str(uuid.uuid4())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="audit7",
        correlation_id=corr,
        nonce=str(uuid.uuid4()), timestamp=int(time.time()),
        payload={"amount": 100},
    )
    env_tampered = {**env, "payload": {"amount": 1_000_000}}
    row = _inbox_row(env_tampered, sender_agent_id=sender)

    with pytest.raises(ValueError, match="signature"):
        client.decrypt_oneshot(row)
    client.close()


# ── Positive round-trip under v2 ──────────────────────────────────────


async def test_decrypt_accepts_valid_v2_mtls_envelope():
    sender = "audit8::alice"
    client = _seed_client(sender, "audit8")

    corr = str(uuid.uuid4())
    payload = {"greeting": "hello"}
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="audit8",
        correlation_id=corr,
        nonce=str(uuid.uuid4()), timestamp=int(time.time()),
        payload=payload,
    )
    row = _inbox_row(env, sender_agent_id=sender)

    decoded = client.decrypt_oneshot(row)
    assert decoded["mode"] == "mtls-only"
    assert decoded["sender_verified"] is True
    assert decoded["payload"] == payload
    client.close()


# ── F-A-3 broker-side: broker now verifies v2 envelope sig ────────────


async def test_broker_rejects_flipped_mode_post_v2(client: AsyncClient):
    """At broker ingest, a body where ``mode`` disagrees with what the
    sender signed must 401 (the canonical form includes mode).
    """
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "audit9::alice", "audit9")
    await _register_and_login(client, dpop_b, "audit9r::bob", "audit9r")

    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("audit9::alice", "audit9")
    payload = {"msg": "legit"}

    # Sender signs mtls-only, attacker/proxy flips body.mode to envelope.
    sig = sign_oneshot_envelope(
        alice_priv,
        correlation_id=corr, sender_agent_id="audit9::alice",
        nonce=nonce, timestamp=ts,
        mode="mtls-only", reply_to=None, payload=payload,
    )
    body = {
        "recipient_agent_id": "audit9r::bob",
        "correlation_id": corr,
        "reply_to_correlation_id": None,
        "payload": payload,
        "signature": sig,
        "nonce": nonce,
        "timestamp": ts,
        "mode": "envelope",  # tampered
        "ttl_seconds": 300,
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
    }
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 401


async def test_broker_rejects_flipped_reply_to_post_v2(client: AsyncClient):
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "audit10::alice", "audit10")
    await _register_and_login(client, dpop_b, "audit10r::bob", "audit10r")

    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("audit10::alice", "audit10")
    payload = {"msg": "legit"}

    sig = sign_oneshot_envelope(
        alice_priv,
        correlation_id=corr, sender_agent_id="audit10::alice",
        nonce=nonce, timestamp=ts,
        mode="mtls-only", reply_to=None, payload=payload,
    )
    body = {
        "recipient_agent_id": "audit10r::bob",
        "correlation_id": corr,
        "reply_to_correlation_id": str(uuid.uuid4()),  # tampered
        "payload": payload,
        "signature": sig,
        "nonce": nonce,
        "timestamp": ts,
        "mode": "mtls-only",
        "ttl_seconds": 300,
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
    }
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 401


async def test_broker_rejects_v1_envelope_protocol(client: AsyncClient):
    """A sender still speaking v1 (no ``v`` field or v=1) must be
    hard-rejected so we never silently accept a downgraded envelope.
    """
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(client, dpop_a, "audit11::alice", "audit11")
    await _register_and_login(client, dpop_b, "audit11r::bob", "audit11r")

    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    alice_priv = get_agent_key_pem("audit11::alice", "audit11")
    payload = {"msg": "legit"}

    # v1 payload-only signature (old form) — server must not accept.
    sig = sign_message(
        alice_priv, f"oneshot:{corr}", "audit11::alice",
        nonce, ts, payload, client_seq=0,
    )
    body = {
        "recipient_agent_id": "audit11r::bob",
        "correlation_id": corr,
        "reply_to_correlation_id": None,
        "payload": payload,
        "signature": sig,
        "nonce": nonce,
        "timestamp": ts,
        "mode": "mtls-only",
        "ttl_seconds": 300,
        "v": 1,
    }
    r = await client.post(
        "/v1/broker/oneshot/forward", json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code in (400, 401)


# ── send_oneshot_and_wait: verified-only ──────────────────────────────


async def test_send_oneshot_and_wait_raises_on_unverified():
    """Even if a pathological reply slipped through, the helper must not
    return unauthenticated plaintext (F-A-1 callsite). We exercise this
    by monkey-patching ``decrypt_oneshot`` to return ``sender_verified=False``
    and asserting the helper refuses.
    """
    from unittest.mock import MagicMock

    alice_priv = get_agent_key_pem("audit12::alice", "audit12")
    bob_pubkey = get_agent_pubkey_pem("audit12r::bob", "audit12r")

    alice = CullisClient("http://mock-proxy", verify_tls=False)
    alice._signing_key_pem = alice_priv
    alice._proxy_api_key = "fake-api-key"
    alice._proxy_agent_id = "audit12::alice"

    # The helper's receive_oneshot loop looks for reply_to==corr.
    captured_corr: dict = {}

    def _fake_post(url: str, *args, **kwargs):
        body = kwargs.get("json", {})
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.headers = {}
        if url.endswith("/v1/egress/resolve"):
            resp.json.return_value = {
                "path": "cross-org",
                "target_agent_id": "audit12r::bob",
                "target_org_id": "audit12r",
                "target_spiffe": None,
                "transport": "envelope",
                "egress_inspection": False,
                "target_cert_pem": bob_pubkey,
            }
            return resp
        if url.endswith("/v1/egress/message/send"):
            captured_corr["corr"] = body["correlation_id"]
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
        if url.endswith("/v1/egress/message/inbox"):
            corr = captured_corr.get("corr", "")
            row_env = {
                "v": ONESHOT_ENVELOPE_PROTO_VERSION,
                "mode": "mtls-only",
                "payload": {"a": 1},
                "signature": "stub",
                "nonce": "n",
                "timestamp": 0,
                "correlation_id": "reply-corr",
                "reply_to": corr,
            }
            resp.json.return_value = {
                "messages": [{
                    "msg_id": str(uuid.uuid4()),
                    "correlation_id": "reply-corr",
                    "reply_to": corr,
                    "sender_agent_id": "audit12r::bob",
                    "payload_ciphertext": json.dumps(row_env, separators=(",", ":"), sort_keys=True),
                    "idempotency_key": "oneshot:x",
                    "enqueued_at": "2026-04-17T00:00:00+00:00",
                    "expires_at": None,
                }],
                "count": 1,
            }
            return resp
        raise AssertionError(url)

    alice._http = MagicMock()
    alice._http.post.side_effect = _fake_post
    alice._http.get.side_effect = _fake_get

    # Patch decrypt_oneshot to return unverified — simulates a belt-and-
    # braces regression of the old behavior. The helper must refuse.
    alice.decrypt_oneshot = MagicMock(return_value={
        "payload": {"a": 1},
        "sender_verified": False,
        "mode": "mtls-only",
    })

    with pytest.raises(ValueError, match="could not be verified"):
        alice.send_oneshot_and_wait(
            "audit12r::bob", {"q": "?"},
            timeout=2.0, poll_interval=0.1,
        )
