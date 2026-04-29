"""Tests for ADR-006 §2.2 extension — SDK session ops route to egress.

Closes Finding #9 from the 2026-04-29 dogfood: with no Court attached,
``client.open_session`` (and the rest of the session API) used to call
``/v1/broker/sessions*``, which the proxy reverse-proxy forwarder
returned 503 for whenever ``broker_url`` was ``None`` (i.e. every
standalone Mastio).

The SDK now flips ``_use_egress_for_sessions`` to True for every
proxy-bound factory (``from_connector``, ``from_enrollment``,
``from_identity_dir``, ``from_api_key_file`` flow) so the same calls
hit ``/v1/egress/sessions*`` — the proxy's local mini-broker handles
intra-org locally and falls through to the broker bridge for cross-
org. Direct-broker clients (``CullisClient(broker_url=…)``) leave the
flag at False so they keep talking to ``/v1/broker``.

These tests verify the path dispatch by mocking the http client and
asserting which URL each method calls. They DO NOT exercise crypto —
``test_proxy_local_sessions.py`` already covers the server-side
end-to-end.
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from cullis_sdk import CullisClient


def _make_client(*, use_egress: bool) -> CullisClient:
    """A CullisClient with crypto + http stubs that just record calls.

    Skips ``__init__`` (matching the factory pattern) and sets only the
    attributes the session methods touch. Tests that need the full
    init path use ``CullisClient.from_*`` directly.
    """
    instance = CullisClient.__new__(CullisClient)
    instance.base = "https://fake-mastio.test:9443"
    instance._verify_tls = True
    instance._http = _RecordingHttp()
    instance.token = None
    instance._label = "test-agent"
    instance._signing_key_pem = None
    instance._pubkey_cache = {}
    instance._client_seq = {}
    instance._dpop_privkey = None
    instance._dpop_pubkey_jwk = None
    instance._dpop_nonce = None
    instance._egress_dpop_key = None
    instance._egress_dpop_nonce = None
    instance.server_role = None
    instance.identity = None
    instance._use_egress_for_sessions = use_egress
    instance._proxy_agent_id = "acme::test-agent"
    instance._proxy_org_id = "acme"
    return instance


class _RecordingHttp:
    """Minimal httpx.Client stand-in: records the URL+method+kwargs of
    each call and returns a 200 with a configurable JSON body."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.responses: dict[str, Any] = {}  # method+path → JSON body
        self.default_body: Any = {"status": "ok"}

    def _resp(self, method: str, url: str, **kwargs) -> httpx.Response:
        self.calls.append((method, url, kwargs))
        body = self.responses.get(f"{method.upper()} {url}", self.default_body)
        return httpx.Response(
            200, json=body, request=httpx.Request(method.upper(), url),
        )

    def get(self, url, **kw): return self._resp("get", url, **kw)
    def post(self, url, **kw): return self._resp("post", url, **kw)
    def put(self, url, **kw): return self._resp("put", url, **kw)
    def delete(self, url, **kw): return self._resp("delete", url, **kw)


@pytest.fixture
def disable_dpop_signing(monkeypatch):
    """The egress path goes through ``proxy_headers`` which would try
    to mint a DPoP proof — short-circuit it to a no-op for these
    routing tests, since we only care about *which URL* gets hit."""
    monkeypatch.setattr(
        CullisClient, "proxy_headers", lambda self, method, url: {},
    )


# ── from_connector wires the flag to True ───────────────────────────


def test_from_connector_sets_egress_routing_flag(tmp_path):
    """The whole point of Finding #9: every Connector identity must
    route session ops through the egress surface."""
    identity = tmp_path / "identity"
    identity.mkdir()
    (identity / "metadata.json").write_text(
        '{"agent_id":"acme::cullis","site_url":"http://fake-mastio.test"}'
    )
    client = CullisClient.from_connector(tmp_path, verify_tls=False)
    assert client._use_egress_for_sessions is True


def test_default_constructor_keeps_broker_routing():
    """Direct-broker clients (no proxy) MUST keep talking to
    /v1/broker/sessions — they have no proxy in front of them so the
    egress paths don't exist on the wire."""
    client = CullisClient(broker_url="https://broker.test", verify_tls=False)
    assert client._use_egress_for_sessions is False


# ── Egress path dispatch ─────────────────────────────────────────────


def test_open_session_via_egress_uses_capabilities_field(disable_dpop_signing):
    client = _make_client(use_egress=True)
    client._http.responses["POST https://fake-mastio.test:9443/v1/egress/sessions"] = {
        "session_id": "abc-123", "status": "opened",
    }
    sid = client.open_session("acme::peer", "acme", ["cap.read"])
    assert sid == "abc-123"
    method, url, kwargs = client._http.calls[-1]
    assert method == "post"
    assert url.endswith("/v1/egress/sessions")
    body = kwargs["json"]
    assert body == {
        "target_agent_id": "acme::peer",
        "target_org_id": "acme",
        # Egress uses ``capabilities``, NOT ``requested_capabilities``.
        "capabilities": ["cap.read"],
    }


def test_accept_session_via_egress(disable_dpop_signing):
    client = _make_client(use_egress=True)
    client.accept_session("abc-123")
    method, url, _ = client._http.calls[-1]
    assert method == "post"
    assert url.endswith("/v1/egress/sessions/abc-123/accept")


def test_close_session_via_egress(disable_dpop_signing):
    client = _make_client(use_egress=True)
    client.close_session("abc-123")
    method, url, _ = client._http.calls[-1]
    assert method == "post"
    assert url.endswith("/v1/egress/sessions/abc-123/close")


def test_reject_session_via_egress_folds_into_close(disable_dpop_signing):
    """Egress has no /reject endpoint — the SDK folds reject → close so
    the local store treats both terminal states equivalently."""
    client = _make_client(use_egress=True)
    client.reject_session("abc-123")
    method, url, _ = client._http.calls[-1]
    assert method == "post"
    assert url.endswith("/v1/egress/sessions/abc-123/close")


def test_list_sessions_via_egress_unwraps_payload(disable_dpop_signing):
    client = _make_client(use_egress=True)
    client._http.responses["GET https://fake-mastio.test:9443/v1/egress/sessions"] = {
        "sessions": [
            {"session_id": "s1", "status": "active",
             "initiator_agent_id": "acme::a", "target_agent_id": "acme::b",
             "capabilities": []},
        ],
    }
    sessions = client.list_sessions(status="active")
    assert len(sessions) == 1
    assert sessions[0].session_id == "s1"
    method, url, kwargs = client._http.calls[-1]
    assert method == "get"
    assert url.endswith("/v1/egress/sessions")
    assert kwargs["params"] == {"status": "active"}


def test_ack_message_via_egress(disable_dpop_signing):
    """``ack_message`` on a proxy-bound client must use the egress
    sessions/{id}/messages/{msg}/ack path (the same one
    ``ack_via_proxy`` already used)."""
    client = _make_client(use_egress=True)
    # The egress ack returns 204; we patch the response shape.
    def _post(url, **kw):
        client._http.calls.append(("post", url, kw))
        return httpx.Response(
            204, request=httpx.Request("POST", url),
        )
    client._http.post = _post
    ok = client.ack_message("abc-123", "msg-1")
    assert ok is True
    method, url, _ = client._http.calls[-1]
    assert url.endswith("/v1/egress/sessions/abc-123/messages/msg-1/ack")


# ── Broker path dispatch (regression guard for direct-broker SDKs) ──


def test_open_session_direct_broker_uses_requested_capabilities():
    """Pre-existing direct-broker SDKs MUST keep using the broker path
    and the historical ``requested_capabilities`` field name. The flag
    defaults to False so this is the default behaviour."""
    client = _make_client(use_egress=False)
    client._http.responses["POST https://fake-mastio.test:9443/v1/broker/sessions"] = {
        "session_id": "abc-123", "status": "pending",
    }
    # Patch _authed_request because direct-broker uses it (DPoP/token).
    captured: dict = {}

    def _fake_authed(method, path, **kw):
        captured["method"] = method
        captured["path"] = path
        captured["kwargs"] = kw
        return httpx.Response(
            200, json={"session_id": "abc-123", "status": "pending"},
            request=httpx.Request(method, path),
        )

    client._authed_request = _fake_authed  # type: ignore[method-assign]
    client.open_session("acme::peer", "acme", ["cap.read"])
    assert captured["path"] == "/v1/broker/sessions"
    body = captured["kwargs"]["json"]
    assert body == {
        "target_agent_id": "acme::peer",
        "target_org_id": "acme",
        "requested_capabilities": ["cap.read"],
    }


# ── Egress poll body unwrap ─────────────────────────────────────────


def test_unwrap_egress_message_envelope_to_broker_shape():
    """The egress GET /messages serialises the cipher dict to JSON
    under ``payload_ciphertext`` — ``decrypt_payload`` expects it as a
    dict under ``payload``. The unwrap helper must bridge them."""
    egress_row = {
        "msg_id": "m1",
        "session_id": "s1",
        "sender_agent_id": "acme::a",
        "mode": "envelope",
        "payload_ciphertext": '{"ciphertext":"abc","encrypted_key":"def","iv":"xyz"}',
    }
    out = CullisClient._unwrap_egress_message(egress_row, "s1")
    assert out["payload"] == {"ciphertext": "abc", "encrypted_key": "def", "iv": "xyz"}
    assert "payload_ciphertext" not in out


def test_unwrap_egress_message_passes_mtls_only_through():
    """mtls-only rows already carry ``payload`` as a dict — unwrap
    must not touch them or crypto verifier downstream gets nothing
    to decrypt against."""
    row = {
        "msg_id": "m1",
        "session_id": "s1",
        "sender_agent_id": "acme::a",
        "mode": "mtls-only",
        "payload": {"text": "hi"},
        "signature": "sig",
        "nonce": "n",
        "timestamp": 1,
    }
    out = CullisClient._unwrap_egress_message(row, "s1")
    assert out["payload"] == {"text": "hi"}
    assert out["signature"] == "sig"


def test_unwrap_egress_message_fills_in_session_id_when_missing():
    """Some egress rows omit session_id; the SDK already knows it
    (the caller passed it to ``poll``), so backfill it on the unwrap
    path so ``decrypt_payload`` never sees ``session_id=''``."""
    row = {"msg_id": "m1", "sender_agent_id": "x", "mode": "envelope"}
    out = CullisClient._unwrap_egress_message(row, "s1-fallback")
    assert out["session_id"] == "s1-fallback"
