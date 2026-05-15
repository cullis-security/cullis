"""ADR-016 Phase 3 — send_oneshot wires inspect_before_send.

Tests stub ``CullisClient._egress_http`` to capture every endpoint the
SDK hits, so we can assert (a) the order of POSTs matches the wire
contract (resolve → guardian/inspect → message/send), (b) the guardian
hook is skipped entirely when CULLIS_GUARDIAN_ENABLED is off, and (c)
``decision=block`` short-circuits BEFORE the message is sent.
"""
from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest

from cullis_sdk.client import CullisClient
from cullis_sdk.guardian import GuardianBlocked


_DUMMY_REQUEST = httpx.Request("POST", "http://test")


def _resolve_response() -> httpx.Response:
    return httpx.Response(200, request=_DUMMY_REQUEST, json={
        "transport": "mtls-only",
        "target_org_id": "orgb",
        "target_agent_id": "bob",
        "target_cert_pem": None,
    })


def _send_response() -> httpx.Response:
    return httpx.Response(200, request=_DUMMY_REQUEST, json={
        "correlation_id": "corr-1",
        "msg_id": "msg-1",
        "status": "enqueued",
    })


def _guardian_response(
    *, decision: str = "pass", redacted_b64: str | None = None,
    audit_id: str = "aud-1", ticket: str = "fake-jwt",
) -> httpx.Response:
    return httpx.Response(200, request=_DUMMY_REQUEST, json={
        "decision": decision,
        "ticket": ticket,
        "ticket_exp": int(time.time()) + 30,
        "audit_id": audit_id,
        "redacted_payload_b64": redacted_b64,
        "reasons": [{"tool": "stub", "match": "x"}] if decision != "pass" else [],
    })


class _StubEgressHTTP:
    """Captures every (method, path, body) and replies from ``replies``."""

    def __init__(self, replies: dict[str, httpx.Response]):
        self.replies = replies
        self.calls: list[dict[str, Any]] = []

    def __call__(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        self.calls.append({
            "method": method, "path": path, "json": kwargs.get("json"),
        })
        if path not in self.replies:
            raise AssertionError(f"unexpected path: {path}")
        return self.replies[path]


def _client_with_stub(stub: _StubEgressHTTP) -> CullisClient:
    c = CullisClient("http://test", verify_tls=False)
    c._signing_key_pem = (
        # cryptography accepts this minimal RSA key for sign() in tests; the
        # tests don't verify the signature, only that send_oneshot reaches
        # the wire stage. We patch sign_message + sign_oneshot_envelope so
        # the actual signing is a no-op.
        "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN..."
    )
    c._proxy_agent_id = "orga::alice"
    c._egress_http = stub  # type: ignore[assignment]
    return c


@pytest.fixture(autouse=True)
def _stub_signing(monkeypatch):
    """Stub the cryptographic primitives so the wire stage runs without
    a real key. The Guardian wiring sits BEFORE these calls; what we
    care about is who got called and in what order, not the signature
    bytes themselves."""
    monkeypatch.setattr(
        "cullis_sdk._client._messaging_oneshot.sign_message",
        lambda *a, **kw: "fake-inner-sig",
    )
    monkeypatch.setattr(
        "cullis_sdk._client._messaging_oneshot.sign_oneshot_envelope",
        lambda *a, **kw: "fake-outer-sig",
    )


def test_send_oneshot_no_op_when_guardian_disabled(monkeypatch):
    """With CULLIS_GUARDIAN_ENABLED=0 the SDK never hits the guardian
    endpoint — only resolve + message/send. Existing deployments must
    see zero new traffic until they opt in."""
    monkeypatch.delenv("CULLIS_GUARDIAN_ENABLED", raising=False)

    stub = _StubEgressHTTP({
        "/v1/egress/resolve": _resolve_response(),
        "/v1/egress/message/send": _send_response(),
    })
    c = _client_with_stub(stub)

    result = c.send_oneshot("orgb::bob", {"hello": "world"})

    assert result["status"] == "enqueued"
    paths = [call["path"] for call in stub.calls]
    assert "/v1/guardian/inspect" not in paths
    assert paths == ["/v1/egress/resolve", "/v1/egress/message/send"]


def test_send_oneshot_inspects_when_guardian_enabled(monkeypatch):
    """With CULLIS_GUARDIAN_ENABLED=1 the SDK calls the guardian
    endpoint between resolve and send, and the guardian body carries
    direction=out + the canonical payload."""
    monkeypatch.setenv("CULLIS_GUARDIAN_ENABLED", "1")

    stub = _StubEgressHTTP({
        "/v1/egress/resolve": _resolve_response(),
        "/v1/guardian/inspect": _guardian_response(decision="pass"),
        "/v1/egress/message/send": _send_response(),
    })
    c = _client_with_stub(stub)

    c.send_oneshot("orgb::bob", {"hello": "world"})

    paths = [call["path"] for call in stub.calls]
    assert paths == [
        "/v1/egress/resolve",
        "/v1/guardian/inspect",
        "/v1/egress/message/send",
    ]
    inspect_body = stub.calls[1]["json"]
    assert inspect_body["direction"] == "out"
    assert inspect_body["peer_agent_id"] == "orgb::bob"
    assert inspect_body["msg_id"]
    assert inspect_body["payload_b64"]


def test_send_oneshot_block_short_circuits_before_send(monkeypatch):
    """A guardian decision=block raises GuardianBlocked, and message/send
    is NEVER reached. The cost of the blocked send is one guardian call,
    not a full encrypt + DPoP round-trip."""
    monkeypatch.setenv("CULLIS_GUARDIAN_ENABLED", "1")

    stub = _StubEgressHTTP({
        "/v1/egress/resolve": _resolve_response(),
        "/v1/guardian/inspect": _guardian_response(
            decision="block", audit_id="aud-block-99",
        ),
        # message/send intentionally omitted — must not be called.
    })
    c = _client_with_stub(stub)

    with pytest.raises(GuardianBlocked) as exc:
        c.send_oneshot("orgb::bob", {"secret": "AKIA…"})

    assert exc.value.audit_id == "aud-block-99"
    assert exc.value.direction == "out"
    paths = [call["path"] for call in stub.calls]
    assert "/v1/egress/message/send" not in paths


def test_send_oneshot_redact_substitutes_payload_before_signing(monkeypatch):
    """When guardian returns decision=redact + redacted_payload_b64, the
    SDK signs + encrypts the REDACTED form. We assert the wire body
    sent to message/send carries the redacted payload, not the
    original."""
    import base64

    monkeypatch.setenv("CULLIS_GUARDIAN_ENABLED", "1")

    redacted = {"card": "[REDACTED]"}
    redacted_bytes = json.dumps(
        redacted, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    redacted_b64 = base64.urlsafe_b64encode(redacted_bytes).rstrip(b"=").decode()

    stub = _StubEgressHTTP({
        "/v1/egress/resolve": _resolve_response(),
        "/v1/guardian/inspect": _guardian_response(
            decision="redact", redacted_b64=redacted_b64,
        ),
        "/v1/egress/message/send": _send_response(),
    })
    c = _client_with_stub(stub)

    c.send_oneshot("orgb::bob", {"card": "4242 4242 4242 4242"})

    send_body = stub.calls[-1]["json"]
    # The wire body's "payload" field is the redacted version.
    assert send_body["payload"] == {"card": "[REDACTED]"}


def test_send_oneshot_msg_id_consistent_with_correlation_id(monkeypatch):
    """The Guardian msg_id ties to the message correlation_id end-to-end
    so audit rows + the receiver's ticket verification can correlate.
    A caller-supplied correlation_id flows into the inspect body."""
    monkeypatch.setenv("CULLIS_GUARDIAN_ENABLED", "1")

    stub = _StubEgressHTTP({
        "/v1/egress/resolve": _resolve_response(),
        "/v1/guardian/inspect": _guardian_response(decision="pass"),
        "/v1/egress/message/send": _send_response(),
    })
    c = _client_with_stub(stub)

    explicit_corr = "explicit-correlation-id-abc"
    c.send_oneshot(
        "orgb::bob", {"hello": "x"}, correlation_id=explicit_corr,
    )

    inspect_body = stub.calls[1]["json"]
    send_body = stub.calls[2]["json"]
    assert inspect_body["msg_id"] == explicit_corr
    assert send_body["correlation_id"] == explicit_corr
