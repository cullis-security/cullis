"""ADR-032 Layer 2 R2 — SDK egress header injection.

Pins the contract that ``proxy_headers()`` carries:

* ``X-Cullis-Session-Token`` + ``X-Cullis-On-Behalf-Of-User`` after
  :meth:`CullisClient.attach_user_session` (R1 wire-up, finalised here).
* ``X-Cullis-Device-Attestation`` after
  :meth:`CullisClient.attach_device_attestation` (R2 new). Encoded as
  ``base64url(JSON.dumps(claim, separators=(',', ':')))`` without
  trailing ``=`` per ``imp/attestation-claim-schema.md`` sez. 3 +
  memory ``feedback_base64url_nopad``.

R2's job is the wire envelope only — Mastio-side verification of the
attestation claim (effective_tier recompute, manufacturer whitelist,
stale-window enforcement) lands in F5.
"""
from __future__ import annotations

import base64
import json

import pytest

from cullis_sdk import CullisClient


@pytest.fixture
def client():
    c = CullisClient(broker_url="http://test.invalid", verify_tls=False)
    try:
        yield c
    finally:
        c.close()


def test_proxy_headers_returns_baseline_when_nothing_attached(client):
    headers = client.proxy_headers(method="POST", url="http://test/x")
    assert headers["Content-Type"] == "application/json"
    assert "X-Cullis-Session-Token" not in headers
    assert "X-Cullis-On-Behalf-Of-User" not in headers
    assert "X-Cullis-Device-Attestation" not in headers


def test_attach_user_session_injects_two_headers(client):
    client.attach_user_session(
        session_token="sess-abc123",
        principal_id="acme::user::alice",
    )
    headers = client.proxy_headers(method="POST", url="http://test/x")
    assert headers["X-Cullis-Session-Token"] == "sess-abc123"
    assert headers["X-Cullis-On-Behalf-Of-User"] == "acme::user::alice"


def test_attach_user_session_rejects_empty_token(client):
    with pytest.raises(ValueError):
        client.attach_user_session(session_token="", principal_id="acme::user::alice")


def test_attach_user_session_rejects_empty_principal(client):
    with pytest.raises(ValueError):
        client.attach_user_session(session_token="sess-x", principal_id="")


def test_detach_user_session_drops_headers(client):
    client.attach_user_session("sess-abc123", "acme::user::alice")
    client.detach_user_session()
    headers = client.proxy_headers(method="POST", url="http://test/x")
    assert "X-Cullis-Session-Token" not in headers
    assert "X-Cullis-On-Behalf-Of-User" not in headers


def test_detach_user_session_is_idempotent(client):
    client.detach_user_session()  # no-op on fresh client
    client.detach_user_session()  # still a no-op
    assert client.get_user_session() is None


def test_attach_device_attestation_emits_base64url_nopad(client):
    claim = {
        "mdm": "intune",
        "device_id": "61b8d3f4-aef1",
        "compliance": "compliant",
        "hardware": "tpm_2.0",
        "strength": "hw_attested",
        "manufacturer": "Infineon",
        "verified_at": "2026-05-17T08:34:00Z",
        "stale_seconds": 312,
    }
    client.attach_device_attestation(claim)
    headers = client.proxy_headers(method="POST", url="http://test/x")
    encoded = headers["X-Cullis-Device-Attestation"]

    # base64url, no padding.
    assert "=" not in encoded
    assert "+" not in encoded
    assert "/" not in encoded

    # Round-trip the encoding back to the original dict.
    padded = encoded + "=" * (-len(encoded) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    assert decoded == claim


def test_attach_device_attestation_serialises_with_compact_separators(client):
    """Header size is bounded — the JSON must not contain unnecessary
    whitespace. ``imp/attestation-claim-schema.md`` sez. 3 mandates
    ``separators=(',', ':')`` for header-size minimisation (nginx default
    8KB envelope budget)."""
    claim = {"a": 1, "b": [2, 3]}
    client.attach_device_attestation(claim)
    headers = client.proxy_headers(method="POST", url="http://test/x")
    encoded = headers["X-Cullis-Device-Attestation"]
    padded = encoded + "=" * (-len(encoded) % 4)
    raw = base64.urlsafe_b64decode(padded).decode("utf-8")
    assert raw == '{"a":1,"b":[2,3]}'


def test_attach_device_attestation_none_detaches(client):
    client.attach_device_attestation({"mdm": "intune"})
    client.attach_device_attestation(None)
    headers = client.proxy_headers(method="POST", url="http://test/x")
    assert "X-Cullis-Device-Attestation" not in headers


def test_user_session_and_attestation_compose(client):
    """All three headers ride together when both bindings are active."""
    client.attach_user_session("sess-abc", "acme::user::alice")
    client.attach_device_attestation({"mdm": "intune", "compliance": "compliant"})
    headers = client.proxy_headers(method="POST", url="http://test/x")
    assert headers["X-Cullis-Session-Token"] == "sess-abc"
    assert headers["X-Cullis-On-Behalf-Of-User"] == "acme::user::alice"
    assert "X-Cullis-Device-Attestation" in headers


def test_get_user_session_returns_tuple_after_attach(client):
    assert client.get_user_session() is None
    client.attach_user_session("sess-x", "acme::user::bob")
    assert client.get_user_session() == ("sess-x", "acme::user::bob")


def test_get_device_attestation_returns_claim_after_attach(client):
    assert client.get_device_attestation() is None
    claim = {"mdm": None, "compliance": "unknown"}
    client.attach_device_attestation(claim)
    assert client.get_device_attestation() == claim
