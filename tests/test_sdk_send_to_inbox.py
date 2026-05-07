"""SDK ``send_to_inbox`` helper — request shape + auth integration.

The helper wraps the broker's ``POST /v1/inbox/send`` endpoint (ADR-020
Phase 4) and is the canonical SDK path for agent → user / user → user
delivery, distinct from ``send_oneshot`` which encrypts an envelope for
agent ↔ agent E2E.

These tests cover only the SDK layer: the body shape produced by the
helper and its handling of common server responses. End-to-end coverage
of the broker side lives in ``test_user_inbox.py``; the proxy reverse-
proxy forwarding for ``/v1/inbox/*`` is exercised by the live smoke
that drove issue #481.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from cullis_sdk.client import CullisClient


def _client() -> CullisClient:
    """Build a minimally-initialised CullisClient bypassing __init__.

    Mirrors the cls.__new__(cls) factory pattern used by
    ``from_identity_dir`` / ``from_enrollment``. DPoP keys are real
    because ``_authed_request`` builds a DPoP proof on every call.
    """
    from cullis_sdk.auth import generate_dpop_keypair
    inst = CullisClient.__new__(CullisClient)
    inst.base = "http://mastio.test"
    inst.token = "fake-access-token"
    inst._label = "agent::night-reporter"
    inst._http = MagicMock()
    inst._dpop_privkey, inst._dpop_pubkey_jwk = generate_dpop_keypair()
    inst._dpop_nonce = None
    inst.server_role = None
    return inst


def _mock_response(client: CullisClient, *, status_code: int, body: dict | str):
    """Stub ``client._http.request`` to return a fixed response.

    ``raise_for_status`` mirrors httpx's real behaviour so the SDK's
    own raise path is exercised end-to-end.
    """
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = body if isinstance(body, str) else str(body)
    resp.json.return_value = body if isinstance(body, dict) else {}
    resp.headers = {}

    def _raise():
        if status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {status_code}", request=MagicMock(), response=resp,
            )

    resp.raise_for_status = _raise
    client._http.request.return_value = resp
    return resp


def test_send_to_inbox_serialises_dict_body():
    c = _client()
    _mock_response(c, status_code=201, body={
        "msg_id": "m1", "inserted": True, "quadrant": "A2U-intra",
    })
    out = c.send_to_inbox(
        recipient_org_id="orga",
        recipient_principal_type="user",
        recipient_name="claim-officer",
        body={"hello": "world"},
        subject="night report",
    )
    assert out["msg_id"] == "m1"
    assert out["quadrant"] == "A2U-intra"

    # Verify the wire-level request was built correctly.
    call = c._http.request.call_args
    assert call.args[0] == "POST"
    # Default route is mastio-mediated egress prefix.
    assert call.args[1].endswith("/v1/egress/inbox/send")
    payload = call.kwargs["json"]
    assert payload["recipient_org_id"] == "orga"
    assert payload["recipient_principal_type"] == "user"
    assert payload["recipient_name"] == "claim-officer"
    # Dict body becomes JSON string.
    assert payload["body"] == '{"hello": "world"}'
    assert payload["subject"] == "night report"
    # Optional fields omitted when not supplied.
    assert "idempotency_key" not in payload


def test_send_to_inbox_passes_string_body_through():
    c = _client()
    _mock_response(c, status_code=201, body={
        "msg_id": "m2", "inserted": True, "quadrant": "U2U-intra",
    })
    c.send_to_inbox(
        recipient_org_id="orga",
        recipient_principal_type="user",
        recipient_name="claim-manager",
        body="raw text already serialised",
        idempotency_key="claim-2026-0501",
    )
    payload = c._http.request.call_args.kwargs["json"]
    assert payload["body"] == "raw text already serialised"
    assert payload["idempotency_key"] == "claim-2026-0501"


def test_send_to_inbox_403_raises_permission_error():
    c = _client()
    _mock_response(c, status_code=403, body={
        "detail": {"reason": "reach denied", "quadrant": "A2U-cross"},
    })
    with pytest.raises(PermissionError, match="reach"):
        c.send_to_inbox(
            recipient_org_id="orgb",
            recipient_principal_type="user",
            recipient_name="counterparty-liaison",
            body={"x": 1},
        )


def test_send_to_inbox_500_raises_http_status_error():
    c = _client()
    _mock_response(c, status_code=500, body={"detail": "boom"})
    with pytest.raises(httpx.HTTPStatusError):
        c.send_to_inbox(
            recipient_org_id="orga",
            recipient_principal_type="user",
            recipient_name="claim-officer",
            body={"x": 1},
        )


def test_via_broker_flag_uses_direct_path():
    """When the SDK is run inside the proxy (BrokerBridge sets the flag),
    send_to_inbox calls /v1/inbox/send directly on the broker — no
    /v1/egress/ prefix."""
    c = _client()
    c._inbox_path_via_broker = True
    _mock_response(c, status_code=201, body={
        "msg_id": "m3", "inserted": True, "quadrant": "A2U-intra",
    })
    c.send_to_inbox(
        recipient_org_id="orga",
        recipient_principal_type="user",
        recipient_name="claim-officer",
        body={"x": 1},
    )
    assert c._http.request.call_args.args[1].endswith("/v1/inbox/send")


def test_egress_inbox_router_is_registered():
    """The proxy must mount the new egress/inbox router. Sanity check."""
    from mcp_proxy.egress.inbox import router
    routes = {r.path for r in router.routes}
    assert "/v1/egress/inbox/send" in routes
