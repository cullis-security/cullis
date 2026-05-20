"""ADR-012 Phase 2.1 — ``BrokerBridge.propagate_mastio_key_rotation``.

Unit coverage of the HTTP shim between the Mastio rotation primitive
and the Court endpoint landed in the previous commit. The ``httpx``
client is substituted with a stubbed transport so the test asserts on
the *request shape* (URL, JSON body) and the shim's behaviour on
non-2xx + transport errors — no live Court here. The happy-path
end-to-end test (real Court in-process via ASGITransport) lives
alongside this file.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException

from mcp_proxy.auth.local_keystore import compute_kid
from mcp_proxy.auth.mastio_rotation import build_proof
from mcp_proxy.egress.broker_bridge import BrokerBridge


def _fresh_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


def _bridge(broker_url: str = "http://court.local") -> BrokerBridge:
    # ``agent_manager`` is only consulted by session/client methods; the
    # propagate path does not touch it, so a sentinel ``None`` is fine
    # for these unit tests.
    return BrokerBridge(
        broker_url=broker_url,
        org_id="acme",
        agent_manager=None,  # type: ignore[arg-type]
        verify_tls=False,
    )


def _install_mock_transport(monkeypatch, handler):
    """Substitute ``httpx.AsyncClient`` inside ``broker_bridge`` so
    every ``async with httpx.AsyncClient(...)`` routes through a
    stubbed transport. Uses the *real* ``httpx.AsyncClient`` class
    under a captured reference — the monkeypatch only replaces the
    attribute on the ``broker_bridge.httpx`` namespace, not the
    identity of the underlying class."""
    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def _factory(*_, **kwargs):
        # Drop the real ``verify`` / ``timeout`` kwargs on the floor —
        # MockTransport ignores TLS/timeout anyway — and force our
        # transport so every request is served by ``handler``.
        kwargs.pop("verify", None)
        kwargs.pop("timeout", None)
        return real_async_client(transport=transport, **kwargs)

    import mcp_proxy.egress.broker_bridge as module
    monkeypatch.setattr(module.httpx, "AsyncClient", _factory)


@pytest.mark.asyncio
async def test_propagate_sends_expected_payload_to_court(monkeypatch):
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "org_id": "acme",
                "new_kid": proof.new_kid,
                "rotated_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    _install_mock_transport(monkeypatch, handler)
    bridge = _bridge("http://court.local")

    await bridge.propagate_mastio_key_rotation(
        proof, new_cert_pem="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
    )

    assert len(captured) == 1
    req = captured[0]
    assert req.method == "POST"
    assert str(req.url) == (
        "http://court.local/v1/onboarding/orgs/acme/mastio-pubkey/rotate"
    )
    body = json.loads(req.content)
    assert body["new_pubkey_pem"] == new_pub
    assert body["proof"]["old_kid"] == proof.old_kid
    assert body["proof"]["new_kid"] == proof.new_kid
    assert body["proof"]["signature_b64u"] == proof.signature_b64u
    assert body["new_cert_pem"].startswith("-----BEGIN CERTIFICATE-----")


@pytest.mark.asyncio
async def test_propagate_raises_on_court_4xx(monkeypatch):
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )

    def handler(_request):
        return httpx.Response(
            401,
            json={"detail": "continuity proof rejected: signature verification failed"},
        )

    _install_mock_transport(monkeypatch, handler)
    bridge = _bridge()

    with pytest.raises(HTTPException) as excinfo:
        await bridge.propagate_mastio_key_rotation(proof, new_cert_pem="")
    assert excinfo.value.status_code == 401
    # Audit F-A-306 — detail must NOT echo Court response body.
    # Constant string only; the Court text lives in the WARNING log
    # line for ops triage.
    assert excinfo.value.detail == "court rejected rotation"
    assert "continuity proof rejected" not in excinfo.value.detail
    assert "signature verification failed" not in excinfo.value.detail


@pytest.mark.asyncio
async def test_propagate_wraps_court_5xx_as_502(monkeypatch):
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )

    def handler(_request):
        return httpx.Response(503, text="service unavailable")

    _install_mock_transport(monkeypatch, handler)
    bridge = _bridge()

    with pytest.raises(HTTPException) as excinfo:
        await bridge.propagate_mastio_key_rotation(proof, new_cert_pem="")
    assert excinfo.value.status_code == 502
    # Audit F-A-306 — detail no longer echoes Court 5xx text/status.
    # The 503 status code from Court is in the WARNING log, not the
    # client-facing detail.
    assert excinfo.value.detail == "court rejected rotation"
    assert "service unavailable" not in excinfo.value.detail


@pytest.mark.asyncio
async def test_propagate_wraps_transport_error_as_502(monkeypatch):
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )

    def handler(_request):
        raise httpx.ConnectError("connection refused")

    _install_mock_transport(monkeypatch, handler)
    bridge = _bridge()

    with pytest.raises(HTTPException) as excinfo:
        await bridge.propagate_mastio_key_rotation(proof, new_cert_pem="")
    assert excinfo.value.status_code == 502
    assert "unreachable" in excinfo.value.detail
