"""HMAC signing + verification on the PDP webhook channel.

Audit 2026-04-30 lane 3 H3 — the broker → Mastio /pdp/policy call was
unauthenticated, letting any host that could reach the proxy on the
PDP plane probe ``policy_rules`` via differential responses and inject
log lines via attacker-controlled ``initiator``/``target``/``context``
strings.

This test file pins both sides of the contract:
  * broker side (``call_pdp_webhook``) attaches X-ATN-Signature when
    ``policy_webhook_hmac_secret`` is set,
  * proxy side (``/pdp/policy``) verifies it when
    ``MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET`` is set, fail-closed on
    mismatch / missing.

When the secret is unset on either side the legacy unsigned path is
preserved so deployments mid-rollout don't break — the audit finding
is still partly mitigated because the receiver gets to enforce as
soon as the operator configures it.
"""
from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


# ── Broker-side: outbound signing ───────────────────────────────────


@pytest.mark.asyncio
async def test_call_pdp_webhook_signs_when_secret_set(monkeypatch):
    """When ``policy_webhook_hmac_secret`` is set the outbound call
    carries ``X-ATN-Signature: hex(hmac_sha256(secret, body))``
    and the body bytes match the signed bytes."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "shared-secret-xyz")
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = bytes(request.content)
        return httpx.Response(200, json={"decision": "allow"})

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    decision = await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url="https://example.com/pdp",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
    )

    assert decision.allowed is True
    assert "x-atn-signature" in captured["headers"]
    expected = hmac.new(
        b"shared-secret-xyz", captured["body"], hashlib.sha256,
    ).hexdigest()
    assert captured["headers"]["x-atn-signature"] == expected
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_call_pdp_webhook_unsigned_when_secret_unset(monkeypatch):
    """Legacy backward-compat: when the secret is empty, no signature
    header is attached (operators mid-rollout)."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "")
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    captured: dict = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"decision": "allow"})

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url="https://example.com/pdp",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=[],
        session_context="initiator",
    )

    assert "x-atn-signature" not in captured["headers"]
    get_settings.cache_clear()


# ── Proxy-side: inbound verification ────────────────────────────────


@pytest_asyncio.fixture
async def proxy_app_signed(tmp_path, monkeypatch):
    """Proxy app booted with ``MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET`` set."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", "shared-secret-xyz")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import importlib
    import mcp_proxy.main as main_mod
    importlib.reload(main_mod)
    app = main_mod.app

    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client

    get_settings.cache_clear()


def _sign(body: bytes, secret: str = "shared-secret-xyz") -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.mark.asyncio
async def test_pdp_policy_accepts_valid_signature(proxy_app_signed):
    body = json.dumps({
        "initiator_agent_id": "acme::alice",
        "initiator_org_id": "acme",
        "target_agent_id": "other-org::bob",
        "target_org_id": "other-org",
        "capabilities": [],
        "session_context": "initiator",
    }).encode()
    resp = await proxy_app_signed.post(
        "/pdp/policy",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-ATN-Signature": _sign(body),
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["decision"] in ("allow", "deny")


@pytest.mark.asyncio
async def test_pdp_policy_rejects_missing_signature(proxy_app_signed):
    body = json.dumps({"initiator_agent_id": "x", "session_context": "initiator"}).encode()
    resp = await proxy_app_signed.post(
        "/pdp/policy",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401
    assert "signature" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_pdp_policy_rejects_wrong_signature(proxy_app_signed):
    body = json.dumps({"initiator_agent_id": "x", "session_context": "initiator"}).encode()
    resp = await proxy_app_signed.post(
        "/pdp/policy",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-ATN-Signature": "deadbeef" * 8,
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_pdp_policy_rejects_tampered_body(proxy_app_signed):
    """Sign body A, send body B → reject. The whole point of HMAC."""
    body_signed = json.dumps({"initiator_agent_id": "alice", "session_context": "initiator"}).encode()
    body_sent = json.dumps({"initiator_agent_id": "MALLORY", "session_context": "initiator"}).encode()
    sig = _sign(body_signed)
    resp = await proxy_app_signed.post(
        "/pdp/policy",
        content=body_sent,
        headers={
            "Content-Type": "application/json",
            "X-ATN-Signature": sig,
        },
    )
    assert resp.status_code == 401


@pytest_asyncio.fixture
async def proxy_app_unsigned(tmp_path, monkeypatch):
    """Legacy compat: no secret set → unsigned calls accepted."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.delenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    import importlib
    import mcp_proxy.main as main_mod
    importlib.reload(main_mod)
    app = main_mod.app

    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client

    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_pdp_policy_legacy_unsigned_accepted_when_secret_unset(proxy_app_unsigned):
    body = json.dumps({"initiator_agent_id": "x", "session_context": "initiator"}).encode()
    resp = await proxy_app_unsigned.post(
        "/pdp/policy",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200
