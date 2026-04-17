"""ADR-009 Phase 2 PR 2a — proxy end-to-end login flow carries the
mastio counter-signature.

Covers:
  - /v1/auth/sign-assertion returns ``mastio_signature`` when the proxy
    has loaded its mastio identity
  - /v1/auth/sign-assertion returns ``mastio_signature=None`` when no
    mastio identity is loaded (pre-ADR-009 / legacy)
  - The signature is valid — verifiable against the mastio leaf pubkey
  - /v1/admin/mastio-pubkey returns the PEM under X-Admin-Secret and
    403s on wrong secret
  - SDK login_via_proxy forwards mastio_signature into the /v1/auth/token
    X-Cullis-Mastio-Signature header (MockTransport unit test)
"""
from __future__ import annotations

import base64

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


# ── /v1/auth/sign-assertion ────────────────────────────────────────────

async def _spin_proxy(tmp_path, monkeypatch, org_id: str):
    """Shared fixture body — boot an in-process proxy app."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def test_sign_assertion_includes_mastio_signature(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sa-mastio")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            # Pre-register an agent so sign-assertion can resolve credentials.
            from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
            from mcp_proxy.db import create_agent
            from mcp_proxy.egress.agent_manager import AgentManager
            mgr: AgentManager = app.state.agent_manager

            # Issue an agent cert signed by the Org CA that the proxy just
            # generated during first-boot.
            cert_pem, key_pem = mgr._generate_agent_cert("alice")
            raw = generate_api_key("alice")
            await create_agent(
                agent_id="sa-mastio::alice",
                display_name="alice",
                capabilities=["oneshot.message"],
                api_key_hash=hash_api_key(raw),
                cert_pem=cert_pem,
            )
            # Persist the private key so get_agent_credentials works.
            from mcp_proxy.db import set_config
            await set_config("agent_key:sa-mastio::alice", key_pem)

            r = await cli.post(
                "/v1/auth/sign-assertion",
                headers={"X-API-Key": raw},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["agent_id"] == "sa-mastio::alice"
            assert body["client_assertion"]
            assert body["mastio_signature"], "expected non-null mastio_signature"

            # Verify the signature is valid against the pinned pubkey.
            pubkey_pem = mgr.get_mastio_pubkey_pem()
            pubkey = serialization.load_pem_public_key(pubkey_pem.encode())
            sig = base64.urlsafe_b64decode(
                body["mastio_signature"] + "=" * ((4 - len(body["mastio_signature"]) % 4) % 4)
            )
            pubkey.verify(
                sig, body["client_assertion"].encode(),
                ec.ECDSA(hashes.SHA256()),
            )

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── /v1/admin/mastio-pubkey ────────────────────────────────────────────

async def test_admin_mastio_pubkey_requires_admin_secret(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "adm-no-auth")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.get("/v1/admin/mastio-pubkey")
            assert r.status_code == 422  # missing required header
            r2 = await cli.get(
                "/v1/admin/mastio-pubkey",
                headers={"X-Admin-Secret": "wrong"},
            )
            assert r2.status_code == 403

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_admin_mastio_pubkey_returns_pem(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "adm-ok")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            from mcp_proxy.config import get_settings
            admin_secret = get_settings().admin_secret

            r = await cli.get(
                "/v1/admin/mastio-pubkey",
                headers={"X-Admin-Secret": admin_secret},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["org_id"] == "adm-ok"
            assert body["mastio_pubkey"]
            key = serialization.load_pem_public_key(body["mastio_pubkey"].encode())
            assert isinstance(key, ec.EllipticCurvePublicKey)
            assert isinstance(key.curve, ec.SECP256R1)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── SDK login_via_proxy wiring ─────────────────────────────────────────

def test_sdk_login_via_proxy_forwards_mastio_signature():
    """login_via_proxy reads mastio_signature from /sign-assertion and sends
    it as X-Cullis-Mastio-Signature on the /auth/token POST."""
    from cullis_sdk.client import CullisClient

    captured: dict[str, str] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/sign-assertion"):
            return httpx.Response(
                200,
                json={
                    "client_assertion": "FAKE-ASSERTION-JWT",
                    "agent_id": "test-org::bot",
                    "mastio_signature": "FAKE-MASTIO-SIG",
                },
                headers={"DPoP-Nonce": "test-nonce"},
            )
        # /auth/token
        captured["mastio"] = request.headers.get("x-cullis-mastio-signature", "")
        captured["dpop"] = request.headers.get("dpop", "")
        return httpx.Response(
            200,
            json={
                "access_token": "fake-token",
                "token_type": "DPoP",
                "expires_in": 900,
            },
        )

    transport = httpx.MockTransport(_handler)
    client = CullisClient("http://proxy.test", verify_tls=False)
    client._http = httpx.Client(transport=transport)
    client._proxy_api_key = "sk_local_test_abcdef"
    client._proxy_agent_id = "test-org::bot"

    client.login_via_proxy()

    assert captured["mastio"] == "FAKE-MASTIO-SIG"
    assert captured["dpop"]  # DPoP proof was sent too
    assert client.token == "fake-token"


def test_sdk_login_via_proxy_skips_header_when_signature_missing():
    """Legacy proxies (no mastio identity) return mastio_signature=None —
    SDK must not send an empty header."""
    from cullis_sdk.client import CullisClient

    captured: dict[str, str | None] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/sign-assertion"):
            return httpx.Response(
                200,
                json={
                    "client_assertion": "FAKE-ASSERTION-JWT",
                    "agent_id": "legacy::bot",
                    "mastio_signature": None,
                },
            )
        captured["mastio"] = request.headers.get("x-cullis-mastio-signature")
        return httpx.Response(
            200,
            json={
                "access_token": "fake-token",
                "token_type": "DPoP",
                "expires_in": 900,
            },
        )

    transport = httpx.MockTransport(_handler)
    client = CullisClient("http://proxy.legacy", verify_tls=False)
    client._http = httpx.Client(transport=transport)
    client._proxy_api_key = "sk_local_test_xyz"
    client._proxy_agent_id = "legacy::bot"

    client.login_via_proxy()
    assert captured.get("mastio") is None
