"""ADR-004 PR D — /v1/auth/sign-assertion endpoint.

The proxy signs a broker client_assertion JWT on behalf of an enrolled
agent so the SDK can call /v1/auth/token (via the reverse-proxy) without
needing the cert+key locally.
"""
from __future__ import annotations

import jwt as jose_jwt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    """Proxy ASGI app with an initialized BrokerBridge + AgentManager."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_BROKER_URL", "http://broker.example")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield app, client
    get_settings.cache_clear()


async def _provision_agent_with_cert(app, agent_id: str) -> tuple[str, str]:
    """Provision an enrolled agent: Org CA + cert issued + key stored.

    Returns (api_key, cert_pem).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    # Generate Org CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject).issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(hours=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    from mcp_proxy.db import set_config
    await set_config("org_ca_key", ca_key_pem)
    await set_config("org_ca_cert", ca_cert_pem)

    # ``app.state.broker_bridge`` is None in standalone test runs; the
    # canonical AgentManager reference is on ``app.state.agent_manager``
    # regardless of lifespan mode (see mcp_proxy/main.py:131). Using the
    # nested attribute was racy under xdist when a prior test left the
    # app singleton with broker_bridge=None.
    mgr = (
        getattr(app.state, "broker_bridge", None) and
        app.state.broker_bridge._agent_manager
    ) or app.state.agent_manager
    await mgr.load_org_ca(ca_key_pem, ca_cert_pem)

    cert_pem, key_pem = mgr._generate_agent_cert(agent_id.split("::", 1)[-1])

    from mcp_proxy.db import create_agent
    await create_agent(
        agent_id=agent_id,
        display_name=agent_id,
        capabilities=["cap.read"],
        cert_pem=cert_pem,
    )
    await set_config(f"agent_key:{agent_id}", key_pem)
    return cert_pem


@pytest.mark.asyncio
async def test_sign_assertion_returns_jwt(proxy_app):
    app, client = proxy_app
    cert_pem = await _provision_agent_with_cert(app, "acme::enrolled-bot")
    from tests._mtls_helpers import mtls_headers

    resp = await client.post(
        "/v1/auth/sign-assertion",
        headers=mtls_headers(cert_pem),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["agent_id"] == "acme::enrolled-bot"
    assertion = body["client_assertion"]
    assert assertion.count(".") == 2

    claims = jose_jwt.decode(assertion, options={"verify_signature": False})
    assert claims["sub"] == "acme::enrolled-bot"
    assert claims["iss"] == "acme::enrolled-bot"
    assert claims["aud"] == "agent-trust-broker"
    assert "jti" in claims and len(claims["jti"]) > 0
    assert claims["exp"] > claims["iat"]

    header = jose_jwt.get_unverified_header(assertion)
    assert header.get("x5c"), "assertion must carry the agent cert in x5c"


@pytest.mark.asyncio
async def test_sign_assertion_requires_client_cert(proxy_app):
    _, client = proxy_app
    resp = await client.post("/v1/auth/sign-assertion")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sign_assertion_not_reverse_proxied(proxy_app):
    """Route precedence — /v1/auth/sign-assertion must NOT hit the reverse proxy."""
    _, client = proxy_app
    # Anonymous request → 401 from cert dep. The reverse-proxy would
    # yield something very different (x-cullis-role set by the forwarder).
    resp = await client.post("/v1/auth/sign-assertion")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sign_assertion_agent_missing_credentials(proxy_app):
    app, client = proxy_app
    # Provision an agent that has a cert (so the cert-auth dep accepts
    # them) but NO server-side private key — the endpoint must fail
    # gracefully with 404 because get_agent_credentials returns nothing.
    from mcp_proxy.db import create_agent
    from tests._mtls_helpers import mint_agent_cert, mtls_headers
    cert_pem, _ = mint_agent_cert(org_id="acme", agent_name="ghost-bot")
    await create_agent(
        agent_id="acme::ghost-bot",
        display_name="ghost-bot",
        capabilities=[],
        cert_pem=cert_pem,
    )
    resp = await client.post(
        "/v1/auth/sign-assertion",
        headers=mtls_headers(cert_pem),
    )
    assert resp.status_code == 404
