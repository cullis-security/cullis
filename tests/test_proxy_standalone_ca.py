"""#115 — standalone first-boot Org CA self-generation.

Booting the proxy in standalone mode with an empty DB should produce a
fresh self-signed Org CA: persisted to proxy_config, loaded into the
AgentManager, usable to mint agent certs. Federation mode keeps the
existing attach-ca behaviour.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def standalone_proxy(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield app, client
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_standalone_generates_org_ca_on_first_boot(standalone_proxy):
    app, _ = standalone_proxy
    mgr = app.state.agent_manager
    assert mgr.ca_loaded, "AgentManager must load the freshly-generated CA"
    cert = mgr._org_ca_cert
    subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert subject_cn == "acme CA"
    # Self-signed: issuer == subject
    assert cert.issuer == cert.subject
    # BasicConstraints(ca=True, path_length=1) — ADR-003 allows one intermediate
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 1


@pytest.mark.asyncio
async def test_standalone_ca_persisted_to_proxy_config(standalone_proxy):
    _, _ = standalone_proxy
    from mcp_proxy.db import get_config
    ca_key_pem = await get_config("org_ca_key")
    ca_cert_pem = await get_config("org_ca_cert")
    assert ca_key_pem and "BEGIN PRIVATE KEY" in ca_key_pem
    assert ca_cert_pem and "BEGIN CERTIFICATE" in ca_cert_pem
    # M-crypto-2 audit: Org CA is now EC P-256 (was RSA-2048). Loading
    # legacy RSA Org CAs from disk still works via the dual-stack
    # verifier; this test exercises the freshly-minted path.
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
    assert isinstance(key, _ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, _ec.SECP256R1)


@pytest.mark.asyncio
async def test_standalone_ca_can_issue_agent_cert(standalone_proxy):
    """The generated CA must be usable to mint internal agent certs."""
    app, _ = standalone_proxy
    mgr = app.state.agent_manager
    cert_pem, key_pem = mgr._generate_agent_cert("bot-alpha")
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    # Signed by the freshly-generated Org CA
    assert cert.issuer == mgr._org_ca_cert.subject
    # Agent subject is {org}::{name}
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "acme::bot-alpha"


@pytest.mark.asyncio
async def test_standalone_ca_survives_restart(tmp_path, monkeypatch):
    """Second boot must reuse the persisted CA instead of generating a new one."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    # First boot — generates CA.
    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        first_cert_pem = app.state.agent_manager._org_ca_cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode()

    # Second boot — same DB, should reuse.
    get_settings.cache_clear()
    async with app.router.lifespan_context(app):
        second_cert_pem = app.state.agent_manager._org_ca_cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode()

    assert first_cert_pem == second_cert_pem
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_federation_mode_no_autogeneration(tmp_path, monkeypatch):
    """Federation deploys must NOT auto-generate a CA — attach-ca is the source of truth."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")  # PR-D: default flipped to true; tests that expect federated bring-up must opt in explicitly
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_BROKER_URL", "http://broker.example")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app
    async with app.router.lifespan_context(app):
        mgr = app.state.agent_manager
        # No attach-ca performed → CA not loaded, AND not auto-generated.
        assert mgr.ca_loaded is False
    get_settings.cache_clear()
