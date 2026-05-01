"""
M-crypto-2 regression: Org CA + agent leaf cert generation defaults to
EC P-256, not RSA.

The audit flagged ``mcp_proxy/egress/agent_manager.py`` for shipping
RSA-2048 by default. RSA-2048 carries 112-bit security strength under
NIST SP 800-57, which is below the recommended floor for keys with a
10-year (Org CA) or 1-year (agent leaf) lifetime starting in 2026. EC
P-256 hits 128-bit strength with smaller keys, faster signatures, and
matches the convention already used by the Mastio identity, the DPoP
keypair, and the ECDH ephemeral.

Existing RSA agents and Org CAs keep working because the verifier
stays dual-stack; this file just locks in that NEW material is EC.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "m_crypto.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


def _load_priv(pem: str):
    return serialization.load_pem_private_key(pem.encode(), password=None)


@pytest.mark.asyncio
async def test_standalone_org_ca_is_ec_p256(proxy_app):
    """Self-signed Org CA on first boot must be EC P-256, not RSA."""
    from mcp_proxy.db import get_config
    pem = await get_config("org_ca_key")
    assert pem is not None, "standalone proxy did not persist Org CA"
    key = _load_priv(pem)
    assert isinstance(key, ec.EllipticCurvePrivateKey), (
        f"Org CA must be EC under M-crypto-2 audit fix, got {type(key).__name__}"
    )
    assert isinstance(key.curve, ec.SECP256R1)
    # And NOT RSA — explicit guard so a regression to RSA fails loudly.
    assert not isinstance(key, _rsa.RSAPrivateKey)


@pytest.mark.asyncio
async def test_internal_agent_leaf_is_ec_p256(proxy_app):
    """``_generate_agent_cert`` must produce EC P-256 leaves."""
    app, _ = proxy_app
    mgr = app.state.agent_manager
    cert_pem, key_pem = mgr._generate_agent_cert("alice")
    key = _load_priv(key_pem)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)
    assert not isinstance(key, _rsa.RSAPrivateKey)


@pytest.mark.asyncio
async def test_agent_cert_signature_alg_is_ecdsa(proxy_app):
    """Cert signature algorithm must be ecdsa-with-SHA256 (an EC Org CA
    signs with ECDSA, not RSA-PKCS1v15)."""
    from cryptography import x509 as _x509

    app, _ = proxy_app
    mgr = app.state.agent_manager
    cert_pem, _ = mgr._generate_agent_cert("alice")
    cert = _x509.load_pem_x509_certificate(cert_pem.encode())
    # ECDSA with SHA-256 — OID 1.2.840.10045.4.3.2
    assert cert.signature_algorithm_oid.dotted_string == "1.2.840.10045.4.3.2", (
        f"agent cert must be ECDSA-signed under EC Org CA, got "
        f"{cert.signature_algorithm_oid.dotted_string}"
    )


@pytest.mark.asyncio
async def test_agent_cert_chains_under_ec_org_ca(proxy_app):
    """Sanity: agent cert verifies against the EC Org CA via ECDSA."""
    from cryptography import x509 as _x509

    app, _ = proxy_app
    mgr = app.state.agent_manager
    cert_pem, _ = mgr._generate_agent_cert("alice")
    cert = _x509.load_pem_x509_certificate(cert_pem.encode())
    org_pub = mgr._org_ca_cert.public_key()
    assert isinstance(org_pub, ec.EllipticCurvePublicKey)
    # ECDSA verify path — raises on failure.
    org_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),
    )
