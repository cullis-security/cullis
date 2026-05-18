"""Three-tier PKI hardening (audit 2026-05-18) — chain regression tests.

Verifies that:

* Agent certs are signed by the Mastio Intermediate, not the Org Root.
* External pubkey enrollment (Connector) chains under the Intermediate.
* nginx server cert chains under the Intermediate.
* The Mastio Leaf chains under the Intermediate (pre-existing).
* The Intermediate chains under the Org Root.
* Org Root private key is NOT cached in memory at steady state
  (cold-by-default).

Plus Phase 4 rotation:

* :meth:`AgentManager.rotate_mastio_ca` mints a new Intermediate,
  re-issues the Mastio Leaf, atomic-swaps under the rotation lock.
* Old Intermediate's continuity proof verifies against the new
  Intermediate cert.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "pki_three_tier.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "test-passphrase-32-chars-minimum-three-tier",
    )
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    # Make sure the pki_at_rest module reads the fresh env value.
    from mcp_proxy.kms.pki_at_rest import _reset_cache_for_tests
    _reset_cache_for_tests()
    from mcp_proxy.kms.factory import reset_kms_provider
    reset_kms_provider()

    from httpx import ASGITransport, AsyncClient

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()
    reset_kms_provider()
    _reset_cache_for_tests()


def _load_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


@pytest.mark.asyncio
async def test_agent_cert_chains_under_intermediate(proxy_app):
    app, _ = proxy_app
    mgr = app.state.agent_manager
    cert_pem, _ = mgr._generate_agent_cert("alice")
    cert = _load_cert(cert_pem)
    # Issuer must be the Intermediate CA (CN '<org> Mastio CA'), not
    # the Org Root (CN '<org> CA').
    issuer_cn = cert.issuer.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME,
    )[0].value
    assert issuer_cn.endswith("Mastio CA"), (
        f"agent cert must be Intermediate-signed, got issuer CN={issuer_cn!r}"
    )
    # And the Intermediate pubkey verifies the signature.
    int_pub = mgr._mastio_ca_cert.public_key()
    int_pub.verify(
        cert.signature, cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),
    )


@pytest.mark.asyncio
async def test_external_pubkey_chains_under_intermediate(proxy_app):
    app, _ = proxy_app
    mgr = app.state.agent_manager

    ext_key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = ext_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    cert_pem = mgr.sign_external_pubkey(pubkey_pem=pub_pem, agent_name="ext")
    cert = _load_cert(cert_pem)
    issuer_cn = cert.issuer.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME,
    )[0].value
    assert issuer_cn.endswith("Mastio CA"), (
        f"external pubkey enrollment must be Intermediate-signed, "
        f"got issuer CN={issuer_cn!r}"
    )


@pytest.mark.asyncio
async def test_nginx_server_cert_chains_under_intermediate(proxy_app, tmp_path):
    app, _ = proxy_app
    mgr = app.state.agent_manager
    out_dir = tmp_path / "nginx-certs"
    await mgr.ensure_nginx_server_cert(
        out_dir=str(out_dir), sans=["mastio.local"],
    )
    crt = _load_cert((out_dir / "mastio-server.crt").read_bytes().decode())
    issuer_cn = crt.issuer.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME,
    )[0].value
    assert issuer_cn.endswith("Mastio CA"), (
        f"nginx server cert must be Intermediate-signed, got "
        f"issuer CN={issuer_cn!r}"
    )
    # The on-disk trust bundle must contain BOTH the Org Root and the
    # Intermediate so client-side chain validation succeeds.
    bundle_text = (out_dir / "org-ca.crt").read_bytes().decode()
    cert_blocks = bundle_text.count("-----BEGIN CERTIFICATE-----")
    assert cert_blocks == 2, (
        f"trust bundle must hold (Org Root || Intermediate); got "
        f"{cert_blocks} cert blocks"
    )


@pytest.mark.asyncio
async def test_nginx_cert_validity_is_90_days(proxy_app, tmp_path):
    """New 90-day cadence for nginx leaf (audit 2026-05-18 rebalancing)."""
    from datetime import datetime, timezone

    app, _ = proxy_app
    mgr = app.state.agent_manager
    out_dir = tmp_path / "nginx-certs"
    await mgr.ensure_nginx_server_cert(out_dir=str(out_dir))
    crt = _load_cert((out_dir / "mastio-server.crt").read_bytes().decode())
    not_after = crt.not_valid_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    delta = not_after - datetime.now(timezone.utc)
    days = int(delta.total_seconds() / 86400)
    # Tolerance window: 88..92 to accept clock drift + the -5m
    # not_valid_before slop in the builder.
    assert 88 <= days <= 92, f"nginx leaf validity {days}d not ~= 90d"


@pytest.mark.asyncio
async def test_org_root_cold_by_default_at_steady_state(proxy_app):
    """Post-bootstrap the Org Root private key is NOT in memory."""
    app, _ = proxy_app
    mgr = app.state.agent_manager
    # Cert is loaded (public material), private key is None (cold).
    assert mgr._org_ca_cert is not None
    assert mgr._org_ca_key is None, (
        "Org Root private key must be cold at steady state; "
        f"got {type(mgr._org_ca_key).__name__}"
    )


@pytest.mark.asyncio
async def test_rotate_mastio_ca_dry_run(proxy_app):
    app, _ = proxy_app
    mgr = app.state.agent_manager
    old_int_cn = mgr._mastio_ca_cert.subject.rfc4514_string()
    result = await mgr.rotate_mastio_ca(
        grace_days=14, operator="admin", dry_run=True,
    )
    assert result["dry_run"] is True
    assert result["old_intermediate_cn"] == old_int_cn
    # No mutation on dry run — same Intermediate still in memory.
    assert mgr._mastio_ca_cert.subject.rfc4514_string() == old_int_cn


@pytest.mark.asyncio
async def test_rotate_mastio_ca_real_swap(proxy_app):
    app, _ = proxy_app
    mgr = app.state.agent_manager
    old_int_cert = mgr._mastio_ca_cert
    old_int_pubkey_der = old_int_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    result = await mgr.rotate_mastio_ca(
        grace_days=14, operator="admin", dry_run=False,
    )
    assert result["dry_run"] is False
    assert result["new_leaf_kid"] is not None

    # Intermediate changed.
    new_int_cert = mgr._mastio_ca_cert
    new_int_pubkey_der = new_int_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert new_int_pubkey_der != old_int_pubkey_der, (
        "rotation should produce a fresh Intermediate keypair"
    )

    # Continuity proof: old Intermediate's pubkey verifies the
    # signature over the new Intermediate's DER.
    import base64

    proof = result["continuity_proof"]
    proof_bytes = base64.urlsafe_b64decode(proof + "=" * (4 - len(proof) % 4))
    old_int_pub = old_int_cert.public_key()
    old_int_pub.verify(
        proof_bytes,
        new_int_cert.public_bytes(serialization.Encoding.DER),
        ec.ECDSA(hashes.SHA256()),
    )

    # Agent issuance still works under the new Intermediate.
    cert_pem, _ = mgr._generate_agent_cert("post-rotation")
    new_agent_cert = _load_cert(cert_pem)
    new_int_pub = new_int_cert.public_key()
    new_int_pub.verify(
        new_agent_cert.signature,
        new_agent_cert.tbs_certificate_bytes,
        ec.ECDSA(new_agent_cert.signature_hash_algorithm),
    )
