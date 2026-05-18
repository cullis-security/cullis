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


# ── Wave 1-A bootstrap regression (PR #794 follow-up) ─────────────────


def _seed_org_ca_pem(org_id: str) -> tuple[str, str]:
    """Mint a self-signed Org Root + return (key_pem, cert_pem) PEMs.

    Mirrors what ``sandbox/proxy-init/seed.py`` does for the legacy
    plaintext seeding path: an EC P-256 keypair under a CA cert with
    pathLen=1 so a Mastio Intermediate can chain underneath.
    """
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


@pytest_asyncio.fixture
async def proxy_app_with_seeded_legacy_org_ca(tmp_path, monkeypatch):
    """Like ``proxy_app`` but pre-seeds legacy plaintext rows BEFORE lifespan.

    Reproduces the sandbox federated boot: ``proxy-init/seed.py`` writes
    ``proxy_config.org_ca_key`` + ``org_ca_cert`` as plaintext, then the
    Mastio container boots and runs the lifespan. Without the Wave 1-A
    fix, Phase 0 wipes the plaintext rows without first migrating them
    into ``pki_key_store``, leaving the Mastio without an Org Root on
    the next ``ensure_mastio_identity`` call.
    """
    db_file = tmp_path / "pki_bootstrap_migrate.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    # Federated mode: short-circuits the standalone generate_org_ca
    # fallback, so the migration is the only path that lands a usable
    # Org Root on this boot.
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "test-passphrase-32-chars-minimum-three-tier",
    )

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.kms.pki_at_rest import _reset_cache_for_tests
    _reset_cache_for_tests()
    from mcp_proxy.kms.factory import reset_kms_provider
    reset_kms_provider()

    # Mirror what ``sandbox/proxy-init/seed.py`` writes BEFORE the
    # Mastio lifespan runs: schema upgrade + legacy plaintext rows
    # in ``proxy_config``. Lifespan calls ``init_db`` again on entry;
    # alembic upgrade head is idempotent so the double call is safe.
    from sqlalchemy import text as _text

    key_pem, cert_pem = _seed_org_ca_pem("acme")

    from mcp_proxy.db import dispose_db, get_db, init_db
    await init_db(f"sqlite+aiosqlite:///{db_file}")
    async with get_db() as conn:
        for k, v in (
            ("org_id", "acme"),
            ("org_ca_key", key_pem),
            ("org_ca_cert", cert_pem),
        ):
            await conn.execute(
                _text(
                    "INSERT INTO proxy_config (key, value) "
                    "VALUES (:k, :v) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
                ),
                {"k": k, "v": v},
            )
    await dispose_db()

    from httpx import ASGITransport, AsyncClient

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client, key_pem, cert_pem

    get_settings.cache_clear()
    reset_kms_provider()
    _reset_cache_for_tests()


@pytest.mark.asyncio
async def test_bootstrap_migrates_legacy_org_ca_into_pki_key_store(
    proxy_app_with_seeded_legacy_org_ca,
):
    """Phase 0 must MIGRATE legacy plaintext into ``pki_key_store``.

    Reproduces the sandbox federated cold-boot. Pre-fix the wipe
    archived + deleted the only copy of the Org Root keypair, and the
    federated lifespan (``settings.standalone=False``) skipped the
    ``generate_org_ca`` fallback — leaving ``ca_loaded=False`` and
    cascading into nginx cert + Mastio Intermediate provisioning
    failures. Post-fix the migration step encrypts the legacy keypair
    into ``pki_key_store`` before the archive+delete, so the very same
    boot can load it via ``load_org_ca_from_config`` and complete the
    chain.
    """
    app, _client, expected_key_pem, expected_cert_pem = (
        proxy_app_with_seeded_legacy_org_ca
    )
    mgr = app.state.agent_manager

    # Lifespan must have loaded the Org Root + minted the Intermediate
    # + emitted a Mastio leaf. The bug surfaced as ca_loaded=False here.
    assert mgr.ca_loaded, "Org Root must be loaded after migrate-then-wipe"
    assert mgr._mastio_ca_cert is not None, (
        "Mastio Intermediate must be minted under the migrated Org Root"
    )
    assert mgr._active_key is not None, (
        "Mastio Leaf must be issued under the new Intermediate"
    )

    # The Org Root cert preserved across the migration must match the
    # legacy seed (pubkey identity, not a fresh keypair — federation
    # trust pinning would break otherwise).
    persisted_cert = _load_cert(expected_cert_pem)
    assert (
        mgr._org_ca_cert.public_bytes(serialization.Encoding.DER)
        == persisted_cert.public_bytes(serialization.Encoding.DER)
    ), "migration must preserve the legacy Org Root pubkey, not regen it"

    # ``pki_key_store`` should hold the migrated keypair under the
    # active row for ``key_type='org_ca'``.
    from mcp_proxy.db import get_active_pki_key
    row = await get_active_pki_key("org_ca")
    assert row is not None, "pki_key_store.org_ca active row must exist post-migration"
    assert row["cert_pem"] == expected_cert_pem


@pytest.mark.asyncio
async def test_bootstrap_legacy_plaintext_rows_are_archived(
    proxy_app_with_seeded_legacy_org_ca,
):
    """After migration the legacy plaintext key is gone from proxy_config.

    The wipe step still runs (the migration is on top of, not in place
    of, the archive+delete). ``org_ca_cert`` stays in ``proxy_config``
    for the legacy ``/pki/ca.crt`` and connector-bootstrap endpoints
    that still read it directly.
    """
    app, _client, _key_pem, expected_cert_pem = (
        proxy_app_with_seeded_legacy_org_ca
    )

    from mcp_proxy.db import get_config, list_legacy_pki_archive
    assert await get_config("org_ca_key") is None, (
        "legacy org_ca_key plaintext must be deleted from proxy_config "
        "after Phase 0 migrate+wipe"
    )
    # Cert kept for back-compat readers.
    assert await get_config("org_ca_cert") == expected_cert_pem

    archive = await list_legacy_pki_archive()
    org_rows = [r for r in archive if r["key_type"] == "org_ca"]
    assert len(org_rows) >= 1, (
        "legacy_pki_archive must record the archived plaintext key for forensic recovery"
    )

    # And the chain still works end-to-end: agent cert minted under
    # the Intermediate (the cascade-fail surface pre-fix).
    mgr = app.state.agent_manager
    cert_pem, _ = mgr._generate_agent_cert("alice")
    cert = _load_cert(cert_pem)
    issuer_cn = cert.issuer.get_attributes_for_oid(
        x509.NameOID.COMMON_NAME,
    )[0].value
    assert issuer_cn.endswith("Mastio CA"), (
        f"agent cert must chain under the migrated Intermediate, got CN={issuer_cn!r}"
    )
