"""CRIT-1 — TOFU pubkey enforcement on the Mastio CSR signer.

Audit ref: ``imp/audits/2026-05-11-track-2-auth.md`` finding C1
(impersonation via cert mint + cert-pin bypass for typed principals).

The Mastio CSR signer (``mcp_proxy.registry.principals_csr.sign_user_csr``)
must refuse to sign a CSR whose public key does not match the
previously-pinned ``pubkey_thumbprint`` for the requested principal.
First-touch (no row, or row with NULL pubkey_thumbprint) sets the pin.
Re-mint with the same keypair refreshes the rotational cert. Re-mint
with a different keypair is the impersonation vector and must 4xx.
"""
from __future__ import annotations

import os

# Match the conftest env baseline so this file can run standalone too
# (the `tests/conftest.py` shared fixture sets these globally, but
# importing it eagerly pulls the Court app — we only need the proxy).
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    """Spin a Mastio app against a tmp sqlite — same shape as the
    proxy_app fixture in test_client_cert_auth.py."""
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_INTRA_ORG", "true")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "false")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


def _build_org_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """A tiny throwaway Org CA suitable for unit-level CSR signing."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Cullis Mastio Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "acme"),
    ])
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_csr(spiffe_uri: str) -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Build an EC P-256 CSR with the given SPIFFE SAN."""
    priv = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "principal"),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_uri),
            ]),
            critical=False,
        )
    )
    csr = builder.sign(priv, hashes.SHA256())
    return priv, csr.public_bytes(serialization.Encoding.PEM).decode()


def _fake_agent_manager(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    org_id: str = "acme",
):
    """sign_user_csr only reads ``.org_id``, ``.ca_loaded``,
    ``._org_ca_key``, ``._org_ca_cert`` — a SimpleNamespace covers it
    without dragging the full AgentManager bootstrap."""
    return SimpleNamespace(
        org_id=org_id,
        ca_loaded=True,
        _org_ca_key=ca_key,
        _org_ca_cert=ca_cert,
    )


# ── direct sign_user_csr TOFU tests ─────────────────────────────────


async def test_first_mint_succeeds_and_returns_pubkey_thumbprint(proxy_app):
    """No prior row for the principal — sign succeeds and returns a
    non-empty pubkey thumbprint that the caller will pin."""
    ca_key, ca_cert = _build_org_ca()
    mgr = _fake_agent_manager(ca_key, ca_cert)
    _priv, csr_pem = _make_csr(
        "spiffe://cullis.local/acme/user/mario",
    )

    from mcp_proxy.registry.principals_csr import sign_user_csr
    cert_pem, cert_thumb, pubkey_thumb, not_after = await sign_user_csr(
        csr_pem, "cullis.local/acme/user/mario", agent_manager=mgr,
    )
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert len(cert_thumb) == 64  # sha256 hex
    assert len(pubkey_thumb) == 64  # sha256 hex
    assert cert_thumb != pubkey_thumb  # cert DER ≠ SPKI DER


async def test_remint_same_pubkey_succeeds(proxy_app):
    """Re-mint with the same keypair (rotational cert refresh) is
    idempotent — pubkey thumbprint stays the same."""
    ca_key, ca_cert = _build_org_ca()
    mgr = _fake_agent_manager(ca_key, ca_cert)
    priv, csr_pem = _make_csr("spiffe://cullis.local/acme/user/alice")

    # First mint via the same module path the router uses, including
    # the upsert_from_csr step that pins the pubkey.
    from mcp_proxy.registry.principals_csr import sign_user_csr
    from mcp_proxy.admin.users import upsert_from_csr
    _, _, first_pubkey, _ = await sign_user_csr(
        csr_pem, "cullis.local/acme/user/alice", agent_manager=mgr,
    )
    await upsert_from_csr(
        principal_id="cullis.local/acme/user/alice",
        org_id="acme",
        cert_thumbprint="dummy",
        pubkey_thumbprint=first_pubkey,
    )

    # Second CSR with the SAME private key (rebuild the CSR from the
    # same priv) — pubkey thumbprint must match.
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "principal"),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(
                    "spiffe://cullis.local/acme/user/alice",
                ),
            ]),
            critical=False,
        )
    )
    second_csr = builder.sign(priv, hashes.SHA256())
    second_pem = second_csr.public_bytes(serialization.Encoding.PEM).decode()

    _, _, second_pubkey, _ = await sign_user_csr(
        second_pem, "cullis.local/acme/user/alice", agent_manager=mgr,
    )
    assert second_pubkey == first_pubkey


async def test_remint_different_pubkey_rejected(proxy_app):
    """The headline impersonation defence — second CSR for the same
    principal_id with a NEW keypair must be refused (TOFU mismatch)."""
    ca_key, ca_cert = _build_org_ca()
    mgr = _fake_agent_manager(ca_key, ca_cert)
    _priv1, csr_pem1 = _make_csr("spiffe://cullis.local/acme/user/ceo")

    # First mint pins the legitimate keypair.
    from mcp_proxy.registry.principals_csr import sign_user_csr, CsrValidationError
    from mcp_proxy.admin.users import upsert_from_csr
    _, _, first_pubkey, _ = await sign_user_csr(
        csr_pem1, "cullis.local/acme/user/ceo", agent_manager=mgr,
    )
    await upsert_from_csr(
        principal_id="cullis.local/acme/user/ceo",
        org_id="acme",
        cert_thumbprint="dummy",
        pubkey_thumbprint=first_pubkey,
    )

    # Attacker generates their own keypair, builds a CSR with the
    # same SPIFFE SAN. The CSR is structurally valid; CA could sign it
    # (the chain would be fine). But the pubkey doesn't match what
    # we pinned.
    _priv2, csr_pem2 = _make_csr("spiffe://cullis.local/acme/user/ceo")

    with pytest.raises(CsrValidationError, match="TOFU"):
        await sign_user_csr(
            csr_pem2, "cullis.local/acme/user/ceo", agent_manager=mgr,
        )


async def test_first_mint_with_legacy_row_pubkey_null_succeeds(proxy_app):
    """Admin pre-created the row via /v1/admin/users (no pubkey yet,
    column is NULL). First CSR succeeds — sets pubkey on upsert.
    Behaviour matches the bare ``no row at all`` case."""
    from datetime import datetime, timezone
    from sqlalchemy import text
    from mcp_proxy.db import get_db

    # Pre-create the row admin-style (pubkey NULL).
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO local_user_principals "
                "(principal_id, user_name, reach, surface, "
                " pubkey_thumbprint, created_at) "
                "VALUES ('acme::user::pre', 'pre', 'intra', NULL, "
                " NULL, :now)"
            ),
            {"now": datetime.now(timezone.utc).isoformat()},
        )

    ca_key, ca_cert = _build_org_ca()
    mgr = _fake_agent_manager(ca_key, ca_cert)
    _, csr_pem = _make_csr("spiffe://cullis.local/acme/user/pre")

    from mcp_proxy.registry.principals_csr import sign_user_csr
    cert_pem, _, pubkey_thumb, _ = await sign_user_csr(
        csr_pem, "cullis.local/acme/user/pre", agent_manager=mgr,
    )
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert len(pubkey_thumb) == 64
