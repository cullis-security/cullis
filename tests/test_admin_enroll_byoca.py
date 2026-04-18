"""ADR-011 Phase 1b — ``/v1/admin/agents/enroll/byoca``.

Covers:
  - Happy path: caller submits Org-CA-signed cert → 201 with api_key +
    thumbprint + enrollment_method='byoca' persisted
  - Cert NOT signed by the Mastio's Org CA → 400
  - Private key does not match cert public key → 400
  - Agent already enrolled → 409
  - Admin secret missing / wrong → 403
  - Cert with SPIFFE URI SAN → response surfaces ``spiffe_id``
  - ``dpop_jwk`` pins RFC 7638 jkt on ``internal_agents``
  - ``dpop_jwk`` with private material (``d``) → 400
"""
from __future__ import annotations

import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


# ── harness ──────────────────────────────────────────────────────────────

async def _spin_proxy(tmp_path, monkeypatch, org_id: str):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def _headers():
    from mcp_proxy.config import get_settings
    return {"X-Admin-Secret": get_settings().admin_secret}


async def _load_org_ca():
    """Read the Mastio's auto-generated Org CA from proxy_config.

    Standalone mode generates the CA at lifespan startup and stores
    both halves in ``proxy_config`` (see ``AgentManager.generate_org_ca``).
    The test fixtures reuse it to mint valid leaves — a real deployment
    would use a real PKI here.
    """
    from mcp_proxy.db import get_config
    return await get_config("org_ca_cert"), await get_config("org_ca_key")


def _issue_cert_from_ca(
    ca_cert_pem: str,
    ca_key_pem: str,
    *,
    subject_cn: str,
    spiffe_uri: str | None = None,
    validity_days: int = 30,
) -> tuple[str, str]:
    """Issue a fresh leaf cert signed by the supplied Org CA.

    Returns ``(cert_pem, key_pem)``. EC P-256 leaves — the Org CA in
    the Mastio accepts any key type the ``cryptography`` stack can
    produce; EC keeps the helper fast.
    """
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=validity_days)
        )
    )
    if spiffe_uri:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=False,
        )

    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _generate_foreign_ca() -> tuple[str, str]:
    """Build a rogue CA + issue a leaf — neither chain is loaded on the
    Mastio, so enrollment must reject the leaf."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue-ca")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue-ca")]))
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return ca_cert_pem, ca_key_pem


async def _fetch_internal_row(app, agent_id: str) -> dict:
    """Read the ``internal_agents`` row the endpoint wrote."""
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT enrollment_method, spiffe_id, enrolled_at, dpop_jkt, "
                 "cert_pem FROM internal_agents WHERE agent_id = :aid"),
            {"aid": agent_id},
        )).first()
    assert row is not None, f"row missing for {agent_id}"
    return {
        "enrollment_method": row[0],
        "spiffe_id": row[1],
        "enrolled_at": row[2],
        "dpop_jkt": row[3],
        "cert_pem": row[4],
    }


# ── happy path ───────────────────────────────────────────────────────────

async def test_byoca_enroll_happy_path_returns_api_key(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "bc-happy")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            from mcp_proxy.db import get_config
            ca_cert_pem = await get_config("org_ca_cert")
            ca_key_pem = await get_config("org_ca_key")
            cert_pem, key_pem = _issue_cert_from_ca(
                ca_cert_pem, ca_key_pem,
                subject_cn="alice",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers=await _headers(),
                json={
                    "agent_name": "alice",
                    "display_name": "Alice BYOCA",
                    "capabilities": ["order.read"],
                    "cert_pem": cert_pem,
                    "private_key_pem": key_pem,
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["agent_id"] == "bc-happy::alice"
            assert body["api_key"].startswith("sk_local_alice_")
            assert len(body["cert_thumbprint"]) == 64  # SHA-256 hex
            assert body["spiffe_id"] is None
            assert body["dpop_jkt"] is None

            row = await _fetch_internal_row(app, "bc-happy::alice")
            assert row["enrollment_method"] == "byoca"
            assert row["spiffe_id"] is None
            assert row["enrolled_at"] is not None
            assert row["cert_pem"] == cert_pem
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_byoca_enroll_extracts_spiffe_uri_san(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "bc-spiffe")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            mgr = app.state.agent_manager
            spiffe = "spiffe://bc-spiffe.test/agent/bob"
            cert_pem, key_pem = _issue_cert_from_ca(
                *await _load_org_ca(),
                subject_cn="bob", spiffe_uri=spiffe,
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers=await _headers(),
                json={
                    "agent_name": "bob",
                    "cert_pem": cert_pem,
                    "private_key_pem": key_pem,
                },
            )
            assert r.status_code == 201, r.text
            assert r.json()["spiffe_id"] == spiffe
            row = await _fetch_internal_row(app, "bc-spiffe::bob")
            assert row["spiffe_id"] == spiffe
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_byoca_enroll_pins_dpop_jkt_when_jwk_supplied(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "bc-dpop")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            mgr = app.state.agent_manager
            cert_pem, key_pem = _issue_cert_from_ca(
                *await _load_org_ca(), subject_cn="carol",
            )
            # Generate a public EC JWK for the DPoP key; server computes
            # the thumbprint from ``kty``+``crv``+``x``+``y``.
            dpop_key = ec.generate_private_key(ec.SECP256R1())
            pub_numbers = dpop_key.public_key().public_numbers()
            import base64
            def b64u(n: int) -> str:
                b = n.to_bytes(32, "big")
                return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
            dpop_jwk = {
                "kty": "EC", "crv": "P-256",
                "x": b64u(pub_numbers.x), "y": b64u(pub_numbers.y),
            }
            r = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers=await _headers(),
                json={
                    "agent_name": "carol",
                    "cert_pem": cert_pem,
                    "private_key_pem": key_pem,
                    "dpop_jwk": dpop_jwk,
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["dpop_jkt"] is not None
            assert len(body["dpop_jkt"]) > 20
            row = await _fetch_internal_row(app, "bc-dpop::carol")
            assert row["dpop_jkt"] == body["dpop_jkt"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── rejection paths ──────────────────────────────────────────────────────

async def test_byoca_enroll_rejects_cert_from_foreign_ca(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "bc-foreign")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            foreign_ca_pem, foreign_ca_key_pem = _generate_foreign_ca()
            cert_pem, key_pem = _issue_cert_from_ca(
                foreign_ca_pem, foreign_ca_key_pem, subject_cn="rogue",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers=await _headers(),
                json={
                    "agent_name": "rogue",
                    "cert_pem": cert_pem,
                    "private_key_pem": key_pem,
                },
            )
            assert r.status_code == 400, r.text
            assert "Org CA" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_byoca_enroll_rejects_mismatched_private_key(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "bc-mismatch")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            mgr = app.state.agent_manager
            cert_pem, _ = _issue_cert_from_ca(
                *await _load_org_ca(), subject_cn="d1",
            )
            # Use a *different* key to sign the re-enrollment body.
            _, wrong_key_pem = _issue_cert_from_ca(
                *await _load_org_ca(), subject_cn="d2",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers=await _headers(),
                json={
                    "agent_name": "mismatch",
                    "cert_pem": cert_pem,
                    "private_key_pem": wrong_key_pem,
                },
            )
            assert r.status_code == 400, r.text
            assert "does not match" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_byoca_enroll_rejects_private_jwk(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "bc-privjwk")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            mgr = app.state.agent_manager
            cert_pem, key_pem = _issue_cert_from_ca(
                *await _load_org_ca(), subject_cn="priv",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers=await _headers(),
                json={
                    "agent_name": "priv",
                    "cert_pem": cert_pem,
                    "private_key_pem": key_pem,
                    # Private JWK — rejected to prevent accidental key leak
                    # via admin log / memory dump.
                    "dpop_jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "SECRET"},
                },
            )
            assert r.status_code == 400, r.text
            assert "private material" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_byoca_enroll_duplicate_agent_returns_409(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "bc-dup")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            mgr = app.state.agent_manager
            cert_pem, key_pem = _issue_cert_from_ca(
                *await _load_org_ca(), subject_cn="twice",
            )
            body = {
                "agent_name": "twice",
                "cert_pem": cert_pem,
                "private_key_pem": key_pem,
            }
            r1 = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers=await _headers(), json=body,
            )
            assert r1.status_code == 201
            r2 = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers=await _headers(), json=body,
            )
            assert r2.status_code == 409
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_byoca_enroll_refuses_without_admin_secret(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "bc-noauth")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            mgr = app.state.agent_manager
            cert_pem, key_pem = _issue_cert_from_ca(
                *await _load_org_ca(), subject_cn="noauth",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/byoca",
                headers={"X-Admin-Secret": "wrong"},
                json={
                    "agent_name": "noauth",
                    "cert_pem": cert_pem,
                    "private_key_pem": key_pem,
                },
            )
            assert r.status_code == 403
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
