"""ADR-011 Phase 1c — ``/v1/admin/agents/enroll/spiffe``.

Covers:
  - Happy path: SVID signed by body-supplied trust bundle → 201 with
    pinned ``spiffe_id`` and ``enrollment_method='spiffe'``
  - Trust bundle resolved from ``proxy_config.spire_trust_bundle`` when
    body omits ``trust_bundle_pem``
  - SVID without SPIFFE URI SAN → 400 (not an SVID)
  - SVID signed by a bundle OTHER than the configured one → 400
  - Missing trust bundle (neither body nor config) → 503
  - ``svid_key_pem`` does not match SVID public key → 400
  - Duplicate agent → 409
  - ``dpop_jwk`` pins RFC 7638 jkt
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


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


def _make_trust_bundle(cn: str = "spire-test-ca") -> tuple[str, str, x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Mint a self-signed root CA that stands in for the SPIRE trust bundle.

    Returns ``(bundle_pem, key_pem, bundle_cert, bundle_key)`` — callers
    keep the private parts to issue SVID leaves underneath.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    bundle_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return bundle_pem, key_pem, cert, key


def _issue_svid(
    bundle_cert: x509.Certificate,
    bundle_key: ec.EllipticCurvePrivateKey,
    *,
    spiffe_uri: str | None,
    cn: str = "svid-leaf",
) -> tuple[str, str]:
    """Issue an SVID signed by the trust bundle CA. ``spiffe_uri=None``
    produces a plain cert without the URI SAN (used to prove rejection)."""
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(bundle_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
        )
    )
    if spiffe_uri:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)]),
            critical=False,
        )
    cert = builder.sign(bundle_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


async def _fetch_row(agent_id: str) -> dict:
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT enrollment_method, spiffe_id, dpop_jkt, cert_pem "
                 "FROM internal_agents WHERE agent_id = :aid"),
            {"aid": agent_id},
        )).first()
    assert row is not None, f"missing row {agent_id}"
    return {"enrollment_method": row[0], "spiffe_id": row[1],
            "dpop_jkt": row[2], "cert_pem": row[3]}


# ── happy paths ──────────────────────────────────────────────────────────

async def test_spiffe_enroll_happy_path_with_body_bundle(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sp-happy")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            bundle_pem, _, bundle_cert, bundle_key = _make_trust_bundle()
            spiffe = "spiffe://sp-happy.test/agent/alice"
            svid_pem, svid_key_pem = _issue_svid(
                bundle_cert, bundle_key, spiffe_uri=spiffe, cn="alice",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(),
                json={
                    "agent_name": "alice",
                    "capabilities": ["order.read"],
                    "svid_pem": svid_pem,
                    "svid_key_pem": svid_key_pem,
                    "trust_bundle_pem": bundle_pem,
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["agent_id"] == "sp-happy::alice"
            assert body["spiffe_id"] == spiffe
            # ADR-014 PR-C: no api_key minted — the SVID is the credential.
            assert "api_key" not in body

            row = await _fetch_row("sp-happy::alice")
            assert row["enrollment_method"] == "spiffe"
            assert row["spiffe_id"] == spiffe
            assert row["cert_pem"] == svid_pem
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_spiffe_enroll_uses_proxy_config_bundle_when_body_omits_it(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sp-config")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            bundle_pem, _, bundle_cert, bundle_key = _make_trust_bundle()
            # Persist the bundle in proxy_config so the endpoint can
            # resolve it without a per-request override.
            from mcp_proxy.db import set_config
            await set_config("spire_trust_bundle", bundle_pem)

            spiffe = "spiffe://sp-config.test/bob"
            svid_pem, svid_key_pem = _issue_svid(
                bundle_cert, bundle_key, spiffe_uri=spiffe, cn="bob",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(),
                json={
                    "agent_name": "bob",
                    "svid_pem": svid_pem,
                    "svid_key_pem": svid_key_pem,
                    # No trust_bundle_pem — endpoint falls back to config.
                },
            )
            assert r.status_code == 201, r.text
            assert r.json()["spiffe_id"] == spiffe
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_spiffe_enroll_pins_dpop_jkt_when_jwk_supplied(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sp-dpop")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            bundle_pem, _, bundle_cert, bundle_key = _make_trust_bundle()
            spiffe = "spiffe://sp-dpop.test/agent/carol"
            svid_pem, svid_key_pem = _issue_svid(
                bundle_cert, bundle_key, spiffe_uri=spiffe, cn="carol",
            )
            dpop_key = ec.generate_private_key(ec.SECP256R1())
            pub = dpop_key.public_key().public_numbers()
            import base64
            def b64u(n: int) -> str:
                return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()
            dpop_jwk = {"kty": "EC", "crv": "P-256",
                        "x": b64u(pub.x), "y": b64u(pub.y)}
            r = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(),
                json={
                    "agent_name": "carol",
                    "svid_pem": svid_pem,
                    "svid_key_pem": svid_key_pem,
                    "trust_bundle_pem": bundle_pem,
                    "dpop_jwk": dpop_jwk,
                },
            )
            assert r.status_code == 201, r.text
            assert r.json()["dpop_jkt"] is not None
            row = await _fetch_row("sp-dpop::carol")
            assert row["dpop_jkt"] == r.json()["dpop_jkt"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── rejection paths ──────────────────────────────────────────────────────

async def test_spiffe_enroll_rejects_cert_without_spiffe_uri(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sp-no-uri")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            bundle_pem, _, bundle_cert, bundle_key = _make_trust_bundle()
            # SVID without URI SAN — technically valid cert, but not an SVID.
            svid_pem, svid_key_pem = _issue_svid(
                bundle_cert, bundle_key, spiffe_uri=None, cn="no-uri",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(),
                json={
                    "agent_name": "nouri",
                    "svid_pem": svid_pem,
                    "svid_key_pem": svid_key_pem,
                    "trust_bundle_pem": bundle_pem,
                },
            )
            assert r.status_code == 400, r.text
            assert "no SPIFFE URI" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_spiffe_enroll_rejects_svid_signed_by_wrong_bundle(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sp-wrong")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            bundle_A_pem, _, _, _ = _make_trust_bundle(cn="trust-A")
            _, _, bundle_B_cert, bundle_B_key = _make_trust_bundle(cn="trust-B")
            # SVID signed by B, submitted against bundle A.
            svid_pem, svid_key_pem = _issue_svid(
                bundle_B_cert, bundle_B_key,
                spiffe_uri="spiffe://other.test/agent/rogue", cn="rogue",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(),
                json={
                    "agent_name": "rogue",
                    "svid_pem": svid_pem,
                    "svid_key_pem": svid_key_pem,
                    "trust_bundle_pem": bundle_A_pem,
                },
            )
            assert r.status_code == 400, r.text
            assert "trust bundle" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_spiffe_enroll_503_when_no_bundle_configured(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sp-none")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            bundle_pem, _, bundle_cert, bundle_key = _make_trust_bundle()
            svid_pem, svid_key_pem = _issue_svid(
                bundle_cert, bundle_key,
                spiffe_uri="spiffe://sp-none.test/x", cn="x",
            )
            # No body bundle, no proxy_config row.
            r = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(),
                json={
                    "agent_name": "nobundle",
                    "svid_pem": svid_pem,
                    "svid_key_pem": svid_key_pem,
                },
            )
            assert r.status_code == 503, r.text
            assert "trust bundle not configured" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_spiffe_enroll_rejects_mismatched_key(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sp-mismatch")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            bundle_pem, _, bundle_cert, bundle_key = _make_trust_bundle()
            svid_pem, _ = _issue_svid(
                bundle_cert, bundle_key,
                spiffe_uri="spiffe://sp-mismatch.test/x", cn="x",
            )
            _, wrong_key_pem = _issue_svid(
                bundle_cert, bundle_key,
                spiffe_uri="spiffe://sp-mismatch.test/y", cn="y",
            )
            r = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(),
                json={
                    "agent_name": "mismatch",
                    "svid_pem": svid_pem,
                    "svid_key_pem": wrong_key_pem,
                    "trust_bundle_pem": bundle_pem,
                },
            )
            assert r.status_code == 400, r.text
            assert "does not match" in r.text
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_spiffe_enroll_duplicate_agent_returns_409(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch, "sp-dup")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            bundle_pem, _, bundle_cert, bundle_key = _make_trust_bundle()
            svid_pem, svid_key_pem = _issue_svid(
                bundle_cert, bundle_key,
                spiffe_uri="spiffe://sp-dup.test/twice", cn="twice",
            )
            body = {
                "agent_name": "twice",
                "svid_pem": svid_pem,
                "svid_key_pem": svid_key_pem,
                "trust_bundle_pem": bundle_pem,
            }
            r1 = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(), json=body,
            )
            assert r1.status_code == 201
            r2 = await cli.post(
                "/v1/admin/agents/enroll/spiffe",
                headers=await _headers(), json=body,
            )
            assert r2.status_code == 409
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
