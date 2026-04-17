"""ADR-009 Phase 1 — onboarding pins mastio_pubkey, proxy AgentManager
generates/loads the Mastio CA + leaf identity.

Covers:
  - /v1/onboarding/join accepts and pins a valid ES256 mastio_pubkey
  - /v1/onboarding/join rejects malformed PEM and non-P-256 keys
  - /v1/onboarding/attach pins mastio_pubkey when supplied
  - Legacy org (no mastio_pubkey in payload) keeps column NULL
  - AgentManager.ensure_mastio_identity is idempotent, persists, re-loads
  - Mastio leaf cert chains back to the Org CA via the Mastio CA intermediate
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.config import get_settings
from tests.cert_factory import get_org_ca_pem

pytestmark = pytest.mark.asyncio

ADMIN_SECRET = get_settings().admin_secret


# ── helpers ────────────────────────────────────────────────────────────

def _make_p256_pubkey_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _make_rsa_pubkey_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


async def _generate_invite(client: AsyncClient, label: str = "") -> str:
    resp = await client.post(
        "/v1/admin/invites",
        json={"label": label, "ttl_hours": 72},
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    assert resp.status_code == 201
    return resp.json()["token"]


async def _generate_attach_invite(
    client: AsyncClient, org_id: str, label: str = "",
) -> str:
    resp = await client.post(
        "/v1/admin/invites",
        json={
            "label": label,
            "ttl_hours": 72,
            "invite_type": "attach-ca",
            "linked_org_id": org_id,
        },
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    assert resp.status_code == 201
    return resp.json()["token"]


async def _fetch_mastio_pubkey(org_id: str) -> str | None:
    """Direct DB peek — the router has no getter endpoint in Phase 1."""
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import get_org_by_id

    async with AsyncSessionLocal() as db:
        org = await get_org_by_id(db, org_id)
        assert org is not None, f"org {org_id} not found"
        return org.mastio_pubkey


# ── /join ──────────────────────────────────────────────────────────────

async def test_join_pins_valid_mastio_pubkey(client: AsyncClient):
    invite = await _generate_invite(client, "join-mastio")
    pubkey_pem = _make_p256_pubkey_pem()
    resp = await client.post(
        "/v1/onboarding/join",
        json={
            "org_id": "join-mastio-ok",
            "display_name": "Mastio OK",
            "secret": "join-mastio-ok-secret",
            "ca_certificate": get_org_ca_pem("join-mastio-ok"),
            "invite_token": invite,
            "mastio_pubkey": pubkey_pem,
        },
    )
    assert resp.status_code == 202, resp.text

    stored = await _fetch_mastio_pubkey("join-mastio-ok")
    assert stored == pubkey_pem


async def test_join_without_mastio_pubkey_keeps_null(client: AsyncClient):
    invite = await _generate_invite(client, "join-legacy")
    resp = await client.post(
        "/v1/onboarding/join",
        json={
            "org_id": "join-mastio-legacy",
            "display_name": "Legacy",
            "secret": "join-mastio-legacy-secret",
            "ca_certificate": get_org_ca_pem("join-mastio-legacy"),
            "invite_token": invite,
        },
    )
    assert resp.status_code == 202, resp.text
    assert await _fetch_mastio_pubkey("join-mastio-legacy") is None


async def test_join_rejects_malformed_mastio_pubkey(client: AsyncClient):
    invite = await _generate_invite(client, "join-bad")
    resp = await client.post(
        "/v1/onboarding/join",
        json={
            "org_id": "join-mastio-bad",
            "display_name": "Bad PEM",
            "secret": "x",
            "ca_certificate": get_org_ca_pem("join-mastio-bad"),
            "invite_token": invite,
            "mastio_pubkey": "-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n",
        },
    )
    assert resp.status_code == 400
    assert "mastio_pubkey" in resp.json()["detail"]


async def test_join_rejects_non_p256_mastio_pubkey(client: AsyncClient):
    invite = await _generate_invite(client, "join-rsa")
    resp = await client.post(
        "/v1/onboarding/join",
        json={
            "org_id": "join-mastio-rsa",
            "display_name": "RSA rejected",
            "secret": "x",
            "ca_certificate": get_org_ca_pem("join-mastio-rsa"),
            "invite_token": invite,
            "mastio_pubkey": _make_rsa_pubkey_pem(),
        },
    )
    assert resp.status_code == 400
    assert "P-256" in resp.json()["detail"]


# ── /attach ────────────────────────────────────────────────────────────

async def test_attach_pins_mastio_pubkey(client: AsyncClient):
    # Create an org shell with no CA yet, then attach via invite.
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import register_org

    async with AsyncSessionLocal() as db:
        await register_org(
            db,
            org_id="attach-mastio",
            display_name="Attach Mastio",
            secret="placeholder",
        )

    # Generate an attach-ca invite bound to this org.
    resp_invite = await client.post(
        "/v1/admin/orgs/attach-mastio/attach-invite",
        json={"ttl_hours": 24},
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    assert resp_invite.status_code == 201, resp_invite.text
    attach_token = resp_invite.json()["token"]

    pubkey_pem = _make_p256_pubkey_pem()
    resp = await client.post(
        "/v1/onboarding/attach",
        json={
            "ca_certificate": get_org_ca_pem("attach-mastio"),
            "invite_token": attach_token,
            "secret": "attach-mastio-new-secret",
            "mastio_pubkey": pubkey_pem,
        },
    )
    assert resp.status_code == 200, resp.text
    assert await _fetch_mastio_pubkey("attach-mastio") == pubkey_pem


# ── AgentManager mastio identity ───────────────────────────────────────

async def test_agent_manager_generates_and_reloads_mastio(tmp_path, monkeypatch):
    """ensure_mastio_identity generates on first call, reloads on second."""
    db_file = tmp_path / "mgr.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "mgr-org")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")

    from mcp_proxy.config import get_settings as _get_settings
    _get_settings.cache_clear()

    from mcp_proxy.db import init_db
    await init_db(f"sqlite+aiosqlite:///{db_file}")

    from mcp_proxy.egress.agent_manager import AgentManager

    mgr = AgentManager(org_id="mgr-org", trust_domain="cullis.test")
    await mgr.generate_org_ca()
    assert mgr.ca_loaded

    # First call — generates fresh.
    await mgr.ensure_mastio_identity()
    assert mgr.mastio_loaded
    cert_pem, key_pem = mgr.get_mastio_credentials()
    leaf = x509.load_pem_x509_certificate(cert_pem.encode())
    first_serial = leaf.serial_number

    # Second call — must re-load, not re-mint.
    mgr2 = AgentManager(org_id="mgr-org", trust_domain="cullis.test")
    await mgr2.load_org_ca_from_config()
    await mgr2.ensure_mastio_identity()
    cert_pem_2, _ = mgr2.get_mastio_credentials()
    leaf2 = x509.load_pem_x509_certificate(cert_pem_2.encode())
    assert leaf2.serial_number == first_serial

    # Leaf pubkey export is EC P-256.
    pub_pem = mgr.get_mastio_pubkey_pem()
    pub = serialization.load_pem_public_key(pub_pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert isinstance(pub.curve, ec.SECP256R1)

    _get_settings.cache_clear()


async def test_mastio_leaf_chains_to_org_ca(tmp_path, monkeypatch):
    """The Mastio leaf's issuer matches the Mastio CA; Mastio CA is signed
    by the Org CA. No external chain verifier — we check the names + the
    Mastio CA sig with cryptography."""
    db_file = tmp_path / "chain.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}",
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "chain-org")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")

    from mcp_proxy.config import get_settings as _get_settings
    _get_settings.cache_clear()

    from mcp_proxy.db import init_db
    await init_db(f"sqlite+aiosqlite:///{db_file}")

    from mcp_proxy.egress.agent_manager import AgentManager
    from mcp_proxy.db import get_config

    mgr = AgentManager(org_id="chain-org", trust_domain="cullis.test")
    await mgr.generate_org_ca()
    await mgr.ensure_mastio_identity()

    leaf_pem, _ = mgr.get_mastio_credentials()
    leaf = x509.load_pem_x509_certificate(leaf_pem.encode())

    mastio_ca_pem = await get_config("mastio_ca_cert")
    mastio_ca = x509.load_pem_x509_certificate(mastio_ca_pem.encode())

    org_ca_pem = await get_config("org_ca_cert")
    org_ca = x509.load_pem_x509_certificate(org_ca_pem.encode())

    # Leaf issuer == Mastio CA subject.
    assert leaf.issuer == mastio_ca.subject
    # Mastio CA issuer == Org CA subject.
    assert mastio_ca.issuer == org_ca.subject

    # Mastio CA is a CA with pathLen=0.
    bc = mastio_ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0

    # Verify the Org CA's signature over the Mastio CA.
    org_ca.public_key().verify(
        mastio_ca.signature,
        mastio_ca.tbs_certificate_bytes,
        padding=__import__(
            "cryptography.hazmat.primitives.asymmetric.padding",
            fromlist=["PKCS1v15"],
        ).PKCS1v15(),
        algorithm=mastio_ca.signature_hash_algorithm,
    )

    # Leaf SAN is spiffe://.../proxy/chain-org.
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    uris = list(san.get_values_for_type(x509.UniformResourceIdentifier))
    assert "spiffe://cullis.test/proxy/chain-org" in uris

    _get_settings.cache_clear()
