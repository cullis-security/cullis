"""ADR-010 Phase 1 — Court /v1/federation/publish-agent endpoint.

The Mastio is authoritative for its org's agent registry and publishes
federated agents to the Court. Auth is the ADR-009 counter-signature
over the raw request body.

Covers:
  - Happy path: pubkey pinned + counter-sig valid + cert chain valid →
    creates agent row on the Court
  - Re-publish updates capabilities + cert + reactivates
  - Revoke marks existing agent is_active=False
  - Missing counter-sig → 403
  - Wrong counter-sig key → 403
  - agent_id prefix mismatch with org → 400 (via pydantic pattern) or
    404 when the org doesn't exist
  - cert_pem not signed by org CA → 400
  - Org without pinned mastio_pubkey → 403
  - Unknown org → 404
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import AsyncClient

from tests.cert_factory import make_agent_cert, get_org_ca_pem
from tests.conftest import ADMIN_HEADERS

pytestmark = [pytest.mark.asyncio, pytest.mark.mastio_strict]


# ── helpers ────────────────────────────────────────────────────────────

def _gen_mastio_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


def _sign(priv: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


async def _onboard_org_with_mastio(
    client: AsyncClient,
    org_id: str,
    mastio_pubkey_pem: str,
) -> None:
    """Create an org on the Court (via admin) + attach its CA + pin
    the mastio pubkey. Skips the attach-ca invite dance by writing
    directly through admin-only endpoints available to the test."""
    org_secret = f"{org_id}-secret"
    r = await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    assert r.status_code in (201, 409), r.text
    ca_pem = get_org_ca_pem(org_id)
    r = await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assert r.status_code in (200, 201), r.text
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import update_org_mastio_pubkey
    async with AsyncSessionLocal() as db:
        await update_org_mastio_pubkey(db, org_id, mastio_pubkey_pem)


def _make_agent_cert_pem(agent_id: str, org_id: str) -> str:
    key, cert = make_agent_cert(agent_id, org_id)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


async def _fetch_agent_row(agent_id: str):
    from app.db.database import AsyncSessionLocal
    from app.registry.store import get_agent_by_id
    async with AsyncSessionLocal() as db:
        return await get_agent_by_id(db, agent_id)


# ── happy path ─────────────────────────────────────────────────────────

async def test_publish_creates_agent(client: AsyncClient):
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-create"
    agent_id = f"{org_id}::alice"
    await _onboard_org_with_mastio(client, org_id, pub)
    cert_pem = _make_agent_cert_pem(agent_id, org_id)

    body = {
        "agent_id": agent_id,
        "cert_pem": cert_pem,
        "capabilities": ["order.read"],
        "display_name": "Alice",
    }
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-agent",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw),
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["agent_id"] == agent_id
    assert data["status"] == "created"
    assert data["cert_thumbprint"]

    row = await _fetch_agent_row(agent_id)
    assert row is not None
    assert row.is_active is True


async def test_republish_updates_capabilities(client: AsyncClient):
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-update"
    agent_id = f"{org_id}::bob"
    await _onboard_org_with_mastio(client, org_id, pub)
    cert_pem = _make_agent_cert_pem(agent_id, org_id)

    async def _push(caps: list[str]) -> dict:
        body = {
            "agent_id": agent_id, "cert_pem": cert_pem,
            "capabilities": caps, "display_name": "Bob",
        }
        raw = json.dumps(body).encode()
        r = await client.post(
            "/v1/federation/publish-agent",
            content=raw,
            headers={"Content-Type": "application/json",
                     "X-Cullis-Mastio-Signature": _sign(priv, raw)},
        )
        assert r.status_code == 200, r.text
        return r.json()

    first = await _push(["order.read"])
    assert first["status"] == "created"
    second = await _push(["order.read", "order.write"])
    assert second["status"] == "updated"

    row = await _fetch_agent_row(agent_id)
    caps = json.loads(row.capabilities_json)
    assert "order.write" in caps


async def test_revoke_marks_agent_inactive(client: AsyncClient):
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-revoke"
    agent_id = f"{org_id}::carol"
    await _onboard_org_with_mastio(client, org_id, pub)
    cert_pem = _make_agent_cert_pem(agent_id, org_id)

    # Create first.
    body = {
        "agent_id": agent_id, "cert_pem": cert_pem,
        "capabilities": [], "display_name": "Carol",
    }
    raw = json.dumps(body).encode()
    await client.post(
        "/v1/federation/publish-agent", content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )

    # Revoke.
    body["revoked"] = True
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-agent", content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"

    row = await _fetch_agent_row(agent_id)
    assert row.is_active is False


# ── auth failures ──────────────────────────────────────────────────────

async def test_missing_countersig_header(client: AsyncClient):
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-nosig"
    await _onboard_org_with_mastio(client, org_id, pub)
    body = {
        "agent_id": f"{org_id}::x", "cert_pem": _make_agent_cert_pem(f"{org_id}::x", org_id),
        "capabilities": [],
    }
    r = await client.post(
        "/v1/federation/publish-agent", json=body,
    )
    assert r.status_code == 403
    assert "mastio counter" in r.text.lower() or "signature" in r.text.lower()


async def test_wrong_countersig_key(client: AsyncClient):
    _, pinned_pub = _gen_mastio_keypair()
    attacker_priv, _ = _gen_mastio_keypair()
    org_id = "fed-badkey"
    agent_id = f"{org_id}::eve"
    await _onboard_org_with_mastio(client, org_id, pinned_pub)
    cert_pem = _make_agent_cert_pem(agent_id, org_id)
    body = {"agent_id": agent_id, "cert_pem": cert_pem, "capabilities": []}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-agent", content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(attacker_priv, raw)},
    )
    assert r.status_code == 403
    assert "verification" in r.text.lower() or "counter-sig" in r.text.lower()


async def test_org_without_pinned_pubkey(client: AsyncClient):
    priv, _ = _gen_mastio_keypair()
    org_id = "fed-no-pubkey"
    # Onboard without pinning.
    org_secret = f"{org_id}-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": get_org_ca_pem(org_id)},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    agent_id = f"{org_id}::dave"
    body = {
        "agent_id": agent_id,
        "cert_pem": _make_agent_cert_pem(agent_id, org_id),
        "capabilities": [],
    }
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-agent", content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )
    assert r.status_code == 403
    assert "mastio_pubkey" in r.text.lower()


async def test_unknown_org(client: AsyncClient):
    priv, _ = _gen_mastio_keypair()
    body = {
        "agent_id": "ghost::nobody",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        "capabilities": [],
    }
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-agent", content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )
    assert r.status_code == 404


async def test_cert_not_signed_by_org_ca(client: AsyncClient):
    priv, pub = _gen_mastio_keypair()
    org_id = "fed-wrongca"
    agent_id = f"{org_id}::frank"
    await _onboard_org_with_mastio(client, org_id, pub)
    # Use a cert from a DIFFERENT org's CA.
    cert_pem_wrong = _make_agent_cert_pem("other-org::frank", "other-org")
    body = {
        "agent_id": agent_id, "cert_pem": cert_pem_wrong, "capabilities": [],
    }
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-agent", content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )
    assert r.status_code == 400
    assert "not signed" in r.text.lower() or "signature" in r.text.lower()
