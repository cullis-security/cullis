"""ADR-009 Phase 2 PR 2b — Court admin endpoint for pinning the mastio
public key on an existing org (post-proxy-boot flow).

Covers:
  - PATCH /v1/admin/orgs/{id}/mastio-pubkey under admin secret pins a
    valid EC P-256 PEM
  - Clear with body {mastio_pubkey: null} reverts to legacy
  - Non-P-256 key rejected (400)
  - Malformed PEM rejected (400)
  - Missing admin secret → 403
  - Unknown org → 404
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.config import get_settings
from tests.cert_factory import get_org_ca_pem

pytestmark = pytest.mark.asyncio

ADMIN_SECRET = get_settings().admin_secret


def _gen_p256_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _gen_rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


async def _create_org(client: AsyncClient, org_id: str) -> None:
    """Create an org with CA — mirror the onboarding flow used by sandbox."""
    invite = await client.post(
        "/v1/admin/invites",
        json={"label": org_id, "ttl_hours": 1},
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    token = invite.json()["token"]
    await client.post("/v1/onboarding/join", json={
        "org_id": org_id,
        "display_name": org_id,
        "secret": f"{org_id}-secret",
        "ca_certificate": get_org_ca_pem(org_id),
        "invite_token": token,
    })


async def _fetch_pubkey(org_id: str) -> str | None:
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import get_org_by_id
    async with AsyncSessionLocal() as db:
        org = await get_org_by_id(db, org_id)
        return org.mastio_pubkey if org else None


# ── happy path ─────────────────────────────────────────────────────────

async def test_patch_pins_mastio_pubkey(client: AsyncClient):
    await _create_org(client, "patch-ok")
    pem = _gen_p256_pem()
    r = await client.patch(
        "/v1/admin/orgs/patch-ok/mastio-pubkey",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"mastio_pubkey": pem},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["org_id"] == "patch-ok"
    assert body["mastio_pubkey_set"] is True
    assert await _fetch_pubkey("patch-ok") == pem


async def test_patch_clear_reverts_to_legacy(client: AsyncClient):
    await _create_org(client, "patch-clear")
    pem = _gen_p256_pem()
    await client.patch(
        "/v1/admin/orgs/patch-clear/mastio-pubkey",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"mastio_pubkey": pem},
    )
    r = await client.patch(
        "/v1/admin/orgs/patch-clear/mastio-pubkey",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"mastio_pubkey": None},
    )
    assert r.status_code == 200
    assert r.json()["mastio_pubkey_set"] is False
    assert await _fetch_pubkey("patch-clear") is None


# ── validation ─────────────────────────────────────────────────────────

async def test_patch_rejects_rsa(client: AsyncClient):
    await _create_org(client, "patch-rsa")
    r = await client.patch(
        "/v1/admin/orgs/patch-rsa/mastio-pubkey",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"mastio_pubkey": _gen_rsa_pem()},
    )
    assert r.status_code == 400
    assert "P-256" in r.json()["detail"]


async def test_patch_rejects_malformed_pem(client: AsyncClient):
    await _create_org(client, "patch-bad")
    r = await client.patch(
        "/v1/admin/orgs/patch-bad/mastio-pubkey",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={
            "mastio_pubkey":
                "-----BEGIN PUBLIC KEY-----\nnot-base64\n-----END PUBLIC KEY-----\n",
        },
    )
    assert r.status_code == 400


# ── auth ───────────────────────────────────────────────────────────────

async def test_patch_requires_admin_secret(client: AsyncClient):
    await _create_org(client, "patch-auth")
    r = await client.patch(
        "/v1/admin/orgs/patch-auth/mastio-pubkey",
        headers={"x-admin-secret": "wrong"},
        json={"mastio_pubkey": _gen_p256_pem()},
    )
    assert r.status_code == 403


async def test_patch_unknown_org_returns_404(client: AsyncClient):
    r = await client.patch(
        "/v1/admin/orgs/does-not-exist/mastio-pubkey",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"mastio_pubkey": _gen_p256_pem()},
    )
    assert r.status_code == 404
