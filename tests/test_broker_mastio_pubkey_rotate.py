"""ADR-012 Phase 2.1 — Court ``POST /v1/onboarding/orgs/{id}/mastio-pubkey/rotate``.

Covers:
  - Happy path: valid continuity proof signed by the pinned old pubkey
    → new pubkey accepted, audit event recorded, old pubkey replaced.
  - Rotation on a brand-new org without a pinned pubkey → 409 Conflict.
  - Rotation against an unknown org → 404.
  - Proof signed by a different (foreign) key → 401.
  - Proof envelope tamper: ``new_pubkey_pem`` mismatch between the
    JSON body and the signed proof → 400.
  - Stale proof (issued > freshness window in the past) → 401.
  - Malformed proof body → 400.

The tests import ``build_proof`` from the proxy package to make sure
the two codebases agree on the canonical format (the proxy module
produces proofs, the broker module consumes them — a format drift
would surface here).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import AsyncClient

from app.config import get_settings
from mcp_proxy.auth.local_keystore import compute_kid
from mcp_proxy.auth.mastio_rotation import build_proof
from tests.cert_factory import get_org_ca_pem

pytestmark = pytest.mark.asyncio

ADMIN_SECRET = get_settings().admin_secret


def _gen_p256_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


async def _create_org_with_pubkey(
    client: AsyncClient, org_id: str, pubkey_pem: str,
) -> None:
    """Onboard an org and pin ``pubkey_pem`` as its mastio_pubkey."""
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
    r = await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-pubkey",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"mastio_pubkey": pubkey_pem},
    )
    assert r.status_code == 200, r.text


async def _fetch_pubkey(org_id: str) -> str | None:
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import get_org_by_id
    async with AsyncSessionLocal() as db:
        org = await get_org_by_id(db, org_id)
        return org.mastio_pubkey if org else None


# ── happy path ────────────────────────────────────────────────────────


async def test_rotate_replaces_pinned_pubkey_with_valid_proof(client: AsyncClient):
    old_priv, old_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "rotate-ok", old_pub)

    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    r = await client.post(
        "/v1/onboarding/orgs/rotate-ok/mastio-pubkey/rotate",
        json={
            "new_pubkey_pem": new_pub,
            "proof": proof.to_dict(),
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["org_id"] == "rotate-ok"
    assert body["new_kid"] == compute_kid(new_pub)
    assert "rotated_at" in body

    stored = await _fetch_pubkey("rotate-ok")
    assert stored == new_pub


async def test_rotate_rejects_unknown_org(client: AsyncClient):
    old_priv, old_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    r = await client.post(
        "/v1/onboarding/orgs/does-not-exist/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
    )
    assert r.status_code == 404


async def test_rotate_rejects_org_without_pinned_pubkey(client: AsyncClient):
    """If no pubkey is pinned yet the org should use the admin
    first-pin flow, not rotation."""
    old_priv, old_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    # Onboard org WITHOUT pinning a pubkey.
    invite = await client.post(
        "/v1/admin/invites",
        json={"label": "no-pin", "ttl_hours": 1},
        headers={"x-admin-secret": ADMIN_SECRET},
    )
    token = invite.json()["token"]
    await client.post("/v1/onboarding/join", json={
        "org_id": "no-pin",
        "display_name": "no-pin",
        "secret": "no-pin-secret",
        "ca_certificate": get_org_ca_pem("no-pin"),
        "invite_token": token,
    })

    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    r = await client.post(
        "/v1/onboarding/orgs/no-pin/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
    )
    assert r.status_code == 409
    assert "admin flow" in r.json()["detail"].lower()


async def test_rotate_rejects_proof_signed_by_foreign_key(client: AsyncClient):
    _, old_pub = _gen_p256_keypair()
    foreign_priv, foreign_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "rotate-foreign", old_pub)

    # Proof signed by a key that is NOT the pinned one.
    proof = build_proof(
        old_priv_key=foreign_priv,
        old_kid=compute_kid(foreign_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    r = await client.post(
        "/v1/onboarding/orgs/rotate-foreign/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
    )
    # The old_kid embedded in the proof is the foreign one; the Court
    # rejects for kid mismatch (signature would fail too — either
    # condition is enough).
    assert r.status_code == 401
    # Audit H-IO-2 — the broker now masks the specific reason
    # (kid mismatch vs signature failure) on the wire; the audit row
    # still carries it for ops triage. This test asserts the contract
    # at the wire boundary: any continuity proof failure is a 401 with
    # the generic prefix.
    assert "continuity proof rejected" in r.json()["detail"].lower()

    # Pin unchanged.
    stored = await _fetch_pubkey("rotate-foreign")
    assert stored == old_pub


async def test_rotate_rejects_envelope_tamper(client: AsyncClient):
    """Attacker replays a valid proof but swaps ``new_pubkey_pem`` in
    the request body for a pubkey they control. The Court must detect
    the envelope/proof mismatch even though the signature itself is
    valid over the original ``new_pubkey_pem``."""
    old_priv, old_pub = _gen_p256_keypair()
    _, intended_pub = _gen_p256_keypair()
    _, evil_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "rotate-tamper", old_pub)

    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(intended_pub),
        new_pubkey_pem=intended_pub,
    )
    r = await client.post(
        "/v1/onboarding/orgs/rotate-tamper/mastio-pubkey/rotate",
        json={"new_pubkey_pem": evil_pub, "proof": proof.to_dict()},
    )
    assert r.status_code == 400
    assert "does not match" in r.json()["detail"].lower()
    stored = await _fetch_pubkey("rotate-tamper")
    assert stored == old_pub


async def test_rotate_rejects_stale_proof(client: AsyncClient):
    old_priv, old_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "rotate-stale", old_pub)

    stale_when = datetime.now(timezone.utc) - timedelta(hours=2)
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
        issued_at=stale_when,
    )
    r = await client.post(
        "/v1/onboarding/orgs/rotate-stale/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": proof.to_dict()},
    )
    assert r.status_code == 401
    # Audit H-IO-2 — wire detail is generic; freshness specifics live
    # in the audit log only.
    assert "continuity proof rejected" in r.json()["detail"].lower()


async def test_rotate_rejects_malformed_proof(client: AsyncClient):
    _, old_pub = _gen_p256_keypair()
    _, new_pub = _gen_p256_keypair()
    await _create_org_with_pubkey(client, "rotate-malformed", old_pub)

    r = await client.post(
        "/v1/onboarding/orgs/rotate-malformed/mastio-pubkey/rotate",
        json={"new_pubkey_pem": new_pub, "proof": {"old_kid": "only-this"}},
    )
    assert r.status_code == 400
    # Audit H-IO-2 — the parser's "missing field X" detail no longer
    # leaks through; only the generic prefix.
    assert "malformed proof" in r.json()["detail"].lower()
