"""Fase B — Court ``POST /v1/federation/publish-stats`` endpoint.

The Mastio pushes aggregate fleet counters (active agents, total agents,
enabled backends) so the Court dashboard can render per-org telemetry
without knowing individual agents. Auth mirrors publish-agent: ADR-009
counter-signature against the pinned ``mastio_pubkey``.

Covers:
  - Happy path: pinned pubkey + valid counter-sig → metadata_json["stats"]
    is populated with the counters + updated_at timestamp
  - Re-push overwrites the prior snapshot (last-writer-wins)
  - Missing or wrong counter-sig → 403 + audit
  - Unknown org → 404
  - Org without pinned mastio_pubkey → 403 + audit
  - Payload validation: negative counts rejected by pydantic
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import AsyncClient

from tests.conftest import ADMIN_HEADERS

pytestmark = [pytest.mark.asyncio, pytest.mark.mastio_strict]


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
    client: AsyncClient, org_id: str, mastio_pubkey_pem: str | None,
) -> None:
    """Create an org + pin the mastio pubkey (skipped if None).

    Stats don't need the CA attached — they never reference a cert chain.
    Keep the onboarding minimal so tests focus on the endpoint behavior.
    """
    org_secret = f"{org_id}-secret"
    r = await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    assert r.status_code in (201, 409), r.text
    if mastio_pubkey_pem is not None:
        from app.db.database import AsyncSessionLocal
        from app.registry.org_store import update_org_mastio_pubkey
        async with AsyncSessionLocal() as db:
            await update_org_mastio_pubkey(db, org_id, mastio_pubkey_pem)


async def _fetch_stats(org_id: str) -> dict | None:
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import get_org_by_id
    async with AsyncSessionLocal() as db:
        org = await get_org_by_id(db, org_id)
        if org is None:
            return None
        meta = json.loads(org.metadata_json or "{}")
        return meta.get("stats")


# ── happy path ─────────────────────────────────────────────────────────


async def test_publish_stats_stores_counters(client: AsyncClient):
    priv, pub = _gen_mastio_keypair()
    org_id = "stats-ok"
    await _onboard_org_with_mastio(client, org_id, pub)

    body = {
        "org_id": org_id,
        "agent_active_count": 7,
        "agent_total_count": 10,
        "backend_count": 3,
    }
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-stats",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-Cullis-Mastio-Signature": _sign(priv, raw),
        },
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["org_id"] == org_id
    assert payload["stored_at"]

    stats = await _fetch_stats(org_id)
    assert stats is not None
    assert stats["agent_active_count"] == 7
    assert stats["agent_total_count"] == 10
    assert stats["backend_count"] == 3
    assert stats["updated_at"] == payload["stored_at"]


async def test_publish_stats_overwrites_prior_snapshot(client: AsyncClient):
    priv, pub = _gen_mastio_keypair()
    org_id = "stats-overwrite"
    await _onboard_org_with_mastio(client, org_id, pub)

    async def _push(active: int, total: int, backends: int) -> str:
        body = {
            "org_id": org_id, "agent_active_count": active,
            "agent_total_count": total, "backend_count": backends,
        }
        raw = json.dumps(body).encode()
        r = await client.post(
            "/v1/federation/publish-stats",
            content=raw,
            headers={"Content-Type": "application/json",
                     "X-Cullis-Mastio-Signature": _sign(priv, raw)},
        )
        assert r.status_code == 200, r.text
        return r.json()["stored_at"]

    first_ts = await _push(1, 1, 0)
    second_ts = await _push(5, 8, 2)

    stats = await _fetch_stats(org_id)
    assert stats["agent_active_count"] == 5
    assert stats["agent_total_count"] == 8
    assert stats["backend_count"] == 2
    # Overwrite — only the latest push is kept.
    assert stats["updated_at"] == second_ts
    assert first_ts != second_ts


async def test_publish_stats_preserves_unrelated_metadata(client: AsyncClient):
    """Injecting ``stats`` must not wipe out other metadata_json keys."""
    priv, pub = _gen_mastio_keypair()
    org_id = "stats-preserve"
    await _onboard_org_with_mastio(client, org_id, pub)

    # Seed an unrelated key the Court cares about.
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import get_org_by_id
    async with AsyncSessionLocal() as db:
        org = await get_org_by_id(db, org_id)
        org.metadata_json = json.dumps({"custom_tag": "keep-me"})
        await db.commit()

    body = {
        "org_id": org_id, "agent_active_count": 2,
        "agent_total_count": 2, "backend_count": 1,
    }
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-stats",
        content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )
    assert r.status_code == 200, r.text

    async with AsyncSessionLocal() as db:
        org = await get_org_by_id(db, org_id)
        meta = json.loads(org.metadata_json)
    assert meta["custom_tag"] == "keep-me"
    assert meta["stats"]["agent_active_count"] == 2


# ── auth failures ──────────────────────────────────────────────────────


async def test_publish_stats_missing_signature_rejected(client: AsyncClient):
    _, pub = _gen_mastio_keypair()
    org_id = "stats-no-sig"
    await _onboard_org_with_mastio(client, org_id, pub)

    body = {"org_id": org_id, "agent_active_count": 1,
            "agent_total_count": 1, "backend_count": 0}
    r = await client.post(
        "/v1/federation/publish-stats",
        content=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )
    # verify_mastio_countersig raises 403 when header is absent.
    assert r.status_code == 403, r.text
    assert await _fetch_stats(org_id) is None


async def test_publish_stats_wrong_signature_rejected(client: AsyncClient):
    _, pinned_pub = _gen_mastio_keypair()
    attacker_priv, _ = _gen_mastio_keypair()
    org_id = "stats-bad-sig"
    await _onboard_org_with_mastio(client, org_id, pinned_pub)

    body = {"org_id": org_id, "agent_active_count": 1,
            "agent_total_count": 1, "backend_count": 0}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-stats",
        content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(attacker_priv, raw)},
    )
    assert r.status_code == 403, r.text
    assert await _fetch_stats(org_id) is None


# ── org lookup failures ────────────────────────────────────────────────


async def test_publish_stats_unknown_org_404(client: AsyncClient):
    priv, _ = _gen_mastio_keypair()
    body = {"org_id": "ghost-org", "agent_active_count": 0,
            "agent_total_count": 0, "backend_count": 0}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-stats",
        content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )
    assert r.status_code == 404, r.text


async def test_publish_stats_unpinned_mastio_pubkey_403(client: AsyncClient):
    priv, _ = _gen_mastio_keypair()
    org_id = "stats-unpinned"
    # Create the org but DON'T pin the pubkey — onboarding is incomplete.
    await _onboard_org_with_mastio(client, org_id, mastio_pubkey_pem=None)

    body = {"org_id": org_id, "agent_active_count": 0,
            "agent_total_count": 0, "backend_count": 0}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-stats",
        content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )
    assert r.status_code == 403, r.text
    assert "mastio_pubkey" in r.json()["detail"]


# ── payload validation ─────────────────────────────────────────────────


async def test_publish_stats_negative_count_rejected(client: AsyncClient):
    priv, pub = _gen_mastio_keypair()
    org_id = "stats-negative"
    await _onboard_org_with_mastio(client, org_id, pub)

    body = {"org_id": org_id, "agent_active_count": -1,
            "agent_total_count": 0, "backend_count": 0}
    raw = json.dumps(body).encode()
    r = await client.post(
        "/v1/federation/publish-stats",
        content=raw,
        headers={"Content-Type": "application/json",
                 "X-Cullis-Mastio-Signature": _sign(priv, raw)},
    )
    assert r.status_code == 422, r.text
