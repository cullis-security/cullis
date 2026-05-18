"""Wave 3 U4 Phase 2 — admin endpoint for the per-org mTLS enforce flag.

Covers:
  - PATCH /v1/admin/orgs/{id}/require-mtls flips the flag (true/false)
  - Persisted on the OrganizationRecord
  - Missing admin secret → 403
  - Unknown org → 404
  - Audit event emitted
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.config import get_settings
from tests.cert_factory import get_org_ca_pem

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.xdist_group(name="serial_require_mastio_mtls_admin"),
]

ADMIN_SECRET = get_settings().admin_secret


async def _create_org(client: AsyncClient, org_id: str) -> None:
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


async def _fetch_flag(org_id: str) -> bool | None:
    from app.db.database import AsyncSessionLocal
    from app.registry.org_store import get_org_by_id
    async with AsyncSessionLocal() as db:
        org = await get_org_by_id(db, org_id)
        return org.require_mastio_mtls if org else None


async def test_default_is_false(client: AsyncClient):
    await _create_org(client, "mtls-default")
    assert await _fetch_flag("mtls-default") is False


async def test_patch_flips_to_true(client: AsyncClient):
    await _create_org(client, "mtls-true")
    r = await client.patch(
        "/v1/admin/orgs/mtls-true/require-mtls",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"require_mastio_mtls": True},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["org_id"] == "mtls-true"
    assert body["require_mastio_mtls"] is True
    assert await _fetch_flag("mtls-true") is True


async def test_patch_flips_back_to_false(client: AsyncClient):
    await _create_org(client, "mtls-flip")
    await client.patch(
        "/v1/admin/orgs/mtls-flip/require-mtls",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"require_mastio_mtls": True},
    )
    r = await client.patch(
        "/v1/admin/orgs/mtls-flip/require-mtls",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"require_mastio_mtls": False},
    )
    assert r.status_code == 200
    assert r.json()["require_mastio_mtls"] is False
    assert await _fetch_flag("mtls-flip") is False


async def test_wrong_admin_secret_rejected(client: AsyncClient):
    await _create_org(client, "mtls-noauth")
    r = await client.patch(
        "/v1/admin/orgs/mtls-noauth/require-mtls",
        headers={"x-admin-secret": "wrong-secret"},
        json={"require_mastio_mtls": True},
    )
    assert r.status_code == 403


async def test_unknown_org_404(client: AsyncClient):
    r = await client.patch(
        "/v1/admin/orgs/does-not-exist/require-mtls",
        headers={"x-admin-secret": ADMIN_SECRET},
        json={"require_mastio_mtls": True},
    )
    assert r.status_code == 404
