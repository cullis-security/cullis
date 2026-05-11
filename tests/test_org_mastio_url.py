"""ADR-029 Phase G — Court endpoints for peer-Mastio URL discovery.

Pins:

- ``PATCH /v1/admin/orgs/{org_id}/mastio-url`` requires admin
  secret, validates the URL is http(s), normalises (strip + drop
  trailing slash), and reflects on subsequent GETs.
- ``GET /v1/federation/orgs/{org_id}/mastio-url`` is unauthenticated
  and returns 404 collapsing 'org unknown' / 'pending' / 'rejected'
  / 'no URL published' into a single response shape.
- Non-active orgs (e.g. pending) never expose a URL even if one was
  written.
"""
from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from tests.conftest import ADMIN_HEADERS, TestSessionLocal

pytestmark = pytest.mark.asyncio


def _unique_org_id(prefix: str = "phaseg") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def _register_org(client: AsyncClient, org_id: str) -> None:
    resp = await client.post(
        "/v1/registry/orgs",
        json={
            "org_id": org_id,
            "display_name": org_id.upper(),
            "secret": f"{org_id}-secret",
        },
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 201, resp.text


# ── PATCH happy paths ────────────────────────────────────────────────


async def test_patch_sets_url_and_normalises(client):
    org_id = _unique_org_id()
    await _register_org(client, org_id)
    resp = await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-url",
        json={"mastio_url": f"  https://{org_id}.local/  "},
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["org_id"] == org_id
    # Trim + trailing slash dropped.
    assert body["mastio_url"] == f"https://{org_id}.local"

    # Round-trip via admin GET.
    resp_get = await client.get(
        f"/v1/registry/orgs/{org_id}", headers=ADMIN_HEADERS,
    )
    assert resp_get.status_code == 200
    assert resp_get.json()["mastio_url"] == f"https://{org_id}.local"


async def test_patch_can_clear_url(client):
    org_id = _unique_org_id()
    await _register_org(client, org_id)
    await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-url",
        json={"mastio_url": f"https://{org_id}.local"},
        headers=ADMIN_HEADERS,
    )
    resp = await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-url",
        json={"mastio_url": None},
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["mastio_url"] is None


# ── PATCH error paths ────────────────────────────────────────────────


async def test_patch_rejects_non_http(client):
    org_id = _unique_org_id()
    await _register_org(client, org_id)
    resp = await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-url",
        json={"mastio_url": "javascript:alert(1)"},
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 422


async def test_patch_without_admin_secret_forbidden(client):
    org_id = _unique_org_id()
    await _register_org(client, org_id)
    resp = await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-url",
        json={"mastio_url": f"https://{org_id}.local"},
        headers={"x-admin-secret": "wrong"},
    )
    assert resp.status_code == 403


async def test_patch_unknown_org_404(client):
    resp = await client.patch(
        "/v1/admin/orgs/ghost-no-exist-12345/mastio-url",
        json={"mastio_url": "https://ghost.local"},
        headers=ADMIN_HEADERS,
    )
    assert resp.status_code == 404


# ── public GET /v1/federation/orgs/{id}/mastio-url ──────────────────


async def test_public_get_returns_url_for_active_org(client):
    org_id = _unique_org_id()
    await _register_org(client, org_id)
    await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-url",
        json={"mastio_url": f"https://{org_id}.local"},
        headers=ADMIN_HEADERS,
    )
    resp = await client.get(f"/v1/federation/orgs/{org_id}/mastio-url")
    assert resp.status_code == 200
    assert resp.json() == {
        "org_id": org_id,
        "mastio_url": f"https://{org_id}.local",
    }


async def test_public_get_unknown_org_404(client):
    resp = await client.get("/v1/federation/orgs/ghost-unknown-9999/mastio-url")
    assert resp.status_code == 404


async def test_public_get_no_url_published_404(client):
    """An org that exists but has not published a URL collapses to the
    same 404 as 'org unknown' — non-enumerable."""
    org_id = _unique_org_id()
    await _register_org(client, org_id)
    resp = await client.get(f"/v1/federation/orgs/{org_id}/mastio-url")
    assert resp.status_code == 404


async def test_public_get_pending_org_404(client):
    """Non-active orgs never expose a URL, even if one was written."""
    org_id = _unique_org_id()
    await _register_org(client, org_id)
    await client.patch(
        f"/v1/admin/orgs/{org_id}/mastio-url",
        json={"mastio_url": f"https://{org_id}.local"},
        headers=ADMIN_HEADERS,
    )
    # Flip the org to 'pending' directly in DB.
    from sqlalchemy import text
    async with TestSessionLocal() as db:
        await db.execute(
            text(f"UPDATE organizations SET status='pending' WHERE org_id='{org_id}'"),
        )
        await db.commit()

    resp = await client.get(f"/v1/federation/orgs/{org_id}/mastio-url")
    assert resp.status_code == 404
