"""ADR-010 Phase 6a-1 — Court federation read endpoints.

Mirrors ``/v1/registry/agents`` GETs under ``/v1/federation/agents``.
These tests validate that behaviour is bit-for-bit equivalent:

  - list scoped to own org (403 when asking another org)
  - search respects capability filter + excludes own org by default
  - public-key fetch requires same-org or an approved binding
  - single-agent fetch follows the same isolation rule

Once every caller has migrated to the new prefix, Phase 6a-4 deletes
the legacy registry routes and we drop the parity guarantee here too.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.cert_factory import get_org_ca_pem
from tests.conftest import ADMIN_HEADERS

pytestmark = pytest.mark.asyncio


async def _setup(client: AsyncClient, org_id: str, agent_id: str,
                 capabilities: list[str], dpop) -> str:
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    await client.post(
        f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": get_org_ca_pem(org_id)},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await client.post("/v1/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": capabilities,
    }, headers={"x-org-id": org_id, "x-org-secret": org_secret})
    resp = await client.post(
        "/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": capabilities},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(
        f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    return await dpop.get_token(client, agent_id, org_id)


# ── list ────────────────────────────────────────────────────────────────

async def test_list_returns_own_org(client: AsyncClient, dpop):
    token = await _setup(
        client, "fr-list-a", "fr-list-a::agent", ["cap.read"], dpop,
    )
    resp = await client.get(
        "/v1/federation/agents",
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp.status_code == 200
    ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "fr-list-a::agent" in ids


async def test_list_rejects_other_org(client: AsyncClient, dpop):
    token = await _setup(
        client, "fr-list-b", "fr-list-b::agent", ["cap.read"], dpop,
    )
    resp = await client.get(
        "/v1/federation/agents",
        params={"org_id": "some-other-org"},
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp.status_code == 403


# ── search ──────────────────────────────────────────────────────────────

async def test_search_finds_cross_org_match(client: AsyncClient, dpop):
    token_buyer = await _setup(
        client, "fr-sup-buy", "fr-sup-buy::agent",
        ["order.read", "order.write"], dpop,
    )
    await _setup(
        client, "fr-sup-sup", "fr-sup-sup::agent",
        ["order.read", "order.write"], dpop,
    )
    resp = await client.get(
        "/v1/federation/agents/search",
        params={"capability": ["order.read", "order.write"]},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token_buyer),
    )
    assert resp.status_code == 200
    ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "fr-sup-sup::agent" in ids


async def test_search_excludes_own_org_by_default(client: AsyncClient, dpop):
    token = await _setup(
        client, "fr-exc-self", "fr-exc-self::agent", ["cap.read"], dpop,
    )
    await _setup(
        client, "fr-exc-other", "fr-exc-other::agent", ["cap.read"], dpop,
    )
    resp = await client.get(
        "/v1/federation/agents/search",
        params={"capability": ["cap.read"]},
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 200
    ids = [a["agent_id"] for a in resp.json()["agents"]]
    assert "fr-exc-self::agent" not in ids
    assert "fr-exc-other::agent" in ids


async def test_search_requires_at_least_one_filter(client: AsyncClient, dpop):
    token = await _setup(
        client, "fr-flt", "fr-flt::agent", ["cap.read"], dpop,
    )
    resp = await client.get(
        "/v1/federation/agents/search",
        headers=dpop.headers("GET", "/v1/federation/agents/search", token),
    )
    assert resp.status_code == 422


# ── public-key ──────────────────────────────────────────────────────────

async def test_public_key_same_org(client: AsyncClient, dpop):
    """Same-org fetch returns 404 when target hasn't logged in (no cert
    pinned) — same contract the legacy ``/v1/registry`` endpoint served."""
    token = await _setup(
        client, "fr-pk-a", "fr-pk-a::caller", ["cap.read"], dpop,
    )
    # Second agent in the same org, never logs in → cert_pem NULL.
    await client.post("/v1/registry/agents", json={
        "agent_id": "fr-pk-a::peer", "org_id": "fr-pk-a",
        "display_name": "peer", "capabilities": ["cap.read"],
    }, headers={"x-org-id": "fr-pk-a", "x-org-secret": "fr-pk-a-secret"})

    resp = await client.get(
        "/v1/federation/agents/fr-pk-a::peer/public-key",
        headers=dpop.headers(
            "GET", "/v1/federation/agents/fr-pk-a::peer/public-key", token,
        ),
    )
    assert resp.status_code == 404


async def test_public_key_cross_org_requires_binding(client: AsyncClient, dpop):
    """Cross-org fetch without any approved binding → 403."""
    token = await _setup(
        client, "fr-pk-caller", "fr-pk-caller::agent", ["cap.read"], dpop,
    )
    # Bootstrap the target org *without* an approved binding: we skip
    # the binding create/approve steps that ``_setup`` does.
    await client.post("/v1/registry/orgs", json={
        "org_id": "fr-pk-no-bind", "display_name": "no-bind",
        "secret": "fr-pk-no-bind-secret",
    }, headers=ADMIN_HEADERS)
    await client.post(
        "/v1/registry/orgs/fr-pk-no-bind/certificate",
        json={"ca_certificate": get_org_ca_pem("fr-pk-no-bind")},
        headers={"x-org-id": "fr-pk-no-bind", "x-org-secret": "fr-pk-no-bind-secret"},
    )
    await client.post("/v1/registry/agents", json={
        "agent_id": "fr-pk-no-bind::agent", "org_id": "fr-pk-no-bind",
        "display_name": "no-bind-agent", "capabilities": ["cap.read"],
    }, headers={"x-org-id": "fr-pk-no-bind", "x-org-secret": "fr-pk-no-bind-secret"})

    resp = await client.get(
        "/v1/federation/agents/fr-pk-no-bind::agent/public-key",
        headers=dpop.headers(
            "GET", "/v1/federation/agents/fr-pk-no-bind::agent/public-key", token,
        ),
    )
    assert resp.status_code == 403


# ── single-agent GET ────────────────────────────────────────────────────

async def test_get_agent_same_org(client: AsyncClient, dpop):
    token = await _setup(
        client, "fr-get", "fr-get::agent", ["cap.read"], dpop,
    )
    resp = await client.get(
        "/v1/federation/agents/fr-get::agent",
        headers=dpop.headers("GET", "/v1/federation/agents/fr-get::agent", token),
    )
    assert resp.status_code == 200
    assert resp.json()["agent_id"] == "fr-get::agent"


async def test_get_agent_unknown_returns_404(client: AsyncClient, dpop):
    token = await _setup(
        client, "fr-404", "fr-404::agent", ["cap.read"], dpop,
    )
    resp = await client.get(
        "/v1/federation/agents/nope::missing",
        headers=dpop.headers("GET", "/v1/federation/agents/nope::missing", token),
    )
    assert resp.status_code == 404


# ── auth ────────────────────────────────────────────────────────────────

async def test_list_requires_auth(client: AsyncClient):
    resp = await client.get("/v1/federation/agents")
    assert resp.status_code in (401, 403)


async def test_search_requires_auth(client: AsyncClient):
    resp = await client.get(
        "/v1/federation/agents/search",
        params={"capability": ["cap.read"]},
    )
    assert resp.status_code in (401, 403)
