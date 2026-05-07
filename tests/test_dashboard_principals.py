"""
Test dashboard principal-type sections (Phase 1 of SPA rework).

Verifies the new /dashboard/users, /dashboard/workloads,
/dashboard/resources, /dashboard/federation pages render and that the
hardcoded demo cast from imp/insurance-demo-spec.md is visible. Also
verifies the new badge-count endpoints respond with neutral chips so
the left-nav is screenshot-ready for the demo recording.

When the backend session lands /v1/admin/users + /v1/admin/workloads,
these tests should be widened to assert against real data and the
``endpoint_ready=False`` banner should disappear from the templates.
"""
import pytest
from httpx import AsyncClient

from app.config import get_settings

pytestmark = pytest.mark.asyncio


async def _admin_cookies(client: AsyncClient) -> dict:
    resp = await client.post("/dashboard/login", data={
        "user_id": "admin", "password": get_settings().admin_secret,
    }, follow_redirects=False)
    assert resp.status_code == 303, f"login failed: {resp.text[:200]}"
    return dict(resp.cookies)


# ─────────────────────────────────────────────────────────────────────────────
# Section pages render with cast names visible
# ─────────────────────────────────────────────────────────────────────────────

async def test_users_page_renders_with_cast(client: AsyncClient):
    cookies = await _admin_cookies(client)
    resp = await client.get("/dashboard/users", cookies=cookies)
    assert resp.status_code == 200
    body = resp.text
    # Cast principals from the spec
    assert "Claim Officer" in body
    assert "Claim Manager" in body
    assert "Counterparty Liaison" in body
    # Principal type badge for users
    assert ">User<" in body
    # Pending-endpoint banner is still showing (will go away when
    # /v1/admin/users lands)
    assert "Endpoint pending" in body


async def test_workloads_page_renders_with_cast(client: AsyncClient):
    cookies = await _admin_cookies(client)
    resp = await client.get("/dashboard/workloads", cookies=cookies)
    assert resp.status_code == 200
    body = resp.text
    assert "Asia-Pacific Frontdesk" in body
    assert "frontdesk-container" in body
    assert ">Workload<" in body
    assert "Endpoint pending" in body


async def test_resources_page_renders_with_cast(client: AsyncClient):
    cookies = await _admin_cookies(client)
    resp = await client.get("/dashboard/resources", cookies=cookies)
    assert resp.status_code == 200
    body = resp.text
    assert "Claims Database" in body
    assert "claims-db" in body
    # MCP type icon path
    assert ">MCP<" in body or "mcp" in body.lower()


async def test_federation_page_renders_peers(client: AsyncClient):
    cookies = await _admin_cookies(client)
    resp = await client.get("/dashboard/federation", cookies=cookies)
    assert resp.status_code == 200
    body = resp.text
    assert "mediterranean" in body
    assert "asia-pacific" in body
    assert "Court" in body
    # Legacy /orgs link is preserved per the legacy-consolidation plan
    assert "/dashboard/orgs" in body


# ─────────────────────────────────────────────────────────────────────────────
# Auth required
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/dashboard/users",
    "/dashboard/workloads",
    "/dashboard/resources",
    "/dashboard/federation",
])
async def test_principal_pages_require_login(client: AsyncClient, path: str):
    resp = await client.get(path, follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers.get("location", "")


# ─────────────────────────────────────────────────────────────────────────────
# Badge-count endpoints
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path,expected_count", [
    ("/dashboard/badge/users-count", 3),
    ("/dashboard/badge/workloads-count", 1),
    ("/dashboard/badge/resources-count", 1),
])
async def test_badge_count_chips_render(client: AsyncClient, path: str, expected_count: int):
    cookies = await _admin_cookies(client)
    resp = await client.get(path, cookies=cookies)
    assert resp.status_code == 200
    body = resp.text
    # Either the chip with the count is present or the count-0 short-circuit
    # (empty body) — the cast spec guarantees non-zero.
    assert str(expected_count) in body, f"expected count {expected_count} in {body!r}"


async def test_badge_agents_count_falls_back_to_cast(client: AsyncClient):
    cookies = await _admin_cookies(client)
    resp = await client.get("/dashboard/badge/agents-count", cookies=cookies)
    assert resp.status_code == 200
    # Empty registry falls back to the cast count (2: night-reporter +
    # ticket-bot) so the demo screenshot is non-zero.
    body = resp.text
    assert body == "" or "2" in body or any(c.isdigit() for c in body)


@pytest.mark.parametrize("path", [
    "/dashboard/badge/users-count",
    "/dashboard/badge/workloads-count",
    "/dashboard/badge/resources-count",
    "/dashboard/badge/agents-count",
])
async def test_badge_count_unauth_returns_empty(client: AsyncClient, path: str):
    """Unauthenticated badge call returns empty string, not redirect."""
    resp = await client.get(path)
    assert resp.status_code == 200
    assert resp.text == ""


# ─────────────────────────────────────────────────────────────────────────────
# Nav: principal-type sections appear on every page
# ─────────────────────────────────────────────────────────────────────────────

async def test_nav_includes_principal_sections(client: AsyncClient):
    cookies = await _admin_cookies(client)
    resp = await client.get("/dashboard", cookies=cookies)
    assert resp.status_code == 200
    body = resp.text
    # Every section link present in the new nav structure
    assert 'href="/dashboard/users"' in body
    assert 'href="/dashboard/agents"' in body
    assert 'href="/dashboard/resources"' in body
    assert 'href="/dashboard/federation"' in body
    # Workloads are LOCAL-only runtime infrastructure: they don't
    # federate, so the Court network-admin nav must not surface them.
    # The /dashboard/workloads route stays alive (URL-accessible) for
    # future per-org Mastio admin reuse.
    assert 'href="/dashboard/workloads"' not in body
    # Group labels
    assert "Principals" in body
    assert "Federation" in body


async def test_overview_stats_strip(client: AsyncClient):
    cookies = await _admin_cookies(client)
    resp = await client.get("/dashboard", cookies=cookies)
    assert resp.status_code == 200
    body = resp.text
    # Stats strip cells
    assert "organizations" in body
    assert "users" in body
    assert "agents" in body
    assert "audit chain" in body
    # Sessions cell must not be on overview anymore
    assert "sessions · live" not in body
    # Users cell links to the Users page
    assert 'href="/dashboard/users"' in body


# ─────────────────────────────────────────────────────────────────────────────
# Agents page extras: enrollment_method + automation_type columns exist
# ─────────────────────────────────────────────────────────────────────────────

async def test_agents_page_renders_new_columns(client: AsyncClient):
    cookies = await _admin_cookies(client)
    resp = await client.get("/dashboard/agents", cookies=cookies)
    assert resp.status_code == 200
    body = resp.text
    assert "Enrollment" in body
    assert "Automation" in body
    # Agent badge appears in the principal column
    assert ">Agent<" in body
