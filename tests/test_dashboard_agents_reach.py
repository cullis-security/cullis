"""Dashboard ``POST /proxy/agents/{id}/reach`` endpoint.

Migrated from the pre-PR-#224 ``/federate`` toggle tests. Same
invariants, three-state model instead of binary:

  - POST sets ``reach`` to the requested value, bumps
    ``federation_revision``, and keeps ``federated`` in sync
    (= ``reach != 'intra'``) so the publisher loop still has a
    single bit to look at for PUT/revoke decisions.
  - Unknown agent → 404.
  - Invalid ``reach`` value → 400.
  - Login required.
  - CSRF token required.
"""
from __future__ import annotations

import json
import re

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.asyncio


async def _spin(tmp_path, monkeypatch, org_id: str = "pd-org"):
    db_file = tmp_path / "p.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.delenv("MCP_PROXY_BROKER_URL", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def _seed_agent(
    agent_id: str = "pd-org::alice",
    *,
    federated: bool = False,
    reach: str = "intra",
) -> None:
    """Minimal row insert — bypasses the admin API so we can exercise
    just the dashboard flip without the cert-mint machinery."""
    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        await conn.execute(
            text(
                """
                INSERT INTO internal_agents (
                    agent_id, display_name, capabilities, cert_pem, created_at, is_active,
                    federated, federation_revision, last_pushed_revision,
                    reach
                ) VALUES (
                    :aid, :name, :caps,
                    NULL, :now, 1,
                    :fed, 1, 0,
                    :reach
                )
                """
            ),
            {
                "aid": agent_id,
                "name": agent_id.split("::", 1)[-1],
                "caps": json.dumps([]),
                "now": "2026-04-17T00:00:00+00:00",
                "fed": 1 if federated else 0,
                "reach": reach,
            },
        )


async def _login(cli: AsyncClient) -> None:
    """Set admin password directly + submit login form."""
    from mcp_proxy.dashboard.session import set_admin_password
    await set_admin_password("test-password-1234")
    r = await cli.post(
        "/proxy/login",
        data={"password": "test-password-1234"},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text


async def _csrf(cli: AsyncClient) -> str:
    """Scrape CSRF token from the agents page."""
    r = await cli.get("/proxy/agents")
    assert r.status_code == 200, r.text
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    assert m, "csrf_token not found in /proxy/agents page"
    return m.group(1)


async def _fetch_flags(agent_id: str) -> dict:
    from mcp_proxy.db import get_db
    from sqlalchemy import text
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                """
                SELECT reach, federated, federation_revision
                  FROM internal_agents WHERE agent_id = :aid
                """
            ),
            {"aid": agent_id},
        )).mappings().first()
        return dict(row) if row else {}


# ── tests ──────────────────────────────────────────────────────────────


async def test_reach_set_bumps_revision_and_syncs_federated(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _seed_agent(reach="intra", federated=False)
            await _login(cli)
            csrf = await _csrf(cli)

            # intra → both: federated must flip to True.
            r = await cli.post(
                "/proxy/agents/pd-org::alice/reach",
                data={"csrf_token": csrf, "reach": "both"},
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text
            state = await _fetch_flags("pd-org::alice")
            assert state["reach"] == "both"
            assert bool(state["federated"]) is True
            assert int(state["federation_revision"]) == 2

            # both → cross: federated stays True, revision bumps again.
            r = await cli.post(
                "/proxy/agents/pd-org::alice/reach",
                data={"csrf_token": csrf, "reach": "cross"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            state = await _fetch_flags("pd-org::alice")
            assert state["reach"] == "cross"
            assert bool(state["federated"]) is True
            assert int(state["federation_revision"]) == 3

            # cross → intra: federated drops to False.
            r = await cli.post(
                "/proxy/agents/pd-org::alice/reach",
                data={"csrf_token": csrf, "reach": "intra"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            state = await _fetch_flags("pd-org::alice")
            assert state["reach"] == "intra"
            assert bool(state["federated"]) is False
            assert int(state["federation_revision"]) == 4

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_reach_unknown_agent_returns_404(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/agents/pd-org::ghost/reach",
                data={"csrf_token": csrf, "reach": "both"},
                follow_redirects=False,
            )
            assert r.status_code == 404

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_reach_invalid_value_returns_400(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _seed_agent()
            await _login(cli)
            csrf = await _csrf(cli)
            r = await cli.post(
                "/proxy/agents/pd-org::alice/reach",
                data={"csrf_token": csrf, "reach": "bogus"},
                follow_redirects=False,
            )
            assert r.status_code == 400, r.text

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_reach_requires_login(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _seed_agent()
            # No login — should redirect to /proxy/login.
            r = await cli.post(
                "/proxy/agents/pd-org::alice/reach",
                data={"reach": "both"},
                follow_redirects=False,
            )
            assert r.status_code in (302, 303, 401, 403)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_reach_requires_csrf(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as cli:
            await _seed_agent()
            await _login(cli)
            # No csrf_token in body.
            r = await cli.post(
                "/proxy/agents/pd-org::alice/reach",
                data={"reach": "both"},
                follow_redirects=False,
            )
            assert r.status_code == 403

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
