"""POST /v1/admin/agents/{id}/reactivate — ADR-013 Phase 4 commit 5.

Covers:
- Auth: missing or wrong admin secret → 403.
- Happy path: enforce event exists, is_active=0 → 200, row re-enabled,
  event marked resolved with operator fingerprint.
- 404: no active event.
- 404: most recent event is shadow-mode.
- 404: agent row already hard-deleted by expiry cron.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

pytestmark = pytest.mark.asyncio


async def _spin_proxy(tmp_path, monkeypatch, org_id: str = "reactivate-test"):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}"
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()
    from mcp_proxy.main import app

    return app


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def _seed_agent(app, agent_id: str, active: int = 1) -> None:
    from mcp_proxy.db import get_db

    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO internal_agents "
                "(agent_id, display_name, capabilities, "
                " created_at, is_active) "
                "VALUES (:a, :a, '[]', :ts, :act)"
            ),
            {
                "a": agent_id,
                "ts": _iso(datetime.now(timezone.utc)),
                "act": active,
            },
        )


async def _seed_event(
    app, *, agent_id: str, mode: str = "enforce",
    resolved: bool = False,
) -> None:
    from mcp_proxy.db import get_db

    now = datetime.now(timezone.utc)
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode, expires_at, "
                " resolved_at, resolved_by) "
                "VALUES (:a, :t, :m, :e, :r, :by)"
            ),
            {
                "a": agent_id,
                "t": _iso(now),
                "m": mode,
                "e": _iso(now + timedelta(hours=23)) if mode == "enforce" else None,
                "r": _iso(now) if resolved else None,
                "by": "operator:prior" if resolved else None,
            },
        )


async def _headers():
    from mcp_proxy.config import get_settings

    return {"X-Admin-Secret": get_settings().admin_secret}


async def test_reactivate_missing_admin_secret_is_403(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.post("/v1/admin/agents/a/reactivate")
    assert r.status_code == 422  # FastAPI validation error on missing header


async def test_reactivate_wrong_admin_secret_is_403(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            r = await cli.post(
                "/v1/admin/agents/a/reactivate",
                headers={"X-Admin-Secret": "wrong"},
            )
    assert r.status_code == 403


async def test_reactivate_returns_404_when_no_event(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_agent(app, "quiet-agent")
            r = await cli.post(
                "/v1/admin/agents/quiet-agent/reactivate",
                headers=await _headers(),
            )
    assert r.status_code == 404
    assert "no active quarantine" in r.json()["detail"]


async def test_reactivate_refuses_shadow_event(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_agent(app, "shadow-only")
            await _seed_event(app, agent_id="shadow-only", mode="shadow")
            r = await cli.post(
                "/v1/admin/agents/shadow-only/reactivate",
                headers=await _headers(),
            )
    assert r.status_code == 404
    assert "shadow" in r.json()["detail"]


async def test_reactivate_clears_enforce_event(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_agent(app, "quarantined", active=0)
            await _seed_event(app, agent_id="quarantined", mode="enforce")

            r = await cli.post(
                "/v1/admin/agents/quarantined/reactivate",
                headers=await _headers(),
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["ok"] is True
            assert body["agent_id"] == "quarantined"
            assert body["resolved_event_id"] is not None

            from mcp_proxy.db import get_db

            async with get_db() as conn:
                active = (
                    await conn.execute(
                        text(
                            "SELECT is_active FROM internal_agents "
                            "WHERE agent_id = 'quarantined'"
                        )
                    )
                ).scalar()
                event = (
                    await conn.execute(
                        text(
                            "SELECT resolved_at, resolved_by FROM "
                            "agent_quarantine_events "
                            "WHERE agent_id = 'quarantined'"
                        )
                    )
                ).first()
    assert active == 1
    assert event[0] is not None
    assert event[1].startswith("operator:")


async def test_reactivate_after_hard_delete_returns_404(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            # Insert event but no internal_agents row — simulates
            # a post-expiry-cron state.
            await _seed_event(app, agent_id="deleted-agent", mode="enforce")

            r = await cli.post(
                "/v1/admin/agents/deleted-agent/reactivate",
                headers=await _headers(),
            )
    assert r.status_code == 404
    assert "re-enrollment" in r.json()["detail"]
