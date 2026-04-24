"""ADR-013 Phase 4 end-to-end integration — commit 8.

Spins up the Mastio with the anomaly stack wired (commit 7) and
exercises the full path: seed traffic → run one evaluator cycle →
verify DB side effects match the configured mode.

Shadow mode: event row written with mode='shadow', is_active stays 1.
Enforce mode: event row written with mode='enforce', is_active flips
to 0, expires_at populated.
Ceiling trip: five simultaneous candidates, zero applied, one
``meta_ceiling_trips_total`` bump.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

pytestmark = pytest.mark.asyncio


async def _spin(tmp_path, monkeypatch, *, mode: str, ceiling: int = 3,
                org_id: str = "ph4-int"):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv(
        "MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}"
    )
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ANOMALY_QUARANTINE_MODE", mode)
    monkeypatch.setenv(
        "MCP_PROXY_ANOMALY_ABSOLUTE_THRESHOLD_RPS", "10"
    )
    monkeypatch.setenv(
        "MCP_PROXY_ANOMALY_SUSTAINED_TICKS_REQUIRED", "1"
    )
    monkeypatch.setenv(
        "MCP_PROXY_ANOMALY_CEILING_PER_MIN", str(ceiling)
    )
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()
    from mcp_proxy.main import app

    return app


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def _seed_agent(agent_id: str) -> None:
    from mcp_proxy.db import get_db

    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO internal_agents "
                "(agent_id, display_name, capabilities, api_key_hash, "
                " created_at, is_active) "
                "VALUES (:a, :a, '[]', 'hash', :ts, 1)"
            ),
            {
                "a": agent_id,
                "ts": _iso(datetime.now(timezone.utc)),
            },
        )


async def _seed_traffic(
    agent_id: str, *, rps: int = 30, window_minutes: int = 5
) -> None:
    """Insert one 10-min bucket that will produce ``rps`` in the 5-min
    rate computation. ``rps * 300`` total reqs in the 5-min window."""
    from mcp_proxy.db import get_db

    total = rps * 300
    now = datetime.now(timezone.utc)
    async with get_db() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_traffic_samples "
                "(agent_id, bucket_ts, req_count) VALUES (:a, :b, :c)"
            ),
            {
                "a": agent_id,
                "b": _iso(now - timedelta(minutes=2)),
                "c": total,
            },
        )


async def test_shadow_mode_logs_decision_without_deactivating(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch, mode="shadow")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test"):
        async with app.router.lifespan_context(app):
            await _seed_agent("suspect")
            await _seed_traffic("suspect", rps=30)
            # Force one cycle — the background task is every 30s; we
            # don't want the test to hang. run_cycle is sync-on-DB.
            result = await app.state.anomaly_evaluator.run_cycle()
            assert result == {"candidates": 1, "applied": 1, "suppressed": 0}

            from mcp_proxy.db import get_db

            async with get_db() as conn:
                active = (
                    await conn.execute(
                        text(
                            "SELECT is_active FROM internal_agents "
                            "WHERE agent_id = 'suspect'"
                        )
                    )
                ).scalar()
                event = (
                    await conn.execute(
                        text(
                            "SELECT mode, expires_at FROM "
                            "agent_quarantine_events WHERE agent_id = 'suspect'"
                        )
                    )
                ).first()
    assert active == 1  # shadow never touches is_active
    assert event is not None
    assert event[0] == "shadow"
    assert event[1] is None  # shadow events have no expiry


async def test_enforce_mode_deactivates_and_stamps_expiry(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch, mode="enforce")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test"):
        async with app.router.lifespan_context(app):
            await _seed_agent("bad-agent")
            await _seed_traffic("bad-agent", rps=30)
            result = await app.state.anomaly_evaluator.run_cycle()
            assert result == {"candidates": 1, "applied": 1, "suppressed": 0}

            from mcp_proxy.db import get_db

            async with get_db() as conn:
                active = (
                    await conn.execute(
                        text(
                            "SELECT is_active FROM internal_agents "
                            "WHERE agent_id = 'bad-agent'"
                        )
                    )
                ).scalar()
                event = (
                    await conn.execute(
                        text(
                            "SELECT mode, expires_at FROM "
                            "agent_quarantine_events "
                            "WHERE agent_id = 'bad-agent'"
                        )
                    )
                ).first()
    assert active == 0
    assert event[0] == "enforce"
    assert event[1] is not None  # expires_at populated


async def test_meta_ceiling_suppresses_batch(tmp_path, monkeypatch):
    app = await _spin(tmp_path, monkeypatch, mode="enforce", ceiling=3)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test"):
        async with app.router.lifespan_context(app):
            # 5 agents, all over threshold → projected 5 > ceiling 3.
            for i in range(5):
                await _seed_agent(f"burst-{i}")
                await _seed_traffic(f"burst-{i}", rps=30)

            result = await app.state.anomaly_evaluator.run_cycle()
            assert result == {"candidates": 5, "applied": 0, "suppressed": 5}
            assert app.state.anomaly_evaluator.meta_breaker.ceiling_trips_total == 1

            # Zero events written, every agent still active.
            from mcp_proxy.db import get_db

            async with get_db() as conn:
                count = (
                    await conn.execute(
                        text(
                            "SELECT COUNT(*) FROM agent_quarantine_events"
                        )
                    )
                ).scalar()
                active_count = (
                    await conn.execute(
                        text(
                            "SELECT COUNT(*) FROM internal_agents "
                            "WHERE is_active = 1"
                        )
                    )
                ).scalar()
    assert count == 0
    assert active_count == 5


async def test_observability_endpoint_reports_quarantine_after_shadow_run(
    tmp_path, monkeypatch
):
    app = await _spin(tmp_path, monkeypatch, mode="shadow")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            await _seed_agent("watched")
            await _seed_traffic("watched", rps=30)
            await app.state.anomaly_evaluator.run_cycle()

            from mcp_proxy.config import get_settings

            r = await cli.get(
                "/v1/admin/observability/anomaly-detector",
                headers={"X-Admin-Secret": get_settings().admin_secret},
            )
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "shadow"
    assert body["quarantines_shadow_total"] == 1
    assert body["quarantines_enforce_total"] == 0
    assert body["quarantines_last_24h_shadow_only"] == 1
    # No enforce rows inside the last 24h window either.
    assert body["quarantines_last_24h"] == 0
