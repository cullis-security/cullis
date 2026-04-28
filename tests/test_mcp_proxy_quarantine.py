"""Quarantine apply + expiry + reactivation tests — ADR-013 Phase 4 c5.

Covers:
- make_quarantine_apply_hook in shadow and enforce modes.
- run_expiry_once hard-deletes enforce-mode rows and marks events.
- reactivate_agent refuses shadow-mode events, handles hard-deleted
  rows, resolves enforce-mode events with an operator fingerprint.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_proxy.db import dispose_db, init_db
from mcp_proxy.observability.anomaly_evaluator import TriggerInfo
from mcp_proxy.observability.quarantine import (
    make_quarantine_apply_hook,
    reactivate_agent,
    run_expiry_once,
    _operator_fingerprint,
)


@pytest.fixture
async def engine(tmp_path):
    db_file = tmp_path / "quarantine.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    await init_db(url)
    eng: AsyncEngine = create_async_engine(url, future=True)
    yield eng
    await eng.dispose()
    await dispose_db()


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


async def _insert_agent(engine: AsyncEngine, agent_id: str, active: int = 1) -> None:
    async with engine.begin() as conn:
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


def _trigger(agent_id: str = "a", rps: float = 150.0) -> TriggerInfo:
    return TriggerInfo(
        agent_id=agent_id,
        current_rate_rps=rps,
        baseline_rpm=10.0,
        ratio=15.0,
        hour_of_week=30,
        mature=True,
        sustained_ticks=3,
    )


# ── apply_hook ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_shadow_hook_inserts_event_without_touching_is_active(engine):
    await _insert_agent(engine, "a")
    hook = make_quarantine_apply_hook(engine)
    await hook(_trigger("a"), "shadow")

    async with engine.begin() as conn:
        event = (
            await conn.execute(
                text(
                    "SELECT mode, expires_at FROM agent_quarantine_events "
                    "WHERE agent_id = 'a'"
                )
            )
        ).first()
        active = (
            await conn.execute(
                text(
                    "SELECT is_active FROM internal_agents WHERE agent_id = 'a'"
                )
            )
        ).scalar()
    assert event is not None
    assert event[0] == "shadow"
    # Shadow events never expire — the expires_at column is NULL.
    assert event[1] is None
    # is_active untouched.
    assert active == 1


@pytest.mark.asyncio
async def test_enforce_hook_inserts_event_and_deactivates(engine):
    await _insert_agent(engine, "a")
    hook = make_quarantine_apply_hook(engine, ttl_hours=24)
    await hook(_trigger("a"), "enforce")

    async with engine.begin() as conn:
        event = (
            await conn.execute(
                text(
                    "SELECT mode, expires_at, trigger_ratio, trigger_abs_rate "
                    "FROM agent_quarantine_events WHERE agent_id = 'a'"
                )
            )
        ).first()
        active = (
            await conn.execute(
                text(
                    "SELECT is_active FROM internal_agents WHERE agent_id = 'a'"
                )
            )
        ).scalar()
    assert event is not None
    assert event[0] == "enforce"
    assert event[1] is not None  # expires_at populated
    assert event[2] == pytest.approx(15.0)
    assert event[3] == pytest.approx(150.0)
    assert active == 0


@pytest.mark.asyncio
async def test_enforce_hook_idempotent_when_agent_already_inactive(engine):
    """If an operator already deactivated the agent, the event row must
    still be written (audit integrity) but no error raised."""
    await _insert_agent(engine, "a", active=0)
    hook = make_quarantine_apply_hook(engine)
    await hook(_trigger("a"), "enforce")  # must not raise

    async with engine.begin() as conn:
        count = (
            await conn.execute(
                text(
                    "SELECT COUNT(*) FROM agent_quarantine_events "
                    "WHERE agent_id = 'a'"
                )
            )
        ).scalar()
    assert count == 1


@pytest.mark.asyncio
async def test_notification_dispatch_receives_context(engine):
    await _insert_agent(engine, "a")
    received: list[dict] = []

    def dispatcher(payload):
        received.append(payload)

    hook = make_quarantine_apply_hook(
        engine, notification_dispatch=dispatcher
    )
    await hook(_trigger("a"), "enforce")

    assert len(received) == 1
    msg = received[0]
    assert msg["agent_id"] == "a"
    assert msg["mode"] == "enforce"
    assert msg["ratio"] == 15.0
    assert msg["expires_at"] is not None
    assert "event_id" in msg


@pytest.mark.asyncio
async def test_notification_dispatch_exception_does_not_abort(engine):
    """A raising dispatcher must not prevent DB side-effects."""
    await _insert_agent(engine, "a")

    def dispatcher(payload):
        raise RuntimeError("webhook down")

    hook = make_quarantine_apply_hook(
        engine, notification_dispatch=dispatcher
    )
    await hook(_trigger("a"), "enforce")  # must not raise

    async with engine.begin() as conn:
        active = (
            await conn.execute(
                text(
                    "SELECT is_active FROM internal_agents WHERE agent_id = 'a'"
                )
            )
        ).scalar()
    assert active == 0


# ── expiry cron ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_expiry_hard_deletes_expired_enforce_rows(engine):
    await _insert_agent(engine, "a")
    await _insert_agent(engine, "b")
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)

    # One expired, one not yet.
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode, expires_at) "
                "VALUES ('a', :t0, 'enforce', :expired)"
            ),
            {
                "t0": _iso(now - timedelta(days=2)),
                "expired": _iso(now - timedelta(hours=1)),
            },
        )
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode, expires_at) "
                "VALUES ('b', :t0, 'enforce', :future)"
            ),
            {
                "t0": _iso(now),
                "future": _iso(now + timedelta(hours=23)),
            },
        )

    stats = await run_expiry_once(engine, now=now)
    assert stats.scanned == 1
    assert stats.deleted == 1
    assert stats.resolved == 1

    async with engine.begin() as conn:
        a_row = (
            await conn.execute(
                text(
                    "SELECT agent_id FROM internal_agents WHERE agent_id = 'a'"
                )
            )
        ).first()
        b_row = (
            await conn.execute(
                text(
                    "SELECT agent_id FROM internal_agents WHERE agent_id = 'b'"
                )
            )
        ).first()
        resolved_a = (
            await conn.execute(
                text(
                    "SELECT resolved_by FROM agent_quarantine_events "
                    "WHERE agent_id = 'a'"
                )
            )
        ).scalar()
    assert a_row is None
    assert b_row is not None
    assert resolved_a == "expired"


@pytest.mark.asyncio
async def test_expiry_ignores_shadow_events(engine):
    await _insert_agent(engine, "a")
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode, expires_at) "
                "VALUES ('a', :t0, 'shadow', :expired)"
            ),
            {
                "t0": _iso(now - timedelta(days=1)),
                "expired": _iso(now - timedelta(hours=1)),
            },
        )

    stats = await run_expiry_once(engine, now=now)
    assert stats.scanned == 0
    assert stats.deleted == 0

    # Agent row untouched.
    async with engine.begin() as conn:
        active = (
            await conn.execute(
                text(
                    "SELECT is_active FROM internal_agents WHERE agent_id = 'a'"
                )
            )
        ).scalar()
    assert active == 1


@pytest.mark.asyncio
async def test_expiry_skips_already_resolved(engine):
    await _insert_agent(engine, "a")
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode, expires_at, "
                " resolved_at, resolved_by) "
                "VALUES ('a', :t0, 'enforce', :expired, :r, 'operator:abc')"
            ),
            {
                "t0": _iso(now - timedelta(days=2)),
                "expired": _iso(now - timedelta(hours=1)),
                "r": _iso(now - timedelta(minutes=10)),
            },
        )

    stats = await run_expiry_once(engine, now=now)
    assert stats.scanned == 0
    assert stats.deleted == 0


# ── reactivate_agent ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reactivate_refuses_when_no_event(engine):
    await _insert_agent(engine, "a")
    result = await reactivate_agent(engine, "a", admin_secret="s")
    assert result.ok is False
    assert "no active quarantine event" in result.message


@pytest.mark.asyncio
async def test_reactivate_refuses_shadow_event(engine):
    await _insert_agent(engine, "a")
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode) "
                "VALUES ('a', :t, 'shadow')"
            ),
            {"t": _iso(now)},
        )

    result = await reactivate_agent(engine, "a", admin_secret="s")
    assert result.ok is False
    assert "shadow" in result.message


@pytest.mark.asyncio
async def test_reactivate_clears_enforce_event(engine):
    await _insert_agent(engine, "a", active=0)
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode, expires_at) "
                "VALUES ('a', :t, 'enforce', :e)"
            ),
            {
                "t": _iso(now - timedelta(hours=1)),
                "e": _iso(now + timedelta(hours=23)),
            },
        )

    result = await reactivate_agent(engine, "a", admin_secret="mysecret")
    assert result.ok is True
    assert result.resolved_event_id is not None

    async with engine.begin() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT is_active FROM internal_agents WHERE agent_id = 'a'"
                )
            )
        ).scalar()
        event = (
            await conn.execute(
                text(
                    "SELECT resolved_at, resolved_by FROM "
                    "agent_quarantine_events WHERE agent_id = 'a'"
                )
            )
        ).first()
    assert row == 1
    assert event[0] is not None  # resolved_at populated
    assert event[1] == _operator_fingerprint("mysecret")


@pytest.mark.asyncio
async def test_reactivate_after_hard_delete_returns_not_ok(engine):
    """If the expiry cron already deleted the agent row, reactivation
    must fail with a clear message — not silently re-insert a ghost.
    """
    # No internal_agents row exists for 'a', but an event does.
    now = datetime(2026, 4, 24, 12, 0, 0, tzinfo=timezone.utc)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO agent_quarantine_events "
                "(agent_id, quarantined_at, mode, expires_at) "
                "VALUES ('ghost', :t, 'enforce', :e)"
            ),
            {
                "t": _iso(now - timedelta(hours=1)),
                "e": _iso(now + timedelta(hours=23)),
            },
        )

    result = await reactivate_agent(engine, "ghost", admin_secret="s")
    assert result.ok is False
    assert "re-enrollment" in result.message


def test_operator_fingerprint_is_deterministic_but_not_reversible():
    f1 = _operator_fingerprint("secret-1")
    f2 = _operator_fingerprint("secret-1")
    f3 = _operator_fingerprint("secret-2")
    assert f1 == f2
    assert f1 != f3
    # No part of the secret appears in the fingerprint.
    assert "secret-1" not in f1
    assert f1.startswith("operator:")
