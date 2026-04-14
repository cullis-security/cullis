"""ADR-001 Phase 4b — proxy federation subscriber + cache handler tests.

Two layers of coverage:

1. Handler unit tests (synchronous apply_event against an in-memory
   SQLite) — the fast, exhaustive layer.
2. Subscriber integration test against a tiny in-process SSE server
   built from Starlette + httpx ASGITransport — the reconnect-and-cursor
   smoke. Heavy HTTP suites are not needed: the shape of the wire is
   trivial and the handlers carry most of the logic risk.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from starlette.applications import Starlette
from starlette.responses import StreamingResponse
from starlette.routing import Route

from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.sync.handlers import (
    EVENT_AGENT_REGISTERED,
    EVENT_AGENT_REVOKED,
    EVENT_AGENT_ROTATED,
    EVENT_BINDING_GRANTED,
    EVENT_BINDING_REVOKED,
    EVENT_POLICY_REMOVED,
    EVENT_POLICY_UPDATED,
    apply_event,
    get_cursor,
)
from mcp_proxy.sync.subscriber import SubscriberConfig, run_subscriber


# ── proxy_db fixture ───────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    await init_db(url)
    yield url
    await dispose_db()


# ── Handler unit tests ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_agent_registered_inserts_row(proxy_db):
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=1,
            event_type=EVENT_AGENT_REGISTERED,
            payload={
                "agent_id": "acme::alice",
                "display_name": "Alice",
                "capabilities": ["cap.read"],
            },
        )
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT agent_id, org_id, display_name, capabilities, revoked "
                 "FROM cached_federated_agents WHERE agent_id='acme::alice'")
        )).first()
    assert row is not None
    assert row[0] == "acme::alice"
    assert row[1] == "acme"
    assert row[2] == "Alice"
    assert json.loads(row[3]) == ["cap.read"]
    assert row[4] == 0


@pytest.mark.asyncio
async def test_agent_registered_is_idempotent(proxy_db):
    for _ in range(3):
        async with get_db() as conn:
            await apply_event(
                conn, org_id="acme", seq=1,
                event_type=EVENT_AGENT_REGISTERED,
                payload={"agent_id": "acme::a", "capabilities": []},
            )
    async with get_db() as conn:
        n = (await conn.execute(
            text("SELECT COUNT(*) FROM cached_federated_agents")
        )).scalar_one()
    assert n == 1


@pytest.mark.asyncio
async def test_agent_revoked_marks_revoked(proxy_db):
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=1,
            event_type=EVENT_AGENT_REGISTERED,
            payload={"agent_id": "acme::b", "capabilities": []},
        )
        await apply_event(
            conn, org_id="acme", seq=2,
            event_type=EVENT_AGENT_REVOKED,
            payload={"agent_id": "acme::b", "reason": "compromised"},
        )
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT revoked FROM cached_federated_agents WHERE agent_id='acme::b'")
        )).first()
    assert row[0] == 1


@pytest.mark.asyncio
async def test_agent_revoked_before_register_is_accepted(proxy_db):
    """Proxy may join mid-stream and miss the original register event.
    A bare revoke should still produce a cache row, so decisions using
    the cache can safely treat 'unknown agent' as absent (not revoked
    masquerading as present)."""
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=1,
            event_type=EVENT_AGENT_REVOKED,
            payload={"agent_id": "acme::ghost"},
        )
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT revoked FROM cached_federated_agents WHERE agent_id='acme::ghost'")
        )).first()
    assert row is not None
    assert row[0] == 1


@pytest.mark.asyncio
async def test_agent_rotated_updates_thumbprint(proxy_db):
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=1,
            event_type=EVENT_AGENT_REGISTERED,
            payload={"agent_id": "acme::c", "capabilities": []},
        )
        await apply_event(
            conn, org_id="acme", seq=2,
            event_type=EVENT_AGENT_ROTATED,
            payload={"agent_id": "acme::c", "thumbprint": "abcdef1234"},
        )
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT thumbprint FROM cached_federated_agents WHERE agent_id='acme::c'")
        )).first()
    assert row[0] == "abcdef1234"


@pytest.mark.asyncio
async def test_policy_lifecycle(proxy_db):
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=1,
            event_type=EVENT_POLICY_UPDATED,
            payload={"policy_id": "p1", "policy_type": "session"},
        )
        await apply_event(
            conn, org_id="acme", seq=2,
            event_type=EVENT_POLICY_REMOVED,
            payload={"policy_id": "p1"},
        )
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT is_active, policy_type FROM cached_policies WHERE policy_id='p1'")
        )).first()
    assert row[0] == 0
    assert row[1] == "session"


@pytest.mark.asyncio
async def test_binding_lifecycle(proxy_db):
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=1,
            event_type=EVENT_BINDING_GRANTED,
            payload={"binding_id": 42, "agent_id": "acme::x", "scope": ["r"]},
        )
        await apply_event(
            conn, org_id="acme", seq=2,
            event_type=EVENT_BINDING_REVOKED,
            payload={"binding_id": 42, "agent_id": "acme::x"},
        )
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT status, scope FROM cached_bindings WHERE binding_id=42")
        )).first()
    assert row[0] == "revoked"
    assert json.loads(row[1]) == ["r"]


@pytest.mark.asyncio
async def test_cursor_advances_with_each_event(proxy_db):
    async with get_db() as conn:
        cur0 = await get_cursor(conn, "acme")
        assert cur0 == 0

        for i in range(1, 4):
            await apply_event(
                conn, org_id="acme", seq=i,
                event_type=EVENT_AGENT_REGISTERED,
                payload={"agent_id": f"acme::a{i}", "capabilities": []},
            )

        cur_final = await get_cursor(conn, "acme")
    assert cur_final == 3


@pytest.mark.asyncio
async def test_unknown_event_advances_cursor_without_raising(proxy_db):
    """Newer broker may emit event types this proxy version does not
    know. Skipping gracefully keeps the subscriber from getting stuck."""
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=7,
            event_type="agent.future-type",
            payload={"some": "future"},
        )
        cur = await get_cursor(conn, "acme")
    assert cur == 7


# ── Subscriber integration ─────────────────────────────────────────


def _make_sse_app(frames: list[str]):
    """In-process SSE server that emits the given pre-formatted frames
    then closes. Used to exercise the subscriber without a real broker."""
    async def _stream(request):
        async def _gen():
            for frame in frames:
                yield frame
                await asyncio.sleep(0)  # cooperative
        return StreamingResponse(_gen(), media_type="text/event-stream")
    return Starlette(routes=[
        Route("/v1/broker/federation/events/stream", _stream),
    ])


@pytest.mark.asyncio
async def test_subscriber_applies_frames_and_updates_cursor(proxy_db):
    frames = [
        "event: connected\ndata: {\"cursor\":0}\n\n",
        'id: 1\nevent: agent.registered\n'
        'data: {"agent_id":"acme::svc","capabilities":["cap.a"]}\n\n',
        'id: 2\nevent: org.policy.updated\n'
        'data: {"policy_id":"policy-alpha","policy_type":"session"}\n\n',
    ]
    sse_app = _make_sse_app(frames)

    async def _factory():
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=sse_app),
            base_url="http://broker.test",
        )

    cfg = SubscriberConfig(
        broker_url="http://broker.test",
        org_id="acme",
        client_factory=_factory,
        initial_backoff_seconds=0.01,
        max_backoff_seconds=0.01,
        stop_after_events=2,
    )
    stop = asyncio.Event()
    await asyncio.wait_for(
        run_subscriber(cfg, stop_event=stop), timeout=5.0,
    )

    assert cfg.stats.events_applied == 2
    assert cfg.stats.last_applied_seq == 2

    async with get_db() as conn:
        cur = await get_cursor(conn, "acme")
        assert cur == 2
        a = (await conn.execute(
            text("SELECT agent_id FROM cached_federated_agents")
        )).first()
        assert a[0] == "acme::svc"
        p = (await conn.execute(
            text("SELECT policy_id, is_active FROM cached_policies")
        )).first()
        assert p[0] == "policy-alpha"
        assert p[1] == 1


@pytest.mark.asyncio
async def test_subscriber_resumes_from_persisted_cursor(proxy_db):
    # Pre-populate the cursor so the subscriber should send
    # Last-Event-ID: 5 and skip everything <= 5.
    async with get_db() as conn:
        await apply_event(
            conn, org_id="acme", seq=5,
            event_type=EVENT_AGENT_REGISTERED,
            payload={"agent_id": "acme::pre", "capabilities": []},
        )

    captured_headers: dict[str, str] = {}

    async def _stream(request):
        captured_headers.update(dict(request.headers))
        async def _gen():
            yield "event: connected\ndata: {\"cursor\":5}\n\n"
            yield ('id: 6\nevent: agent.registered\n'
                   'data: {"agent_id":"acme::new","capabilities":[]}\n\n')
        return StreamingResponse(_gen(), media_type="text/event-stream")

    sse_app = Starlette(routes=[
        Route("/v1/broker/federation/events/stream", _stream),
    ])

    async def _factory():
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=sse_app),
            base_url="http://broker.test",
        )

    cfg = SubscriberConfig(
        broker_url="http://broker.test",
        org_id="acme",
        client_factory=_factory,
        initial_backoff_seconds=0.01,
        stop_after_events=1,
    )
    await asyncio.wait_for(run_subscriber(cfg), timeout=5.0)

    # The subscriber MUST send the cursor so the broker skips the
    # backlog the proxy has already applied.
    assert captured_headers.get("last-event-id") == "5"
    assert cfg.stats.last_applied_seq == 6


@pytest.mark.asyncio
async def test_subscriber_backs_off_on_connect_failure(proxy_db):
    """If the client factory raises, the subscriber must retry with
    backoff rather than crash the proxy lifespan."""
    attempts = {"n": 0}

    async def _factory():
        attempts["n"] += 1
        raise RuntimeError("broker unreachable")

    cfg = SubscriberConfig(
        broker_url="http://broker.test",
        org_id="acme",
        client_factory=_factory,
        initial_backoff_seconds=0.01,
        max_backoff_seconds=0.02,
    )
    stop = asyncio.Event()

    async def _stop_soon():
        await asyncio.sleep(0.08)
        stop.set()

    await asyncio.gather(
        run_subscriber(cfg, stop_event=stop),
        _stop_soon(),
    )
    assert attempts["n"] >= 2
    assert cfg.stats.reconnects >= 1
    assert "broker unreachable" in (cfg.stats.last_error or "")
