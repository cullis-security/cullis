"""ADR-001 Phase 3b — proxy-side WebSocket server for intra-org push.

Covers:
  - LocalConnectionManager: connect/disconnect/send/reconnect
  - /v1/local/ws handshake: missing key, invalid key, valid key
  - Server-initiated push reaches the client
  - Reconnect replaces the stale connection
"""
from __future__ import annotations

import os

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from mcp_proxy.local.ws_manager import LocalConnectionManager

# Starlette's sync TestClient deadlocks the inner anyio loop on single-core
# GHA runners when it's invoked from inside an `@pytest.mark.asyncio` test —
# in particular for the one case that completes a real WS handshake. Tracked
# in #68; will go away once the test moves to httpx_ws / async websockets.
_CI_HANG_SKIP = pytest.mark.skipif(
    os.environ.get("CI") == "true",
    reason="Hangs on GHA runners (#68) — sync TestClient + asyncio loop deadlock.",
)


# ── LocalConnectionManager unit tests ───────────────────────────────

class _FakeWS:
    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.closed: tuple[int, str] | None = None

    async def send_json(self, data: dict) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)


@pytest.mark.asyncio
async def test_connect_and_send():
    mgr = LocalConnectionManager()
    ws = _FakeWS()
    await mgr.connect("alice", ws)
    assert mgr.is_connected("alice")
    delivered = await mgr.send_to_agent("alice", {"type": "new_message"})
    assert delivered is True
    assert ws.sent == [{"type": "new_message"}]


@pytest.mark.asyncio
async def test_send_to_absent_agent_returns_false():
    mgr = LocalConnectionManager()
    assert await mgr.send_to_agent("nobody", {"type": "x"}) is False


@pytest.mark.asyncio
async def test_reconnect_evicts_previous_ws():
    mgr = LocalConnectionManager()
    old_ws = _FakeWS()
    new_ws = _FakeWS()
    await mgr.connect("alice", old_ws)
    await mgr.connect("alice", new_ws)
    assert old_ws.closed is not None
    assert mgr.is_connected("alice")
    await mgr.send_to_agent("alice", {"ok": True})
    assert new_ws.sent == [{"ok": True}]
    assert old_ws.sent == []


@pytest.mark.asyncio
async def test_disconnect_removes_and_closes():
    mgr = LocalConnectionManager()
    ws = _FakeWS()
    await mgr.connect("alice", ws)
    await mgr.disconnect("alice", code=1000, reason="bye")
    assert not mgr.is_connected("alice")
    assert ws.closed == (1000, "bye")


@pytest.mark.asyncio
async def test_send_failure_evicts_connection():
    class _BrokenWS(_FakeWS):
        async def send_json(self, data: dict) -> None:
            raise RuntimeError("socket broken")

    mgr = LocalConnectionManager()
    ws = _BrokenWS()
    await mgr.connect("alice", ws)
    delivered = await mgr.send_to_agent("alice", {"x": 1})
    assert delivered is False
    assert not mgr.is_connected("alice")


@pytest.mark.asyncio
async def test_shutdown_closes_all():
    mgr = LocalConnectionManager()
    ws1, ws2 = _FakeWS(), _FakeWS()
    await mgr.connect("alice", ws1)
    await mgr.connect("bob", ws2)
    await mgr.shutdown()
    assert ws1.closed is not None
    assert ws2.closed is not None
    # Idempotent — calling again doesn't raise.
    await mgr.shutdown()


# ── /v1/local/ws endpoint integration ───────────────────────────────

@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


async def _provision(agent_id: str) -> str:
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
    from mcp_proxy.db import create_agent
    raw = generate_api_key(agent_id)
    await create_agent(
        agent_id=agent_id,
        display_name=agent_id,
        capabilities=[],
        api_key_hash=hash_api_key(raw),
    )
    return raw


def _ws_client(app):
    """TestClient gives a synchronous WebSocket helper that plays well with
    Starlette's transport — easier than httpx for upgrade flows."""
    return TestClient(app, raise_server_exceptions=True)


@pytest.mark.asyncio
async def test_ws_rejects_missing_api_key(proxy_app):
    app, _ = proxy_app
    client = _ws_client(app)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/v1/local/ws"):
            pass
    assert exc.value.code == 4401


@pytest.mark.asyncio
async def test_ws_rejects_invalid_api_key(proxy_app):
    app, _ = proxy_app
    client = _ws_client(app)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/v1/local/ws?api_key=sk_local_fake_nope"):
            pass
    assert exc.value.code == 4401


@_CI_HANG_SKIP
@pytest.mark.asyncio
async def test_ws_accepts_valid_api_key_and_registers(proxy_app):
    app, _ = proxy_app
    raw = await _provision("alice")
    client = _ws_client(app)

    with client.websocket_connect(f"/v1/local/ws?api_key={raw}") as ws:
        welcome = ws.receive_json()
        assert welcome == {"type": "connected", "agent_id": "alice"}
        assert app.state.local_ws_manager.is_connected("alice")

    # After the context exits, the manager should have released the entry.
    assert not app.state.local_ws_manager.is_connected("alice")


# Note: server-initiated push end-to-end (manager.send_to_agent → frame
# arriving at the TestClient websocket) is exercised by Phase 3c when a
# real message delivery path drives it. The unit test
# `test_connect_and_send` above already covers the manager half.
