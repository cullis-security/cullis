"""ADR-001 Phase 3b — LocalConnectionManager unit tests.

Covers:
  - LocalConnectionManager: connect/disconnect/send/reconnect

Note: PR-C dropped the legacy ``/v1/local/ws?api_key=...`` endpoint
(api_key auth path). The manager itself stays — egress send paths
deliver via it when present. A cert-authenticated WS replacement is
deferred; until then there is nothing to integration-test.
"""
from __future__ import annotations

import pytest

from mcp_proxy.local.ws_manager import LocalConnectionManager


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
