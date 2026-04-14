"""WebSocket endpoint for intra-org push delivery — ADR-001 Phase 3b.

An internal agent that wants real-time delivery of messages queued for
it locally connects to `/v1/local/ws?api_key=<raw>`. We accept the
socket, authenticate the key, register the connection in the
`LocalConnectionManager`, and then idle in a read loop (inbound frames
are treated as keepalive — there is nothing the client needs to send
today). Phase 3c will push `new_message` frames over this socket.

Auth via query param (not header) because JS WebSocket and many client
libraries cannot set custom headers on the upgrade request. The proxy
is internal-facing (loopback or LAN); if logs capture URLs, redact the
`api_key` param at the logger level rather than punishing the protocol.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Query, WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState

from mcp_proxy.db import get_agent_by_key_hash
from mcp_proxy.local import message_queue as local_queue
from mcp_proxy.local.ws_manager import LocalConnectionManager

logger = logging.getLogger("mcp_proxy.local.ws_router")

router = APIRouter(prefix="/v1/local", tags=["local"])


# RFC 6455 application-level close codes — 4000-4999 are reserved for app use.
_WS_CLOSE_UNAUTHORIZED = 4401
_WS_CLOSE_INTERNAL_ERROR = 1011


def _get_manager(app) -> LocalConnectionManager | None:
    return getattr(app.state, "local_ws_manager", None)


@router.websocket("/ws")
async def local_ws(
    websocket: WebSocket,
    api_key: str = Query(default="", description="Internal agent API key"),
) -> None:
    """Agent-facing WebSocket for intra-org realtime push."""
    manager = _get_manager(websocket.app)
    if manager is None:
        # Phase 3 not wired — refuse the upgrade before sending anything.
        await websocket.close(code=_WS_CLOSE_INTERNAL_ERROR, reason="ws_not_ready")
        return

    if not api_key or not api_key.startswith("sk_local_"):
        await websocket.close(code=_WS_CLOSE_UNAUTHORIZED, reason="missing_api_key")
        return

    agent_data = await get_agent_by_key_hash(api_key)
    if agent_data is None:
        await websocket.close(code=_WS_CLOSE_UNAUTHORIZED, reason="invalid_api_key")
        return

    agent_id = agent_data["agent_id"]
    await websocket.accept()
    await manager.connect(agent_id, websocket)

    try:
        await websocket.send_json({"type": "connected", "agent_id": agent_id})

        # ADR-001 Phase 3c — drain any messages that were enqueued while
        # this agent was offline. Each replay carries queued:true so the
        # SDK can skip duplicate business handlers if the flow is idempotent.
        try:
            pending = await local_queue.fetch_pending_for_recipient(agent_id)
        except Exception as exc:
            logger.warning("Local queue drain failed for %s: %s", agent_id, exc)
            pending = []
        for msg in pending:
            import json as _json
            try:
                payload = _json.loads(msg.payload_ciphertext)
            except Exception:
                payload = msg.payload_ciphertext
            await websocket.send_json(
                {
                    "type": "new_message",
                    "session_id": msg.session_id,
                    "msg_id": msg.msg_id,
                    "sender_agent_id": msg.sender_agent_id,
                    "payload": payload,
                    "enqueued_at": msg.enqueued_at.isoformat()
                    if msg.enqueued_at else None,
                    "queued": True,
                }
            )

        while True:
            # Treat any inbound frame as a keepalive. Phase 3c may add
            # client-initiated ack frames here.
            try:
                await websocket.receive_text()
            except WebSocketDisconnect:
                break
    except Exception as exc:
        logger.warning("Local WS loop error for %s: %s", agent_id, exc)
    finally:
        # Only disconnect if the manager still owns this socket — the
        # manager itself handles the race where a reconnect already
        # replaced us.
        if manager.is_connected(agent_id):
            await manager.disconnect(agent_id)
        if websocket.client_state != WebSocketState.DISCONNECTED:
            try:
                await websocket.close()
            except Exception:
                pass
