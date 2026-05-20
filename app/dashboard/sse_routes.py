"""Court dashboard — SSE real-time updates endpoint.

Sprint 2 / F-B-202 PR-4 of 10. Extracts the ``GET /dashboard/sse``
endpoint that the dashboard nav listens to for real-time update
notifications (pushed by ``app.dashboard.sse.sse_manager``).

Companion module ``app/dashboard/sse.py`` already exists (the
``sse_manager`` singleton); this file holds only the HTTP route.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from app.dashboard.session import get_session

_log = logging.getLogger("agent_trust")

router = APIRouter(tags=["dashboard-sse"])


@router.get("/sse")
async def dashboard_sse(request: Request):
    session = get_session(request)
    if not session.logged_in:
        raise HTTPException(status_code=401)

    from app.dashboard.sse import sse_manager

    client_id, queue = sse_manager.connect(org_id=None, is_admin=True)

    async def event_stream():
        try:
            yield "event: connected\ndata: ok\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"event: update\ndata: {data}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            sse_manager.disconnect(client_id)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
