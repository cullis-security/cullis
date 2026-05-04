"""FastAPI router for the Connector Ambassador.

Mounted on the Connector dashboard app when
``config.ambassador.enabled`` is true. Exposes:

  GET  /v1/ambassador/health   — unauthenticated, for liveness probes
  GET  /v1/models              — Bearer-authed; lists Cullis-routed models
  POST /v1/chat/completions    — Bearer-authed; OpenAI ChatCompletion
                                 with server-side tool-use loop
  POST /v1/mcp                 — Bearer-authed; JSON-RPC MCP passthrough

All routes (except ``/v1/ambassador/health``) require:
  - the request to come from a loopback peer (127.0.0.1 / ::1)
  - a valid Bearer token matching the local ``local.token`` file

Any 401 from the SDK invalidates the cached client so the next call
re-logs in.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from cullis_connector.ambassador.auth import require_bearer, require_loopback
from cullis_connector.ambassador.client import AmbassadorClient
from cullis_connector.ambassador.loop import run_tool_use_loop
from cullis_connector.ambassador.models import ChatCompletionRequest
from cullis_connector.ambassador.streaming import (
    extract_assistant_text,
    fake_stream,
)

_log = logging.getLogger("cullis_connector.ambassador.router")

router = APIRouter(tags=["ambassador"])


# ── unauth liveness probe ───────────────────────────────────────────

def _enforce_loopback(request: Request) -> None:
    """Apply ``require_loopback`` only when the Ambassador is configured to."""
    state = getattr(request.app.state, "ambassador", None)
    if state and state.get("require_local_only", True):
        require_loopback(request)


@router.get("/v1/ambassador/health")
def health(request: Request) -> dict:
    """Liveness check. Loopback-only, no Bearer required."""
    _enforce_loopback(request)
    state = getattr(request.app.state, "ambassador", None)
    if state is None:
        return {"status": "ok", "agent_id": None, "site_url": None}
    return {
        "status": "ok",
        "agent_id": state.get("agent_id"),
        "site_url": state.get("site_url"),
    }


# ── /v1/models ──────────────────────────────────────────────────────

def _get_state(request: Request) -> dict:
    state = getattr(request.app.state, "ambassador", None)
    if state is None:
        raise HTTPException(503, "Ambassador not initialized on this app")
    return state


@router.get("/v1/models")
def list_models(request: Request) -> dict:
    _enforce_loopback(request)
    state = _get_state(request)
    require_bearer(state["bearer_token"])(request)
    advertised = state["advertised_models"] or ["claude-haiku-4-5"]
    return {
        "object": "list",
        "data": [
            {
                "id": m,
                "object": "model",
                "owned_by": "cullis",
                "created": 0,
            }
            for m in advertised
        ],
    }


# ── /v1/chat/completions ────────────────────────────────────────────

def _completion_envelope(answer: str, model: str) -> dict:
    return {
        "id": f"chatcmpl-cullis-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": answer},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


@router.post("/v1/chat/completions")
def chat_completions(req: ChatCompletionRequest, request: Request):
    _enforce_loopback(request)
    state = _get_state(request)
    require_bearer(state["bearer_token"])(request)

    client_holder: AmbassadorClient = state["client"]
    body = req.model_dump(exclude_none=True)

    try:
        client = client_holder.get()
    except Exception as exc:
        _log.exception("ambassador SDK login failed")
        raise HTTPException(502, f"Cullis cloud login failed: {exc}") from exc

    try:
        response, truncated = run_tool_use_loop(client, body, max_iters=8)
    except Exception as exc:
        # Defensive: any auth-shaped error invalidates the cached
        # client so the next request re-logs in fresh.
        client_holder.invalidate()
        _log.exception("tool-use loop failed")
        raise HTTPException(502, f"Cullis cloud call failed: {exc}") from exc

    model_out = body.get("model") or "claude-haiku-4-5"

    if req.stream:
        # v0.1 fake-stream: compute answer non-stream then fan out.
        answer = extract_assistant_text(response)
        headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        if truncated:
            headers["X-Cullis-Tool-Use-Truncated"] = "true"
        return StreamingResponse(
            fake_stream(answer, model=model_out),
            media_type="text/event-stream",
            headers=headers,
        )

    if truncated:
        # Echo through; clients can detect via this custom header.
        return JSONResponse(
            response, headers={"X-Cullis-Tool-Use-Truncated": "true"}
        )
    return response


# ── /v1/mcp passthrough ─────────────────────────────────────────────

@router.post("/v1/mcp")
async def mcp_passthrough(request: Request) -> JSONResponse:
    """Forward a JSON-RPC MCP body verbatim to the Cullis proxy.

    Useful for clients that want to drive the loop themselves (e.g.
    Cursor in agent mode) instead of letting the Ambassador run it.
    Bearer-authed and loopback-restricted just like the other routes.
    """
    _enforce_loopback(request)
    state = _get_state(request)
    require_bearer(state["bearer_token"])(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid JSON body")
    if not isinstance(body, dict):
        raise HTTPException(400, "MCP body must be a JSON object")

    method = body.get("method")
    if method == "tools/list":
        client = state["client"].get()
        tools = await asyncio.to_thread(client.list_mcp_tools)
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {"tools": tools},
        })
    if method == "tools/call":
        params = body.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not name:
            raise HTTPException(400, "tools/call params.name required")
        client = state["client"].get()
        try:
            result = await asyncio.to_thread(client.call_mcp_tool, name, arguments)
        except Exception as exc:
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": -32000, "message": str(exc)},
            })
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": result,
        })

    return JSONResponse({
        "jsonrpc": "2.0",
        "id": body.get("id"),
        "error": {"code": -32601, "message": f"method {method!r} not supported by Ambassador"},
    })


# ── Wiring helper ───────────────────────────────────────────────────

def install_ambassador(
    app: Any,
    *,
    bearer_token: str,
    client: AmbassadorClient,
    advertised_models: list[str],
    require_local_only: bool = True,
) -> None:
    """Stash Ambassador state on ``app.state.ambassador`` and mount the router.

    Caller is the ``build_app`` factory in ``cullis_connector/web.py``.
    Idempotent: if the router is already mounted, raise; we want a
    loud signal not a silent double-mount.
    """
    if hasattr(app.state, "ambassador") and app.state.ambassador:
        raise RuntimeError("Ambassador already installed on this app")
    app.state.ambassador = {
        "bearer_token": bearer_token,
        "client": client,
        "advertised_models": list(advertised_models),
        "agent_id": client.agent_id,
        "org_id": client.org_id,
        "site_url": getattr(client, "_site_url", ""),
        "require_local_only": require_local_only,
    }
    app.include_router(router)
    _log.info(
        "ambassador installed: agent=%s site=%s models=%s",
        client.agent_id, getattr(client, "_site_url", ""), advertised_models,
    )
