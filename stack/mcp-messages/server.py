"""MCP server: persistent message store (modern dogfood stack).

JSON-RPC 2.0 over POST /. Two tools backed by a real SQLite DB:

  * ``send_message(to, body)``       — INSERT a row
  * ``list_messages(for_agent)``     — SELECT rows where recipient=?

The DB lives on a persistent volume so messages survive container
restarts. The point of this server is to show: an agent invoking an
MCP tool that actually mutates persistent state, not just echo.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="mcp-messages", version="0.1.0")

_DB_PATH = Path(os.environ.get("MCP_MESSAGES_DB", "/data/messages.db"))
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_PROTOCOL_VERSION = "2024-11-05"
_TOOLS = [
    {
        "name": "send_message",
        "description": "Persist a message to another agent",
        "inputSchema": {
            "type": "object",
            "required": ["to", "body"],
            "properties": {
                "to": {"type": "string", "description": "Recipient agent id (e.g. orgb::agent-b)"},
                "body": {"type": "string", "description": "Plaintext message body"},
            },
        },
    },
    {
        "name": "list_messages",
        "description": "List messages addressed to an agent",
        "inputSchema": {
            "type": "object",
            "required": ["for_agent"],
            "properties": {
                "for_agent": {"type": "string", "description": "Recipient agent id to query"},
            },
        },
    },
]


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(_DB_PATH, isolation_level=None)
    c.execute(
        "CREATE TABLE IF NOT EXISTS messages ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  recipient TEXT NOT NULL,"
        "  body TEXT NOT NULL,"
        "  created_at REAL NOT NULL"
        ")"
    )
    return c


def _rpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "db": str(_DB_PATH)}


@app.post("/")
async def rpc(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_rpc_error(None, -32700, "parse error"), status_code=400)

    method = body.get("method")
    req_id = body.get("id")
    params = body.get("params") or {}

    print(
        f"mcp-messages: method={method!r} id={req_id!r} "
        f"params={json.dumps(params, sort_keys=True)[:200]}",
        flush=True,
    )

    if method == "initialize":
        return JSONResponse(_rpc_result(req_id, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-messages", "version": "0.1.0"},
        }))

    if method == "notifications/initialized":
        return JSONResponse(None, status_code=204)

    if method == "tools/list":
        return JSONResponse(_rpc_result(req_id, {"tools": _TOOLS}))

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}

        if name == "send_message":
            recipient = args.get("to", "")
            msg_body = args.get("body", "")
            if not recipient or not msg_body:
                return JSONResponse(_rpc_error(req_id, -32602, "to+body required"))
            with _conn() as c:
                cur = c.execute(
                    "INSERT INTO messages (recipient, body, created_at) VALUES (?, ?, ?)",
                    (recipient, msg_body, time.time()),
                )
                row_id = cur.lastrowid
            return JSONResponse(_rpc_result(req_id, {
                "content": [{
                    "type": "text",
                    "text": json.dumps({"ok": True, "id": row_id, "to": recipient}),
                }]
            }))

        if name == "list_messages":
            for_agent = args.get("for_agent", "")
            if not for_agent:
                return JSONResponse(_rpc_error(req_id, -32602, "for_agent required"))
            with _conn() as c:
                rows = c.execute(
                    "SELECT id, body, created_at FROM messages WHERE recipient=? ORDER BY id",
                    (for_agent,),
                ).fetchall()
            messages = [{"id": r[0], "body": r[1], "created_at": r[2]} for r in rows]
            return JSONResponse(_rpc_result(req_id, {
                "content": [{
                    "type": "text",
                    "text": json.dumps({"for_agent": for_agent, "messages": messages}),
                }]
            }))

        return JSONResponse(_rpc_error(req_id, -32601, f"tool not found: {name}"))

    return JSONResponse(_rpc_error(req_id, -32601, f"method not found: {method}"))
