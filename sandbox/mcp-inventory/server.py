"""MCP server: stock availability check (enterprise sandbox demo).

JSON-RPC 2.0 over POST / with a single tool `check_inventory`.
GET /healthz for compose healthcheck.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="mcp-inventory", version="0.1.0")

_PROTOCOL_VERSION = "2024-11-05"
_TOOL = {
    "name": "check_inventory",
    "description": "Check stock availability for a SKU",
    "inputSchema": {
        "type": "object",
        "properties": {"sku": {"type": "string"}},
    },
}

_STOCK: dict[str, dict] = {
    "WIDGET-X": {"sku": "WIDGET-X", "in_stock": True, "quantity": 150, "warehouse": "EU-1"},
    "GADGET-Y": {"sku": "GADGET-Y", "in_stock": True, "quantity": 23, "warehouse": "US-2"},
}


def _rpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


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
        f"mcp-inventory: method={method!r} id={req_id!r} "
        f"params={json.dumps(params, sort_keys=True)}",
        flush=True,
    )

    if method == "initialize":
        return JSONResponse(_rpc_result(req_id, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-inventory", "version": "0.1.0"},
        }))

    if method == "notifications/initialized":
        return JSONResponse(None, status_code=204)

    if method == "tools/list":
        return JSONResponse(_rpc_result(req_id, {"tools": [_TOOL]}))

    if method == "tools/call":
        name = params.get("name")
        if name != "check_inventory":
            return JSONResponse(_rpc_error(req_id, -32601, f"tool not found: {name}"))
        args = params.get("arguments") or {}
        sku = args.get("sku", "")
        stock = _STOCK.get(sku, {"sku": sku, "in_stock": False, "quantity": 0, "warehouse": None})
        return JSONResponse(_rpc_result(req_id, {
            "content": [{"type": "text", "text": json.dumps(stock)}],
            "isError": False,
        }))

    return JSONResponse(_rpc_error(req_id, -32601, f"method not found: {method}"))
