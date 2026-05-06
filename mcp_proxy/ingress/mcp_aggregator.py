"""ADR-007 Phase 1 PR #3 — aggregated MCP server endpoint.

``POST /v1/mcp`` speaks JSON-RPC 2.0. The proxy presents itself as a
single MCP server that exposes the union of:

  * builtin tools (those registered without a ``resource_id``), filtered
    by the agent's capability scope — same semantics as
    ``/v1/ingress/tools``.
  * DB-loaded MCP resources (``local_mcp_resources`` rows), filtered by
    the agent's explicit bindings in ``local_agent_resource_bindings``.

Methods implemented:

  initialize                       — MCP handshake, advertises tools capability.
  notifications/initialized        — no-op ack per spec.
  tools/list                       — binding-filtered tool list.
  tools/call                       — dispatches via executor.run(); the
                                     resource forwarder (PR #3) actually
                                     talks to the remote MCP server.

Authentication is identical to the rest of ingress: DPoP-bound JWT.
Error codes follow JSON-RPC spec with a Cullis-specific range
(-32000 to -32099) for application errors.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.db import get_db
from mcp_proxy.local.audit import append_local_audit
from mcp_proxy.models import TokenPayload, ToolExecuteRequest
from mcp_proxy.tools import executor
from mcp_proxy.tools.registry import tool_registry

router = APIRouter(prefix="/v1/mcp", tags=["mcp-aggregator"])
_log = logging.getLogger("mcp_proxy.ingress.mcp_aggregator")

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "cullis-proxy"
SERVER_VERSION = "0.1.0"

# JSON-RPC error codes.
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603
# Cullis-specific application errors (-32000 to -32099 per spec).
ERR_RESOURCE_NOT_AUTHORIZED = -32000
ERR_RESOURCE_UNREACHABLE = -32001
ERR_RESOURCE_AUTH_FAILED = -32002
ERR_RESOURCE_ERROR = -32003
ERR_TOOL_NOT_FOUND = -32004


def _rpc_error(req_id: Any, code: int, message: str, data: Any = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _rpc_result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


async def _bound_resource_ids(
    principal_id: str, principal_type: str,
) -> set[str]:
    """Return the set of resource_ids this principal currently has active
    bindings for. ADR-020 — keys on ``(agent_id, principal_type)`` so
    a user named "daniele" never inherits an agent named "daniele"'s
    bindings (or vice versa)."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT resource_id
                  FROM local_agent_resource_bindings
                 WHERE agent_id = :a
                   AND principal_type = :pt
                   AND revoked_at IS NULL
                """
            ),
            {"a": principal_id, "pt": principal_type},
        )
        return {row[0] for row in result.all()}


async def _has_active_binding(
    principal_id: str, principal_type: str, resource_id: str,
) -> bool:
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                """
                SELECT 1 FROM local_agent_resource_bindings
                 WHERE agent_id = :a
                   AND principal_type = :pt
                   AND resource_id = :r
                   AND revoked_at IS NULL
                 LIMIT 1
                """
            ),
            {"a": principal_id, "pt": principal_type, "r": resource_id},
        )).first()
        return row is not None


def _stringify(result: Any) -> str:
    """Serialize a handler return value for MCP ``content`` text block."""
    if isinstance(result, str):
        return result
    return json.dumps(result, separators=(",", ":"), sort_keys=True, default=str)


async def _handle_initialize(req_id: Any) -> dict:
    return _rpc_result(req_id, {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    })


async def _handle_tools_list(req_id: Any, agent: TokenPayload) -> dict:
    bound = await _bound_resource_ids(
        agent.agent_id, agent.principal_type,
    )
    agent_caps = set(agent.scope or [])

    tools_out: list[dict] = []
    for td in tool_registry.list_tools():
        if td.is_mcp_resource:
            # MCP resource: binding is the only gate (capability stays
            # informational in Phase 1; binding is the auth decision).
            if td.resource_id not in bound:
                continue
        else:
            # Builtin: capability-gated like /v1/ingress/tools.
            if td.required_capability and td.required_capability not in agent_caps:
                continue

        tools_out.append({
            "name": td.name,
            "description": td.description or "",
            "inputSchema": td.parameters_schema or {
                "type": "object",
                "properties": {},
            },
        })

    return _rpc_result(req_id, {"tools": tools_out})


async def _handle_tools_call(
    req_id: Any,
    params: dict,
    agent: TokenPayload,
    request: Request,
) -> dict:
    name = params.get("name")
    arguments = params.get("arguments") or {}

    if not isinstance(name, str) or not name:
        return _rpc_error(
            req_id, ERR_INVALID_PARAMS,
            "Missing or invalid 'name' in tools/call params",
        )
    if not isinstance(arguments, dict):
        return _rpc_error(
            req_id, ERR_INVALID_PARAMS,
            "'arguments' must be an object",
        )

    tool_def = tool_registry.get(name)
    if tool_def is None:
        return _rpc_error(
            req_id, ERR_TOOL_NOT_FOUND,
            f"Tool '{name}' not found",
        )

    # Binding is the primary authz for MCP resources — audit + deny
    # before even building a ToolContext.
    if tool_def.is_mcp_resource:
        if not await _has_active_binding(
            agent.agent_id, agent.principal_type, tool_def.resource_id,
        ):
            await append_local_audit(
                event_type="resource_call",
                result="denied",
                agent_id=agent.agent_id,
                org_id=agent.org,
                details={
                    "resource_id": tool_def.resource_id,
                    "tool": name,
                    "reason": "no_binding",
                    "principal_type": agent.principal_type,
                },
            )
            return _rpc_error(
                req_id, ERR_RESOURCE_NOT_AUTHORIZED,
                f"No active binding for resource '{tool_def.resource_id}'",
            )

    # MCP resource names can contain hyphens/uppercase (e.g. 'github-mcp')
    # which ToolExecuteRequest's stricter regex would reject at pydantic
    # validation. The aggregator is the *trusted* caller here — it reads
    # the tool name from our own registry, not from user input verbatim
    # — so bypass validation with ``model_construct``.
    exec_req = ToolExecuteRequest.model_construct(
        tool=name,
        parameters=arguments,
        request_id=str(req_id) if req_id is not None else None,
    )

    secret_provider = getattr(request.app.state, "secret_provider", None)
    resp = await executor.run(
        request=exec_req,
        agent=agent,
        db=None,
        secret_provider=secret_provider,
    )

    if resp.status == "success":
        return _rpc_result(req_id, {
            "content": [{"type": "text", "text": _stringify(resp.result)}],
            "isError": False,
        })
    # executor.run always returns status="error" on failure; map to a
    # generic Cullis-range error. The forwarder has already written a
    # detailed local_audit row; this response carries the message.
    return _rpc_error(
        req_id, ERR_RESOURCE_ERROR,
        resp.error or "Tool execution failed",
    )


@router.post("")
async def mcp_endpoint(
    request: Request,
    agent: TokenPayload = Depends(get_authenticated_agent),
) -> JSONResponse:
    """JSON-RPC 2.0 dispatcher — single endpoint per MCP HTTP transport spec."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            _rpc_error(None, ERR_PARSE, "Invalid JSON body"),
            status_code=400,
        )

    if not isinstance(body, dict):
        return JSONResponse(
            _rpc_error(None, ERR_INVALID_REQUEST, "Request must be a JSON object"),
            status_code=400,
        )

    method = body.get("method")
    req_id = body.get("id")
    params = body.get("params") or {}
    if not isinstance(params, dict):
        return JSONResponse(
            _rpc_error(req_id, ERR_INVALID_PARAMS, "'params' must be an object"),
        )

    if method == "initialize":
        return JSONResponse(await _handle_initialize(req_id))

    if method == "notifications/initialized":
        # Notifications don't expect a response, but FastAPI must return
        # something. 204 is the standard "ack without body".
        return JSONResponse(None, status_code=204)

    if method == "tools/list":
        return JSONResponse(await _handle_tools_list(req_id, agent))

    if method == "tools/call":
        return JSONResponse(await _handle_tools_call(req_id, params, agent, request))

    return JSONResponse(
        _rpc_error(req_id, ERR_METHOD_NOT_FOUND, f"Method '{method}' not found"),
    )
