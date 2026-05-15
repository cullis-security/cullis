"""
Ingress router — API endpoints for tool execution and discovery.

Endpoints:
  POST /v1/ingress/execute  — execute a registered tool
  GET  /v1/ingress/tools    — list tools available to the authenticated agent
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request

from mcp_proxy.auth.dependencies import get_authenticated_agent
from mcp_proxy.models import TokenPayload, ToolExecuteRequest, ToolExecuteResponse, ToolInfo
from mcp_proxy.tools import executor
from mcp_proxy.tools.registry import tool_registry
from mcp_proxy.tools.secrets import SecretProvider

_log = logging.getLogger("mcp_proxy.ingress")

router = APIRouter(prefix="/v1/ingress", tags=["ingress"])


def _get_db(request: Request) -> Any:
    """Retrieve the audit DB connection from app state."""
    return getattr(request.app.state, "audit_db", None)


def _get_secret_provider(request: Request) -> SecretProvider:
    """Retrieve the SecretProvider from app state."""
    return request.app.state.secret_provider


@router.post("/execute", response_model=ToolExecuteResponse)
async def execute_tool(
    request_body: ToolExecuteRequest,
    request: Request,
    agent: TokenPayload = Depends(get_authenticated_agent),
) -> ToolExecuteResponse:
    """Execute a tool.  Requires valid JWT + DPoP proof.

    The executor handles:
      - Tool lookup (404 if not found)
      - Capability check (403 if missing)
      - Secret injection
      - Domain-whitelisted HTTP client
      - Timeout enforcement
      - Audit logging
    """
    db = _get_db(request)
    secret_provider = _get_secret_provider(request)

    response = await executor.run(
        request=request_body,
        agent=agent,
        db=db,
        secret_provider=secret_provider,
        app_state=request.app.state,
    )
    return response


@router.get("/tools", response_model=list[ToolInfo])
async def list_tools(
    agent: TokenPayload = Depends(get_authenticated_agent),
) -> list[ToolInfo]:
    """List available tools, filtered by agent capabilities.

    Only tools whose required_capability is present in the agent's
    scope (JWT claim) are returned.
    """
    all_tools = tool_registry.list_tools()
    agent_caps = set(agent.scope)

    visible = [
        ToolInfo(
            name=t.name,
            description=t.description,
            required_capability=t.required_capability,
            parameters_schema=t.parameters_schema,
        )
        for t in all_tools
        if t.required_capability in agent_caps
    ]

    _log.debug(
        "Agent '%s' can see %d/%d tools",
        agent.agent_id,
        len(visible),
        len(all_tools),
    )
    return visible
