"""
Tool executor — orchestrates lookup, capability check, secret injection,
context assembly, handler invocation, and audit logging.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from mcp_proxy.db import log_audit
from mcp_proxy.models import TokenPayload, ToolExecuteRequest, ToolExecuteResponse
from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.http_whitelist import ToolExecutionError, WhitelistedTransport
from mcp_proxy.tools.registry import tool_registry
from mcp_proxy.tools.secrets import SecretProvider

_log = logging.getLogger("mcp_proxy.tools.executor")

# Default timeout for tool handler execution (seconds)
DEFAULT_TOOL_TIMEOUT = 30.0


async def run(
    request: ToolExecuteRequest,
    agent: TokenPayload,
    db: Any,
    secret_provider: SecretProvider,
    *,
    timeout: float = DEFAULT_TOOL_TIMEOUT,
) -> ToolExecuteResponse:
    """Execute a tool on behalf of an authenticated agent.

    The ``db`` parameter is retained for API compatibility but no longer
    used — ``log_audit`` opens its own connection via ``get_db()`` since
    the SQLAlchemy async refactor (#36).
    """
    del db  # kept in signature for backwards compatibility
    t0 = time.monotonic()
    tool_name = request.tool
    request_id = request.request_id

    # 1. Lookup
    tool_def = tool_registry.get(tool_name)
    if tool_def is None:
        duration_ms = _elapsed_ms(t0)
        await log_audit(
            agent_id=agent.agent_id,
            action="tool_execute",
            tool_name=tool_name,
            status="error",
            detail="Tool not found",
            request_id=request_id,
            duration_ms=duration_ms,
        )
        return ToolExecuteResponse(
            request_id=request_id,
            tool=tool_name,
            status="error",
            error=f"Tool '{tool_name}' not found",
            execution_time_ms=duration_ms,
        )

    # 2. Capability check
    # ADR-020 — typed principals (user / workload) authorise via the
    # ``local_agent_resource_bindings`` table on the proxy, NOT via the
    # broker-issued JWT scope. The aggregator (``_handle_tools_call``)
    # has already verified an active binding for ``(agent_id,
    # principal_type, resource_id)`` before reaching here, so the
    # legacy scope-based capability gate is redundant for typed
    # principals and would fail closed (the broker's user-token flow
    # ships an empty scope).
    principal_type = getattr(agent, "principal_type", "agent")
    if principal_type == "agent" and not tool_registry.has_capability(
        tool_name, agent.scope,
    ):
        duration_ms = _elapsed_ms(t0)
        _log.warning(
            "Agent '%s' lacks capability '%s' for tool '%s'",
            agent.agent_id,
            tool_def.required_capability,
            tool_name,
        )
        await log_audit(
            agent_id=agent.agent_id,
            action="tool_execute",
            tool_name=tool_name,
            status="denied",
            detail=f"Missing capability: {tool_def.required_capability}",
            request_id=request_id,
            duration_ms=duration_ms,
        )
        return ToolExecuteResponse(
            request_id=request_id,
            tool=tool_name,
            status="error",
            error=f"Forbidden: missing capability '{tool_def.required_capability}'",
            execution_time_ms=duration_ms,
        )

    # 3. Fetch secrets
    try:
        secrets = await secret_provider.get_tool_secrets(tool_name)
    except Exception:
        _log.exception("Failed to fetch secrets for tool '%s'", tool_name)
        secrets = {}

    # 4. Build context
    transport = WhitelistedTransport(allowed_domains=tool_def.allowed_domains)
    async with httpx.AsyncClient(transport=transport) as http_client:
        ctx = ToolContext(
            parameters=request.parameters,
            agent_id=agent.agent_id,
            org_id=agent.org,
            capabilities=agent.scope,
            secrets=secrets,
            http_client=http_client,
            request_id=request_id,
            secret_provider=secret_provider,
        )

        # 5. Execute handler with timeout
        try:
            result = await asyncio.wait_for(
                tool_def.handler(ctx),
                timeout=timeout,
            )
            duration_ms = _elapsed_ms(t0)

            _log.info(
                "Tool '%s' executed successfully for agent '%s' in %.1fms (request=%s)",
                tool_name,
                agent.agent_id,
                duration_ms,
                request_id,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="success",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="success",
                result=result,
                execution_time_ms=duration_ms,
            )

        except asyncio.TimeoutError:
            duration_ms = _elapsed_ms(t0)
            _log.error(
                "Tool '%s' timed out after %.0fs (request=%s)",
                tool_name,
                timeout,
                request_id,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="error",
                detail=f"Timeout after {timeout}s",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error=f"Tool execution timed out after {timeout}s",
                execution_time_ms=duration_ms,
            )

        except ToolExecutionError as exc:
            duration_ms = _elapsed_ms(t0)
            _log.warning(
                "Tool '%s' execution error: %s (request=%s)",
                tool_name,
                exc,
                request_id,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="error",
                detail=str(exc),
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error=str(exc),
                execution_time_ms=duration_ms,
            )

        except Exception as exc:
            duration_ms = _elapsed_ms(t0)
            _log.exception(
                "Unexpected error in tool '%s' (request=%s)",
                tool_name,
                request_id,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="error",
                detail=f"Internal error: {type(exc).__name__}",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error="Internal tool execution error",
                execution_time_ms=duration_ms,
            )


def _elapsed_ms(t0: float) -> float:
    return (time.monotonic() - t0) * 1000.0
