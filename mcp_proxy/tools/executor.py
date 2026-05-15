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
    app_state: Any | None = None,
) -> ToolExecuteResponse:
    """Execute a tool on behalf of an authenticated agent.

    The ``db`` parameter is retained for API compatibility but no longer
    used — ``log_audit`` opens its own connection via ``get_db()`` since
    the SQLAlchemy async refactor (#36).

    ``app_state`` is the FastAPI ``request.app.state`` object (or
    equivalent) so handlers that need cross-subsystem dependencies
    (broker bridge, WS manager, audit chain) can fetch them from a
    single well-known location. Callers that don't have one (CLI
    paths, unit tests) pass ``None``.
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

    # 2. Capability check (agent-typed principals)
    # ADR-020 — typed principals (user / workload) authorise via the
    # ``local_agent_resource_bindings`` table on the proxy, NOT via the
    # broker-issued JWT scope (which they ship as empty). Agent-typed
    # callers still go through the legacy scope-based gate.
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

    # 2b. Binding check for MCP-resource tools (CRIT-2 fix, audit T3-F1).
    # The JSON-RPC ``tools/call`` aggregator (``mcp_aggregator._handle_tools_call``)
    # gates ``is_mcp_resource`` tools behind ``has_active_binding(...)``
    # before it ever calls ``executor.run``. The REST surface
    # ``POST /v1/ingress/execute`` calls ``executor.run`` directly; pre-fix
    # the binding check was skipped entirely for any ``principal_type !=
    # "agent"``, so a user / workload token could call any registered
    # MCP-resource tool by name with no per-resource grant. Mirror the
    # aggregator's gate here so both ingress paths enforce the same
    # contract.
    if tool_def.is_mcp_resource:
        from mcp_proxy.local.bindings import has_active_binding
        if not await has_active_binding(
            agent.agent_id, principal_type, tool_def.resource_id,
        ):
            duration_ms = _elapsed_ms(t0)
            _log.warning(
                "Principal '%s' (type=%s) has no active binding for "
                "MCP resource '%s' (tool '%s')",
                agent.agent_id, principal_type,
                tool_def.resource_id, tool_name,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="denied",
                detail=(
                    f"No active binding for resource "
                    f"'{tool_def.resource_id}' (principal_type={principal_type})"
                ),
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error=(
                    f"Forbidden: no active binding for resource "
                    f"'{tool_def.resource_id}'"
                ),
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
            app_state=app_state,
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
