"""ADR-007 Phase 1 PR #3 — forwarding handler for DB-loaded MCP resources.

Replaces the PR-2 ``_unwired_handler``. The resource_loader binds this
function to a specific ``ToolDefinition`` via a closure before
registering it, so ``executor.run`` can invoke it exactly like any
builtin handler.

Contract:
  - Authenticated caller's parameters reach the remote MCP server as
    ``params.arguments`` of a JSON-RPC ``tools/call`` envelope.
  - ``auth_secret_ref`` (if set) resolves via the SecretProvider; the
    value is injected as a ``Authorization: Bearer`` or ``X-API-Key``
    header depending on ``auth_type``.
  - Every call emits exactly one ``local_audit`` row with
    ``event_type='resource_call'``. Failure paths (unreachable, HTTP
    error, RPC error) are audited before raising so the chain reflects
    reality even when the remote is down.
  - Hash chain parity is preserved: the new ``event_type`` uses the
    same canonical form as the rest of ``append_local_audit``; payload
    fields (``resource_id``, ``endpoint_url``, ``tool``) live inside
    ``details`` JSON, not as new hashed columns.
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import httpx

from mcp_proxy.local.audit import append_local_audit
from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.http_whitelist import ToolExecutionError, WhitelistedTransport
from mcp_proxy.tools.registry import ToolDefinition

_log = logging.getLogger("mcp_proxy.tools.mcp_resource_forwarder")

DEFAULT_FORWARD_TIMEOUT = 15.0  # seconds — fail fast, no retry

# Streamable HTTP MCP transport (2025-03 spec) requires the client to
# advertise both JSON and SSE. Stateless servers reply with a single
# JSON object; stateful or streaming servers may push SSE frames. We
# accept both and only ever read the first JSON message.
_MCP_ACCEPT = "application/json, text/event-stream"


async def _build_auth_header(
    *,
    auth_type: str,
    auth_secret_ref: str | None,
    secret_provider: Any,
) -> dict[str, str]:
    """Resolve ``auth_secret_ref`` via the SecretProvider.

    Returns an empty dict when auth is disabled, the ref is missing, or
    the provider cannot resolve it — never raises. Misconfiguration
    degrades to "no header" so one bad row cannot cascade-fail an
    unrelated call.
    """
    if auth_type == "none" or not auth_secret_ref:
        return {}
    if secret_provider is None:
        _log.warning(
            "auth_secret_ref=%r set but no SecretProvider available on "
            "ToolContext — forwarding without auth header",
            auth_secret_ref,
        )
        return {}
    try:
        secret = await secret_provider.get_secret_by_ref(auth_secret_ref)
    except Exception:
        _log.exception(
            "SecretProvider lookup failed for ref=%r", auth_secret_ref
        )
        return {}
    if not secret:
        _log.warning("SecretProvider returned no value for ref=%r", auth_secret_ref)
        return {}

    if auth_type == "bearer":
        return {"Authorization": f"Bearer {secret}"}
    if auth_type == "api_key":
        return {"X-API-Key": secret}
    _log.warning("Unknown auth_type=%r — forwarding without auth header", auth_type)
    return {}


def _decode_mcp_response(resp: httpx.Response) -> dict | None:
    """Return the first JSON-RPC message in the response, or None if malformed.

    Streamable HTTP MCP servers may answer with either:
      - ``Content-Type: application/json`` and a single JSON-RPC object, or
      - ``Content-Type: text/event-stream`` and one or more ``data: {...}``
        SSE frames. The spec guarantees the first ``data:`` line for a
        JSON-RPC reply contains the full envelope; we read only that.
    """
    ctype = resp.headers.get("content-type", "").lower()
    if "text/event-stream" in ctype:
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                payload = line[len("data:"):].strip()
                if not payload:
                    continue
                try:
                    parsed = json.loads(payload)
                except ValueError:
                    return None
                return parsed if isinstance(parsed, dict) else None
        return None
    try:
        parsed = resp.json()
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


async def forward_to_mcp_resource(
    ctx: ToolContext,
    *,
    tool_def: ToolDefinition,
) -> Any:
    """Forward a ``tools/call`` to the remote MCP server backing this resource.

    Raises :class:`ToolExecutionError` on any failure so the executor's
    error path produces a clean ``ToolExecuteResponse``. The local
    audit row is written before the raise.
    """
    endpoint = tool_def.endpoint_url
    if not endpoint:
        raise ToolExecutionError(
            f"Resource '{tool_def.name}' has no endpoint_url configured"
        )

    # Private attrs stashed by resource_loader (avoid widening the
    # ToolDefinition dataclass schema for backend-specific metadata).
    auth_type = getattr(tool_def, "_auth_type", "none") or "none"
    auth_secret_ref = getattr(tool_def, "_auth_secret_ref", None)

    auth_header = await _build_auth_header(
        auth_type=auth_type,
        auth_secret_ref=auth_secret_ref,
        secret_provider=ctx.secret_provider,
    )

    payload = {
        "jsonrpc": "2.0",
        "id": ctx.request_id or str(uuid.uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool_def.name,
            "arguments": ctx.parameters,
        },
    }

    audit_details = {
        "resource_id": tool_def.resource_id,
        "endpoint_url": endpoint,
        "tool": tool_def.name,
    }

    transport = WhitelistedTransport(allowed_domains=tool_def.allowed_domains)
    request_headers = {"Accept": _MCP_ACCEPT, **auth_header}
    try:
        async with httpx.AsyncClient(
            transport=transport,
            timeout=DEFAULT_FORWARD_TIMEOUT,
        ) as client:
            resp = await client.post(endpoint, json=payload, headers=request_headers)
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        await append_local_audit(
            event_type="resource_call",
            result="error",
            agent_id=ctx.agent_id,
            org_id=ctx.org_id,
            details={**audit_details, "error": "unreachable", "detail": str(exc)[:200]},
        )
        raise ToolExecutionError(f"MCP resource unreachable: {exc}") from exc

    if resp.status_code in (401, 403):
        await append_local_audit(
            event_type="resource_call",
            result="denied",
            agent_id=ctx.agent_id,
            org_id=ctx.org_id,
            details={**audit_details, "http_status": resp.status_code},
        )
        raise ToolExecutionError(
            f"MCP resource rejected the call with HTTP {resp.status_code}"
        )
    if resp.status_code >= 400:
        await append_local_audit(
            event_type="resource_call",
            result="error",
            agent_id=ctx.agent_id,
            org_id=ctx.org_id,
            details={**audit_details, "http_status": resp.status_code},
        )
        raise ToolExecutionError(
            f"MCP resource returned HTTP {resp.status_code}"
        )

    data = _decode_mcp_response(resp)
    if data is None:
        await append_local_audit(
            event_type="resource_call",
            result="error",
            agent_id=ctx.agent_id,
            org_id=ctx.org_id,
            details={**audit_details, "error": "malformed_json"},
        )
        raise ToolExecutionError("MCP resource returned non-JSON body")

    if isinstance(data, dict) and "error" in data:
        err = data["error"] if isinstance(data["error"], dict) else {"message": str(data["error"])}
        await append_local_audit(
            event_type="resource_call",
            result="error",
            agent_id=ctx.agent_id,
            org_id=ctx.org_id,
            details={**audit_details, "rpc_error": err},
        )
        raise ToolExecutionError(
            f"MCP resource RPC error: {err.get('message', 'unknown')}"
        )

    await append_local_audit(
        event_type="resource_call",
        result="ok",
        agent_id=ctx.agent_id,
        org_id=ctx.org_id,
        details=audit_details,
    )
    return data.get("result") if isinstance(data, dict) else data
