"""Server-side tool-use loop for the Ambassador.

When a chat client (Cullis Chat etc.) sends a ChatCompletion request,
the Ambassador discovers MCP tools the agent is bound to, attaches
them to the LLM call as ``tools=[...]``, and dispatches any
``tool_calls`` returned by the LLM through ``cullis_sdk.call_mcp_tool``
before re-invoking the LLM. Loop terminates when the LLM stops
returning tool_calls, or when ``max_iters`` is exhausted.

This server-side loop spares clients from MCP awareness; they see a
plain ChatCompletion ending in a final assistant content block.

All work goes through the agent's authenticated CullisClient, so
every LLM call and every tool call is audited in Mastio under the
agent's identity.
"""
from __future__ import annotations

import json
import logging
from typing import Any

_log = logging.getLogger("cullis_connector.ambassador.loop")

DEFAULT_MAX_ITERS = 8


def _mcp_tool_to_openai(tool: dict) -> dict:
    """MCP ``tools/list`` shape -> OpenAI ``tools[]`` shape."""
    return {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "parameters": tool.get("inputSchema", {"type": "object"}),
        },
    }


def _mcp_result_to_text(result: Any) -> str:
    """Extract a single text blob from an MCP ``tools/call`` result."""
    if not isinstance(result, dict):
        return json.dumps(result, default=str)
    content = result.get("content")
    if not content:
        return json.dumps(result, default=str)
    parts: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
        else:
            parts.append(json.dumps(item, default=str))
    return "\n".join(p for p in parts if p) or json.dumps(result, default=str)


def run_tool_use_loop(
    client: Any,
    request_body: dict,
    *,
    max_iters: int = DEFAULT_MAX_ITERS,
) -> tuple[dict, bool]:
    """Drive an LLM tool-use loop through Cullis.

    Args:
        client: an authenticated ``CullisClient``.
        request_body: the OpenAI ChatCompletion body the chat client sent.
        max_iters: cap on LLM ↔ tool-call round trips.

    Returns:
        A tuple ``(final_response, truncated)``. ``final_response`` is the
        last ChatCompletion JSON the LLM returned; ``truncated`` is True
        iff the loop exited because of ``max_iters``.

    Raises:
        Whatever the SDK raises (httpx.HTTPStatusError on 4xx/5xx, etc).
    """
    body = dict(request_body)  # shallow copy; we mutate `messages`
    messages: list[dict] = list(body.get("messages", []))

    # Discover tools the agent is bound to. Empty list is fine: the LLM
    # will simply produce a normal answer without tool_calls.
    try:
        mcp_tools = client.list_mcp_tools()
    except Exception:
        _log.exception("list_mcp_tools failed; proceeding without tools")
        mcp_tools = []

    if mcp_tools and "tools" not in body:
        body["tools"] = [_mcp_tool_to_openai(t) for t in mcp_tools]

    truncated = False
    final_response: dict = {}

    for iteration in range(max_iters):
        body["messages"] = messages
        _log.info(
            "tool-use loop iter=%d agent=%s tools=%d msgs=%d",
            iteration + 1,
            getattr(client, "agent_id", "?"),
            len(body.get("tools", []) or []),
            len(messages),
        )
        final_response = client.chat_completion(body)
        if not isinstance(final_response, dict):
            return final_response, False

        choices = final_response.get("choices") or []
        if not choices:
            return final_response, False
        choice = choices[0]
        msg = choice.get("message") or {}
        tool_calls = msg.get("tool_calls") or []

        if not tool_calls:
            return final_response, False

        # Append the assistant message (with tool_calls) verbatim, then
        # dispatch each tool call and append a `role=tool` reply per id.
        messages.append(msg)
        for tc in tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            args_raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except json.JSONDecodeError:
                _log.warning("tool_call args not valid JSON: %r", args_raw[:200])
                args = {}
            try:
                result = client.call_mcp_tool(name, args)
                text = _mcp_result_to_text(result)
            except Exception as exc:  # broad: surface any tool error to the LLM
                _log.exception("tool %s failed", name)
                text = f"tool error: {exc}"
            messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", f"call_{iteration}_{name}"),
                "content": text,
            })

    truncated = True
    _log.warning(
        "tool-use loop exhausted max_iters=%d, returning last response",
        max_iters,
    )
    return final_response, truncated
