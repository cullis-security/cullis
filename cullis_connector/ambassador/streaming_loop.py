"""Streaming tool-use loop for the Ambassador (P1 Tier B F2b).

Companion to :mod:`cullis_connector.ambassador.loop`. ``run_tool_use_loop``
is a multi-turn non-streaming loop that collapses the entire chat into
one final answer and lets ``router.fake_stream`` fan that single answer
as SSE frames. That hides every intermediate step — most importantly,
the ``tool_call_start`` / ``tool_call_end`` named events the Mastio's
streaming endpoint emits (see PR #719) never reach the SPA.

This module is the streaming counterpart. It:

* calls the Mastio with ``stream=True``;
* yields each upstream SSE frame to the caller verbatim, so token
  chunks, ``tool_call_start`` and ``tool_call_end`` flow to the SPA
  in real time;
* accumulates the streamed ``delta.tool_calls`` into a complete
  assistant ``message.tool_calls`` so the Connector can execute each
  tool through ``client.call_mcp_tool`` between turns;
* runs the same PDP gate (ADR-029 Phase D) as the non-streaming loop;
* swallows per-turn ``cullis_audit`` events and the per-turn
  ``[DONE]`` sentinel, then emits a single aggregated ``cullis_audit``
  summary + final ``[DONE]`` at the end of the multi-turn run. The
  SPA therefore sees exactly one summary regardless of how many
  Mastio round trips happened, matching the mock ambassador shape
  (``frontend/cullis-chat/mock/ambassador.mjs``).

Sync generator: FastAPI's ``StreamingResponse`` runs sync iterators
in a thread executor, so we avoid the async-bridge overhead and stay
parallel to ``streaming.fake_stream``.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterator

from cullis_connector.ambassador.loop import (
    _mcp_result_to_text,
    _mcp_tool_to_openai,
    DEFAULT_MAX_ITERS,
)

_log = logging.getLogger("cullis_connector.ambassador.streaming_loop")


def _parse_sse_frame(frame: str) -> tuple[str | None, str]:
    """Parse one SSE frame into ``(event_name, data_payload)``.

    A ``data:``-only frame returns ``(None, payload)``. The data lines
    are joined with ``\\n`` per the SSE spec so a multi-line ``data:``
    block survives. The frame string passed in is expected to be
    already trimmed of its trailing ``\\n\\n``.
    """
    event: str | None = None
    data_lines: list[str] = []
    for line in frame.split("\n"):
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:"):].lstrip())
    return event, "\n".join(data_lines)


def _merge_tool_call_delta(
    accumulated: list[dict], delta_tcs: list[dict],
) -> None:
    """Fold a ``delta.tool_calls`` streaming delta into the per-turn
    accumulator keyed by index.

    The first delta on a given index carries ``id``, ``type`` and
    ``function.name``. Subsequent deltas only append text to
    ``function.arguments``. This mirrors what OpenAI clients do
    internally; LiteLLM normalises every provider to this shape, so
    one parser covers Anthropic, OpenAI, Bedrock, etc.
    """
    for tc in delta_tcs:
        idx = tc.get("index", 0)
        while len(accumulated) <= idx:
            accumulated.append({
                "id": "",
                "type": "function",
                "function": {"name": "", "arguments": ""},
            })
        entry = accumulated[idx]
        if tc.get("id"):
            entry["id"] = tc["id"]
        if tc.get("type"):
            entry["type"] = tc["type"]
        fn = tc.get("function") or {}
        if fn.get("name"):
            entry["function"]["name"] = fn["name"]
        if fn.get("arguments"):
            entry["function"]["arguments"] += fn["arguments"]


def stream_tool_use_loop(
    client: Any,
    request_body: dict,
    *,
    max_iters: int = DEFAULT_MAX_ITERS,
    pdp_enabled: bool = False,
    principal_id: str | None = None,
    principal_type: str = "user",
    principal_org: str | None = None,
    session_id: str | None = None,
) -> Iterator[str]:
    """Stream-aware multi-turn tool-use loop.

    Same identity / PDP / max_iters semantics as
    :func:`cullis_connector.ambassador.loop.run_tool_use_loop`, but
    yields SSE frame strings as the upstream Mastio produces them.

    Yields:
        Raw SSE frames (``"data: ...\\n\\n"``, ``"event: ...\\n
        data: ...\\n\\n"``). The terminator
        ``"data: [DONE]\\n\\n"`` is the last yielded frame.
    """
    body = dict(request_body)
    messages: list[dict] = list(body.get("messages", []))

    try:
        mcp_tools = client.list_mcp_tools()
    except Exception:
        _log.exception("list_mcp_tools failed; proceeding without tools")
        mcp_tools = []

    if mcp_tools and "tools" not in body:
        body["tools"] = [_mcp_tool_to_openai(t) for t in mcp_tools]

    aggregated_tools: list[dict] = []
    aggregated_latency_ms: int = 0
    last_trace_id: str = ""
    truncated = False

    for iteration in range(max_iters):
        body["messages"] = messages
        body["stream"] = True
        _log.info(
            "streaming tool-use loop iter=%d agent=%s tools=%d msgs=%d",
            iteration + 1,
            getattr(client, "agent_id", "?"),
            len(body.get("tools", []) or []),
            len(messages),
        )

        turn_tool_calls: list[dict] = []
        finish_reason: str | None = None

        for frame_str in client.chat_completion_stream(body):
            event, data_raw = _parse_sse_frame(frame_str.strip())

            if event == "cullis_audit":
                # Buffer per-turn audit; emit a single aggregate at end.
                try:
                    a = json.loads(data_raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(a.get("tools"), list):
                    aggregated_tools.extend(a["tools"])
                latency = a.get("latency_ms")
                if isinstance(latency, int):
                    aggregated_latency_ms += latency
                if a.get("trace_id"):
                    last_trace_id = str(a["trace_id"])
                continue

            if data_raw == "[DONE]":
                # Consume Mastio's per-turn DONE; emit our own at end.
                continue

            # Pass through anything else verbatim:
            # token deltas, tool_call_start, tool_call_end.
            yield frame_str if frame_str.endswith("\n\n") else frame_str + "\n\n"

            # Peek at default-event data:chunks to grow the
            # tool_calls accumulator and watch for finish_reason.
            if event is None:
                try:
                    chunk = json.loads(data_raw)
                except json.JSONDecodeError:
                    continue
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                choice0 = choices[0]
                delta = choice0.get("delta") or {}
                delta_tcs = delta.get("tool_calls") or []
                if delta_tcs:
                    _merge_tool_call_delta(turn_tool_calls, delta_tcs)
                fr = choice0.get("finish_reason")
                if fr:
                    finish_reason = fr

        if finish_reason != "tool_calls":
            break

        if not turn_tool_calls:
            _log.warning(
                "stream ended with finish_reason=tool_calls but no "
                "tool_calls delta was collected; aborting loop",
            )
            break

        # Build the assistant message and execute each MCP tool.
        # Same flow as run_tool_use_loop, just driven off streamed state.
        messages.append({
            "role": "assistant",
            "content": None,
            "tool_calls": turn_tool_calls,
        })

        for tc in turn_tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            args_raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except json.JSONDecodeError:
                _log.warning("tool_call args not valid JSON: %r", args_raw[:200])
                args = {}

            policy_blocked: tuple[bool, str] = (False, "")
            if pdp_enabled and principal_id:
                try:
                    pdp = client.evaluate_tool_call_policy(
                        principal_id=principal_id,
                        principal_type=principal_type,
                        org=principal_org,
                        model_id=body.get("model"),
                        tool_name=name,
                        session_id=session_id,
                    )
                except Exception as exc:
                    _log.warning("PDP transport failure on tool %s: %s", name, exc)
                    pdp = {"allowed": False, "reason": f"PDP transport: {exc}"}
                if not pdp.get("allowed"):
                    policy_blocked = (True, str(pdp.get("reason") or ""))
                    _log.info(
                        "tool %s denied by PDP: %s", name, policy_blocked[1],
                    )

            if policy_blocked[0]:
                text = (
                    f"policy_denied: tool '{name}' refused by policy: "
                    f"{policy_blocked[1]}"
                )
            else:
                try:
                    result = client.call_mcp_tool(name, args)
                    text = _mcp_result_to_text(result)
                except Exception as exc:
                    _log.exception("tool %s failed", name)
                    text = f"tool error: {exc}"
            messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id") or f"call_{iteration}_{name}",
                "content": text,
            })
    else:
        # for-else: max_iters exhausted without break.
        truncated = True
        _log.warning(
            "streaming tool-use loop exhausted max_iters=%d", max_iters,
        )

    summary: dict[str, Any] = {
        "trace_id": last_trace_id,
        "latency_ms": aggregated_latency_ms,
        "tools": aggregated_tools,
    }
    if truncated:
        summary["truncated"] = True
    yield f"event: cullis_audit\ndata: {json.dumps(summary)}\n\n"
    yield "data: [DONE]\n\n"
