"""OpenAI Chat Completion subset used by the egress endpoint.

Kept intentionally minimal: enough for the spike (Portkey → Anthropic
Haiku 4.5) without dragging in streaming / tool-use / function-calling
which Phase 1 explicitly defers.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


ChatRole = Literal["system", "user", "assistant", "tool"]


class ChatMessage(BaseModel):
    role: ChatRole
    # OpenAI tool-use messages can carry list-of-blocks content (tool_use,
    # tool_result, text). Accept both shapes; the dispatcher passes them
    # through to LiteLLM which knows how to format per provider.
    content: str | list[dict] | None = None
    # Tool-use round-trip plumbing (OpenAI-compat). When the model
    # returns tool_calls we echo them back in the next turn; the result
    # comes in as role=tool with tool_call_id.
    tool_calls: list[dict] | None = None
    tool_call_id: str | None = None
    name: str | None = None


class ChatCompletionRequest(BaseModel):
    model: str = Field(..., description="Model id forwarded as-is to the gateway.")
    messages: list[ChatMessage] = Field(..., min_length=1)
    max_tokens: int | None = Field(None, ge=1, le=8192)
    temperature: float | None = Field(None, ge=0.0, le=2.0)
    # stream=true is rejected at the router until Phase 2 wires SSE through.
    stream: bool = False
    # OpenAI-compatible tool-use plumbing. The Connector ambassador
    # discovers MCP tools via list_mcp_tools() and attaches them here so
    # the LLM can choose to invoke one. We forward as-is to LiteLLM
    # (which translates to provider-native tool/function calling shape).
    tools: list[dict] | None = None
    tool_choice: str | dict | None = None


class ChatCompletionUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: str | None = None


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: ChatCompletionUsage = Field(default_factory=ChatCompletionUsage)
    # Mastio-injected trace id propagated end-to-end so the caller can
    # correlate its log with the gateway dashboard and the audit row.
    cullis_trace_id: str
