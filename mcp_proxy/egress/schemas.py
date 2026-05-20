"""OpenAI Chat Completion subset used by the egress endpoint.

Kept intentionally minimal: enough for the spike (Portkey → Anthropic
Haiku 4.5) without dragging in streaming / tool-use / function-calling
which Phase 1 explicitly defers.

F-A-303 (audit 2026-05-20): payload bounds added to each field that
could otherwise grow unbounded. The pydantic ``max_length`` checks
back-stop the body-size middleware in ``mcp_proxy.middleware.
limit_request_body`` — the middleware rejects on declared
Content-Length, the schemas reject anything that slipped past
(chunked uploads, in-process callers). CWE-770 / OWASP A04.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


ChatRole = Literal["system", "user", "assistant", "tool"]

# F-A-303 — per-field ceilings. Sized so legitimate Anthropic /
# OpenAI traffic passes (Anthropic's per-message limit is ~200k
# chars; OpenAI's tool-list practical ceiling is well under 128
# entries) while a single oversized abuse request gets a 422 before
# reaching the upstream gateway.
MAX_CHAT_MESSAGES = 200
MAX_CHAT_TOOLS = 128
MAX_CHAT_MESSAGE_CHARS = 200_000
MAX_CHAT_CONTENT_BLOCKS = 32
MAX_CHAT_TOOL_CALLS = 32


class ChatMessage(BaseModel):
    role: ChatRole
    # OpenAI tool-use messages can carry list-of-blocks content (tool_use,
    # tool_result, text). Accept both shapes; the dispatcher passes them
    # through to LiteLLM which knows how to format per provider.
    # F-A-303 — bound both string content (Anthropic's per-message
    # ceiling) and list-of-blocks length (32 blocks is generous for any
    # legitimate multimodal turn). Pydantic enforces both branches of
    # the union independently.
    content: str | list[dict] | None = Field(
        default=None, max_length=MAX_CHAT_MESSAGE_CHARS,
    )
    # Tool-use round-trip plumbing (OpenAI-compat). When the model
    # returns tool_calls we echo them back in the next turn; the result
    # comes in as role=tool with tool_call_id.
    tool_calls: list[dict] | None = Field(
        default=None, max_length=MAX_CHAT_TOOL_CALLS,
    )
    tool_call_id: str | None = None
    name: str | None = None


class ChatCompletionRequest(BaseModel):
    model: str = Field(..., description="Model id forwarded as-is to the gateway.")
    # F-A-303 — message-count ceiling. 200 turns is far above any
    # interactive session and well above Anthropic's hard limit; a
    # single oversized request can no longer balloon the proxy's
    # memory by appending millions of empty messages.
    messages: list[ChatMessage] = Field(
        ..., min_length=1, max_length=MAX_CHAT_MESSAGES,
    )
    max_tokens: int | None = Field(None, ge=1, le=8192)
    temperature: float | None = Field(None, ge=0.0, le=2.0)
    # stream=true is rejected at the router until Phase 2 wires SSE through.
    stream: bool = False
    # OpenAI-compatible tool-use plumbing. The Connector ambassador
    # discovers MCP tools via list_mcp_tools() and attaches them here so
    # the LLM can choose to invoke one. We forward as-is to LiteLLM
    # (which translates to provider-native tool/function calling shape).
    # F-A-303 — bound tool-list length.
    tools: list[dict] | None = Field(
        default=None, max_length=MAX_CHAT_TOOLS,
    )
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
