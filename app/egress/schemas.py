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
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = Field(..., description="Model id forwarded as-is to the gateway.")
    messages: list[ChatMessage] = Field(..., min_length=1)
    max_tokens: int | None = Field(None, ge=1, le=8192)
    temperature: float | None = Field(None, ge=0.0, le=2.0)
    # stream=true is rejected at the router until Phase 2 wires SSE through.
    stream: bool = False


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
