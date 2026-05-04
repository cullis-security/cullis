"""Pydantic schemas for Ambassador endpoints.

OpenAI ChatCompletion is the wire format. We accept ``content`` as
either a string or a list of content blocks (multimodal-style) so
clients like Cullis Chat / LibreChat / Cursor that emit different
shapes all work without per-client hacks.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class ChatMessage(BaseModel):
    """OpenAI chat message — flexible content shape.

    Accepted shapes for ``content``:
      - ``str``: the typical case
      - ``list[dict]``: multimodal (e.g. ``[{"type":"text","text":"..."}]``)
      - ``None``: occasional case for assistant tool-call messages

    Anything else passes through as-is to keep the schema permissive
    against new client shapes.
    """
    model_config = ConfigDict(extra="allow")

    role: str
    content: Any | None = None
    tool_calls: list[dict] | None = None
    tool_call_id: str | None = None


class ChatCompletionRequest(BaseModel):
    """OpenAI ChatCompletion request body, permissive."""
    model_config = ConfigDict(extra="allow")

    model: str | None = None
    messages: list[ChatMessage]
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool | None = False
    tools: list[dict] | None = None
    tool_choice: Any | None = None


def extract_text(content: Any) -> str:
    """Flatten OpenAI ``content`` to a single string for routing decisions."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                if block.get("type") == "text" and isinstance(block.get("text"), str):
                    parts.append(block["text"])
                elif isinstance(block.get("content"), str):
                    parts.append(block["content"])
        return "\n".join(p for p in parts if p)
    return str(content)
