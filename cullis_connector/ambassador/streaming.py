"""Fake-stream SSE wrapper for v0.1 of the Ambassador.

OpenAI clients (Cullis Chat, LibreChat, OpenWebUI, ...) almost always
default to ``stream: true``. The Cullis cloud (``mcp_proxy
/v1/chat/completions``, PR #402) does not yet support streaming and
returns 400 on ``stream=true``. v0.1 bridges the gap by computing the
answer non-stream and fanning it out as one SSE chunk so clients that
require streaming see well-formed events.

When ADR-017 lands real streaming on Mastio, this module is replaced
with a pass-through that forwards upstream chunks verbatim.

The OpenAI streaming envelope uses ``object=chat.completion.chunk``
and emits ``data: {...}\\n\\n`` frames followed by a sentinel
``data: [DONE]\\n\\n``. We mirror that exactly.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Iterator


def _frame(base: dict, delta: dict, finish_reason: str | None = None) -> str:
    chunk = {
        **base,
        "choices": [{
            "index": 0,
            "delta": delta,
            "finish_reason": finish_reason,
        }],
    }
    return f"data: {json.dumps(chunk)}\n\n"


def fake_stream(answer: str, *, model: str, completion_id: str | None = None) -> Iterator[str]:
    """Emit an OpenAI-compatible single-chunk SSE for the given answer.

    Args:
        answer: the full assistant content that the loop produced.
        model: model identifier to echo in the chunk envelope.
        completion_id: optional explicit id; auto-generated otherwise.
    """
    cid = completion_id or f"chatcmpl-cullis-{uuid.uuid4().hex[:12]}"
    base = {
        "id": cid,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
    }

    yield _frame(base, {"role": "assistant"})
    yield _frame(base, {"content": answer})
    yield _frame(base, {}, finish_reason="stop")
    yield "data: [DONE]\n\n"


def extract_assistant_text(response: dict) -> str:
    """Pull the final assistant content out of a ChatCompletion response."""
    if not isinstance(response, dict):
        return ""
    choices = response.get("choices") or []
    if not choices:
        return ""
    msg = choices[0].get("message") or {}
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # OpenAI may return content as blocks for some models
        parts = []
        for b in content:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(b.get("text", ""))
        return "\n".join(p for p in parts if p)
    return ""
