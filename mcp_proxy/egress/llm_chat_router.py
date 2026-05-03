"""ADR-017 Phase 2 — OpenAI-compatible chat completions endpoint.

This router exposes ``POST /v1/chat/completions`` on the proxy so a
custom agent that already speaks the OpenAI Chat Completions API
(e.g. an in-house worker, an OpenAI Python SDK pointed at a different
``base_url``) can be routed through Cullis without code changes:

  agent (mTLS+DPoP) → mcp_proxy /v1/chat/completions
                    → Mastio /v1/llm/chat
                    → AI gateway (Portkey)
                    → upstream provider (Anthropic Haiku 4.5)

The proxy authenticates the agent via the same mTLS+DPoP pair used by
the rest of ``mcp_proxy.egress.router`` (ADR-014), looks up the
agent's CullisClient via ``BrokerBridge``, and forwards the body
through the SDK's ``chat_completion`` helper. Mastio re-stamps the
identity from its own DPoP-bound JWT and writes the egress audit row;
the proxy writes its own local audit row so the on-VM operator can
see the call without querying Mastio.

Standalone-mode proxies (no broker attached) reject with 400 — there
is no fallback to direct Portkey, by design: we want every LLM call
to traverse Mastio's control plane.
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Literal

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.db import log_audit
from mcp_proxy.models import InternalAgent

logger = logging.getLogger("mcp_proxy.egress.llm_chat")

router = APIRouter(tags=["llm-chat"])


ChatRole = Literal["system", "user", "assistant", "tool"]


class ChatMessage(BaseModel):
    role: ChatRole
    content: str


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible request. Kept as a pydantic model only for
    validation; the body is passed through to Mastio as a dict so
    fields the proxy does not know about (e.g. provider-specific
    extras) survive the round trip when Mastio adds support for them."""
    model: str
    messages: list[ChatMessage] = Field(..., min_length=1)
    max_tokens: int | None = Field(None, ge=1, le=8192)
    temperature: float | None = Field(None, ge=0.0, le=2.0)
    stream: bool = False


@router.post("/v1/chat/completions")
async def chat_completions(
    req: ChatCompletionRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
) -> dict:
    if req.stream:
        raise HTTPException(
            status_code=400,
            detail="stream=true is not supported in Phase 2.",
        )

    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "broker_bridge not initialized — proxy is in standalone mode "
                "or the broker is unreachable. /v1/chat/completions requires "
                "a Mastio-attached proxy by design (ADR-017)."
            ),
        )

    started = time.perf_counter()
    body = req.model_dump(exclude_none=True)

    try:
        client = await bridge.get_client(agent.agent_id)
    except Exception as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="error",
            detail=f"broker_bridge_get_client_failed: {exc}",
        )
        raise HTTPException(
            status_code=502,
            detail=f"failed to obtain authenticated broker client: {exc}",
        ) from exc

    try:
        # CullisClient.chat_completion is synchronous httpx; bounce it
        # off the default thread pool so the proxy event loop is not
        # blocked while Portkey + Anthropic process the request.
        response = await asyncio.to_thread(client.chat_completion, body)
    except httpx.HTTPStatusError as exc:
        upstream_status = exc.response.status_code
        upstream_text = (exc.response.text or "")[:512]
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="error",
            detail=(
                f"upstream_status={upstream_status} "
                f"model={req.model} body={upstream_text}"
            ),
        )
        # Forward the original status so the client can distinguish
        # 401 (broker unauth), 502 (gateway), 504 (timeout), 501 (provider).
        raise HTTPException(
            status_code=upstream_status,
            detail={
                "reason": "mastio_upstream_error",
                "upstream_status": upstream_status,
                "upstream_body": upstream_text,
            },
        ) from exc
    except Exception as exc:
        await log_audit(
            agent_id=agent.agent_id,
            action="egress_llm_chat",
            status="error",
            detail=f"unexpected_error: {exc}",
        )
        raise HTTPException(
            status_code=502,
            detail=f"egress LLM call failed: {exc}",
        ) from exc

    latency_ms = int((time.perf_counter() - started) * 1000)
    usage = response.get("usage", {}) if isinstance(response, dict) else {}
    trace_id = response.get("cullis_trace_id") if isinstance(response, dict) else None

    await log_audit(
        agent_id=agent.agent_id,
        action="egress_llm_chat",
        status="success",
        detail=(
            f"model={req.model} "
            f"trace_id={trace_id or 'n/a'} "
            f"latency_ms={latency_ms} "
            f"prompt_tokens={usage.get('prompt_tokens', 0)} "
            f"completion_tokens={usage.get('completion_tokens', 0)}"
        ),
    )

    logger.info(
        "egress_llm_chat agent=%s model=%s latency_ms=%d trace_id=%s",
        agent.agent_id, req.model, latency_ms, trace_id,
    )

    return response
