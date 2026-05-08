"""DEPRECATED ADR-017 — moved to Mastio.

The Court (``app/``) used to expose ``POST /v1/llm/chat`` and forward
LLM calls to a managed AI gateway (Portkey / LiteLLM / Kong). After
PR #435 the AI gateway is owned by Mastio (``mcp_proxy/``), so calls
from agents must traverse Mastio's DPoP + mTLS + policy + audit gates.

Court keeping a parallel egress endpoint was a zero-trust bypass:
agents that could reach Court directly would have bypassed Mastio's
PDP entirely. This module now returns ``410 Gone`` on any call to
``POST /v1/llm/chat`` so operators hitting it get an actionable hint
to retarget their clients at Mastio's equivalent endpoint.

The live Mastio implementation lives in
``mcp_proxy/egress/llm_chat_router.py`` and
``mcp_proxy/egress/ai_gateway.py``.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/llm", tags=["llm-egress"])


_GONE_DETAIL = (
    "POST /v1/llm/chat moved to the Mastio AI gateway. Configure clients "
    "to call the Mastio's /v1/llm/chat endpoint instead. ADR-017."
)


@router.post("/chat", include_in_schema=False)
async def chat_completion_gone() -> JSONResponse:
    """Return HTTP 410 Gone on the legacy Court egress endpoint.

    The route stays registered (rather than deleted entirely) so callers
    discover the relocation hint instead of a generic 404. The dispatch
    helper that used to call the gateway has been removed; no upstream
    LLM call is reachable through Court anymore.
    """
    return JSONResponse(status_code=410, content={"detail": _GONE_DETAIL})
