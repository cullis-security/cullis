"""ADR-017 drift fix — Court ``POST /v1/llm/chat`` returns 410 Gone.

After PR #435 the AI gateway lives on Mastio (``mcp_proxy/``). The
parallel Court endpoint that used to forward LLM calls is a zero-trust
bypass surface (it skips Mastio's DPoP + mTLS + policy + audit gates),
so the route now returns ``410 Gone`` with a relocation hint instead of
dispatching anywhere.

These tests assert:
  - the route is still mounted (so callers get the hint, not a 404);
  - the response is a 410 with the documented detail message;
  - the dispatch helper is gone (no path from Court to a real LLM call).
"""
from __future__ import annotations

import importlib

import pytest


@pytest.mark.asyncio
async def test_court_llm_chat_returns_410_gone(client):
    """Any POST to /v1/llm/chat on the Court must return 410 Gone."""
    r = await client.post(
        "/v1/llm/chat",
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "ping"}],
        },
    )
    assert r.status_code == 410, r.text
    body = r.json()
    detail = body["detail"]
    # Operators hitting the legacy endpoint must get an actionable hint
    # pointing them at Mastio, plus the ADR reference for archaeology.
    assert "Mastio" in detail
    assert "/v1/llm/chat" in detail
    assert "ADR-017" in detail


@pytest.mark.asyncio
async def test_court_llm_chat_410_does_not_require_auth(client):
    """410 Gone must come back even without a DPoP token.

    The legacy router used to gate the endpoint behind ``get_current_agent``
    (returning 401 to anonymous callers). Now that the route is a static
    relocation hint, leaking that the path used to exist is harmless and
    the operator UX (a real 410, not a confusing 401) is more useful.
    """
    r = await client.post("/v1/llm/chat", json={})
    assert r.status_code == 410


def test_court_egress_dispatch_helper_is_gone():
    """The ai_gateway dispatch helper that powered the old router must
    not be importable from the Court package anymore. Anything left
    would be a latent bypass surface waiting to be re-wired."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("app.egress.ai_gateway")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("app.egress.schemas")
