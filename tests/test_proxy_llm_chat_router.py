"""ADR-017 Phase 4 — proxy /v1/chat/completions native AI gateway.

The router is exercised in isolation: a minimal FastAPI app mounts only
the llm_chat_router with the mTLS+DPoP dep overridden to return a fixed
InternalAgent. The proxy DB is initialized in a temp sqlite so log_audit
can write its hash-chained rows. The litellm dispatcher is patched at
``mcp_proxy.egress.llm_chat_router.dispatch`` so we never touch the
network or pay the LiteLLM import cost.

Phase 4 dropped BrokerBridge from the path: the Mastio dispatches the
chat completion in-process via litellm_embedded. No Court round trip.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from sqlalchemy import text

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.egress import llm_chat_router as router_module
from mcp_proxy.egress.ai_gateway import GatewayError, GatewayResult
from mcp_proxy.egress.llm_chat_router import router as llm_chat_router
from mcp_proxy.egress.schemas import (
    ChatCompletionChoice,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionUsage,
    ChatMessage,
)
from mcp_proxy.models import InternalAgent


async def _audit_rows(action: str, status: str | None = None) -> list[dict]:
    sql = "SELECT agent_id, action, status, detail FROM audit_log WHERE action = :a"
    params = {"a": action}
    if status is not None:
        sql += " AND status = :s"
        params["s"] = status
    sql += " ORDER BY chain_seq ASC"
    async with get_db() as conn:
        result = await conn.execute(text(sql), params)
        return [dict(r._mapping) for r in result.fetchall()]


def _agent() -> InternalAgent:
    return InternalAgent(
        agent_id="orga::alice",
        display_name="alice",
        capabilities=["llm.chat"],
        created_at="2026-05-03T00:00:00Z",
        is_active=True,
        cert_pem=None,
        dpop_jkt="jkt-test",
        reach="both",
    )


def _request_body() -> dict:
    return {
        "model": "claude-haiku-4-5",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 16,
    }


def _gateway_result() -> GatewayResult:
    response = ChatCompletionResponse(
        id="chatcmpl-mastio-1",
        created=1_700_000_000,
        model="claude-haiku-4-5",
        choices=[
            ChatCompletionChoice(
                index=0,
                message=ChatMessage(role="assistant", content="pong"),
                finish_reason="stop",
            )
        ],
        usage=ChatCompletionUsage(
            prompt_tokens=12, completion_tokens=3, total_tokens=15,
        ),
        cullis_trace_id="trace_proxy_test",
    )
    return GatewayResult(
        response=response,
        latency_ms=42,
        upstream_request_id="req_abc",
        backend="litellm_embedded",
        provider="anthropic",
        prompt_tokens=12,
        completion_tokens=3,
        cost_usd=0.000123,
    )


@pytest_asyncio.fixture
async def app_with_router(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    # AI gateway settings — required for the router; never reach LiteLLM
    # because dispatch() is patched per-test.
    monkeypatch.setenv("MCP_PROXY_ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("MCP_PROXY_AI_GATEWAY_BACKEND", "litellm_embedded")
    monkeypatch.setenv("MCP_PROXY_AI_GATEWAY_PROVIDER", "anthropic")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "orga")
    # ``get_settings`` is ``lru_cache``-wrapped — clear it so the test
    # picks up the env we just set instead of whatever value a previous
    # xdist worker memoised.
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)

    test_app = FastAPI()
    test_app.include_router(llm_chat_router)
    test_app.dependency_overrides[get_agent_from_dpop_client_cert] = _agent

    yield test_app

    test_app.dependency_overrides.clear()
    get_settings.cache_clear()
    await dispose_db()


@pytest.mark.asyncio
async def test_chat_completions_happy_path_writes_audit(app_with_router, monkeypatch):
    captured: dict = {}

    async def fake_dispatch(*, req: ChatCompletionRequest, agent_id: str,
                            org_id: str, trace_id: str, settings):
        captured["agent_id"] = agent_id
        captured["org_id"] = org_id
        captured["trace_id"] = trace_id
        captured["model"] = req.model
        return _gateway_result()

    monkeypatch.setattr(router_module, "dispatch", fake_dispatch)

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["choices"][0]["message"]["content"] == "pong"
    assert body["cullis_trace_id"] == "trace_proxy_test"

    assert captured["agent_id"] == "orga::alice"
    assert captured["org_id"] == "orga"
    assert captured["model"] == "claude-haiku-4-5"
    assert captured["trace_id"].startswith("trace_")

    rows = await _audit_rows("egress_llm_chat", status="success")
    assert len(rows) == 1
    assert rows[0]["agent_id"] == "orga::alice"
    detail = json.loads(rows[0]["detail"])
    assert detail["event"] == "llm.chat_completion"
    assert detail["backend"] == "litellm_embedded"
    assert detail["provider"] == "anthropic"
    assert detail["model"] == "claude-haiku-4-5"
    assert detail["prompt_tokens"] == 12
    assert detail["completion_tokens"] == 3
    assert detail["cost_usd"] == 0.000123
    assert detail["latency_ms"] >= 0
    assert detail["upstream_request_id"] == "req_abc"
    assert detail["cache_hit"] is False
    assert detail["trace_id"].startswith("trace_")


@pytest.mark.asyncio
async def test_chat_completions_alias_v1_llm_chat(app_with_router, monkeypatch):
    """ADR-017 Phase 4: SDK back-compat. The Connector SDK calls
    /v1/llm/chat (broker path); the proxy serves it via the same handler
    so device-code agents work without an SDK upgrade."""
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/llm/chat", json=_request_body())

    assert r.status_code == 200, r.text
    assert r.json()["choices"][0]["message"]["content"] == "pong"


@pytest.mark.asyncio
async def test_chat_completions_gateway_error_surfaces_status(app_with_router, monkeypatch):
    """A GatewayError carries the upstream HTTP status (e.g. 504 timeout,
    502 unreachable) so callers can distinguish failure modes. Audit row
    is written with reason + provider for ops."""
    async def boom(**_kwargs):
        raise GatewayError(504, "upstream_timeout", detail="provider 504 after 30s")

    monkeypatch.setattr(router_module, "dispatch", boom)

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 504
    body = r.json()
    assert body["detail"]["reason"] == "upstream_timeout"
    assert body["detail"]["trace_id"].startswith("trace_")

    rows = await _audit_rows("egress_llm_chat", status="error")
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["event"] == "llm.chat_completion"
    assert detail["reason"] == "upstream_timeout"
    assert detail["backend"] == "litellm_embedded"
    assert detail["provider"] == "anthropic"
    assert detail["model"] == "claude-haiku-4-5"
    assert detail["upstream_detail"] == "provider 504 after 30s"
    assert detail["trace_id"].startswith("trace_")


@pytest.mark.asyncio
async def test_chat_completions_rejects_streaming(app_with_router, monkeypatch):
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 400
    assert "stream" in r.json()["detail"].lower()
