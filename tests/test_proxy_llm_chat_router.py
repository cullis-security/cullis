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
from mcp_proxy.egress.ai_gateway import GatewayError, GatewayResult, StreamingDispatch
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
    assert detail["principal_id"] == "orga::alice"
    assert detail["principal_type"] == "agent"
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
async def test_chat_completions_user_principal_recorded(app_with_router, monkeypatch):
    """Frontdesk shared-mode flow: when the auth dep yields a user
    principal (not an agent), the audit row reflects principal_type=user
    so per-principal cost aggregation in Phase B can split user vs agent
    spend without ambiguity."""
    user_principal = InternalAgent(
        agent_id="orga::user::daniele",
        display_name="daniele",
        capabilities=["llm.chat"],
        created_at="2026-05-06T00:00:00Z",
        is_active=True,
        cert_pem=None,
        dpop_jkt="jkt-user",
        reach="both",
        principal_type="user",
    )
    app_with_router.dependency_overrides[get_agent_from_dpop_client_cert] = (
        lambda: user_principal
    )
    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 200, r.text

    rows = await _audit_rows("egress_llm_chat", status="success")
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["principal_id"] == "orga::user::daniele"
    assert detail["principal_type"] == "user"


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
    assert detail["principal_id"] == "orga::alice"
    assert detail["principal_type"] == "agent"
    assert detail["reason"] == "upstream_timeout"
    assert detail["backend"] == "litellm_embedded"
    assert detail["provider"] == "anthropic"
    assert detail["model"] == "claude-haiku-4-5"
    assert detail["upstream_detail"] == "provider 504 after 30s"
    assert detail["trace_id"].startswith("trace_")


@pytest.mark.asyncio
async def test_chat_completions_429_when_token_budget_exhausted(
    app_with_router, monkeypatch,
):
    """When the principal's sliding-window token sum already meets or
    exceeds llm_tokens_per_minute, the next call short-circuits with
    HTTP 429 before reaching the upstream provider, and an audit row
    is written with reason=local_rate_limited_tokens for ops triage."""
    from mcp_proxy.auth.rate_limit import (
        get_token_sum_limiter, reset_agent_rate_limiter,
    )
    from mcp_proxy.config import get_settings

    reset_agent_rate_limiter()
    monkeypatch.setenv("MCP_PROXY_LLM_TOKENS_PER_MINUTE", "100")
    get_settings.cache_clear()

    # Pre-fill the principal's bucket so the next call is over budget.
    limiter = get_token_sum_limiter()
    await limiter.consume("principal:orga::alice:llm_tokens", 100)

    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 429, r.text
    body = r.json()
    assert body["detail"]["reason"] == "local_rate_limited_tokens"
    assert body["detail"]["limit_tokens_per_minute"] == 100
    assert body["detail"]["current_window_tokens"] >= 100

    rows = await _audit_rows("egress_llm_chat", status="error")
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["reason"] == "local_rate_limited_tokens"
    assert detail["principal_id"] == "orga::alice"

    reset_agent_rate_limiter()


@pytest.mark.asyncio
async def test_chat_completions_consumes_tokens_post_call(
    app_with_router, monkeypatch,
):
    """A successful call adds (prompt_tokens + completion_tokens) to
    the principal's window so subsequent peeks see the new usage."""
    from mcp_proxy.auth.rate_limit import (
        get_token_sum_limiter, reset_agent_rate_limiter,
    )

    reset_agent_rate_limiter()
    limiter = get_token_sum_limiter()
    bucket = "principal:orga::alice:llm_tokens"
    assert await limiter.peek(bucket) == 0

    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 200, r.text
    # _gateway_result returns prompt_tokens=12 + completion_tokens=3.
    assert await limiter.peek(bucket) == 15

    reset_agent_rate_limiter()


@pytest.mark.asyncio
async def test_chat_completions_rate_limit_disabled_when_zero(
    app_with_router, monkeypatch,
):
    """Setting llm_tokens_per_minute=0 disables the gate entirely; no
    peek is invoked and no consume is recorded. Useful for benchmarks
    or tightly-controlled pipelines that already cap upstream."""
    from mcp_proxy.auth.rate_limit import (
        get_token_sum_limiter, reset_agent_rate_limiter,
    )
    from mcp_proxy.config import get_settings

    reset_agent_rate_limiter()
    monkeypatch.setenv("MCP_PROXY_LLM_TOKENS_PER_MINUTE", "0")
    get_settings.cache_clear()

    limiter = get_token_sum_limiter()
    bucket = "principal:orga::alice:llm_tokens"
    # Pre-fill above any reasonable cap to prove it's ignored.
    await limiter.consume(bucket, 999_999)

    monkeypatch.setattr(
        router_module, "dispatch",
        AsyncMock(return_value=_gateway_result()),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 200, r.text
    # Bucket unchanged: no consume happened either.
    assert await limiter.peek(bucket) == 999_999

    reset_agent_rate_limiter()


def _parse_sse_frames(body: str) -> list[dict | str]:
    """Split a raw SSE body into frame payloads.

    Each ``data: ...\\n\\n`` becomes one entry: a parsed dict for JSON
    payloads, the literal sentinel string ``[DONE]`` for the terminator.
    Non-data lines (comments, ``event:``) are ignored — the gateway
    never emits them, so any appearance is a regression.
    """
    frames: list[dict | str] = []
    for raw in body.split("\n\n"):
        line = raw.strip()
        if not line:
            continue
        assert line.startswith("data: "), f"non-data SSE line: {line!r}"
        payload = line[len("data: "):]
        if payload == "[DONE]":
            frames.append("[DONE]")
        else:
            frames.append(json.loads(payload))
    return frames


def _build_fake_streamer(
    *,
    chunks: list[dict],
    prompt_tokens: int = 12,
    completion_tokens: int = 3,
    cost_usd: float | None = 0.000123,
    upstream_request_id: str = "req_stream_1",
    raise_mid: GatewayError | None = None,
) -> "callable":
    """Return an ``async`` ``dispatch_stream`` stub.

    The returned callable matches the ``dispatch_stream`` signature and
    yields the supplied chunks. The ``StreamingDispatch`` post-stream
    fields are populated in the generator's ``finally`` so the router's
    audit row sees the same numbers a real backend would write.
    """

    async def fake_dispatch_stream(**kwargs):
        sd = StreamingDispatch(
            backend="litellm_embedded",
            provider="anthropic",
            model=kwargs["req"].model,
            trace_id=kwargs["trace_id"],
        )

        async def _aiter():
            try:
                for chunk in chunks:
                    yield chunk
                if raise_mid is not None:
                    raise raise_mid
            finally:
                sd.prompt_tokens = prompt_tokens
                sd.completion_tokens = completion_tokens
                sd.cost_usd = cost_usd
                sd.upstream_request_id = upstream_request_id
                sd.latency_ms = 25

        sd._aiter_factory = _aiter
        return sd

    return fake_dispatch_stream


@pytest.mark.asyncio
async def test_chat_completions_streaming_happy_path(
    app_with_router, monkeypatch,
):
    """stream=true returns text/event-stream, fans chunk dicts as SSE
    frames, terminates with ``data: [DONE]``, and writes a single
    success audit row with the stream's final token + cost numbers."""
    chunks = [
        {"id": "chatcmpl-stream-1", "choices": [
            {"index": 0, "delta": {"role": "assistant"}, "finish_reason": None},
        ]},
        {"id": "chatcmpl-stream-1", "choices": [
            {"index": 0, "delta": {"content": "pong"}, "finish_reason": None},
        ]},
        {"id": "chatcmpl-stream-1", "choices": [
            {"index": 0, "delta": {}, "finish_reason": "stop"},
        ]},
        {"id": "chatcmpl-stream-1", "choices": [],
         "usage": {"prompt_tokens": 12, "completion_tokens": 3}},
    ]
    monkeypatch.setattr(
        router_module, "dispatch_stream", _build_fake_streamer(chunks=chunks),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.headers.get("x-cullis-trace", "").startswith("trace_")

    frames = _parse_sse_frames(r.text)
    assert frames[-1] == "[DONE]"
    json_frames = [f for f in frames if isinstance(f, dict)]
    assert len(json_frames) == 4
    # cullis_trace_id is injected on every chunk so a downstream audit
    # consumer can correlate even mid-stream.
    for f in json_frames:
        assert f["cullis_trace_id"].startswith("trace_")
    # Content delta survived the round-trip.
    deltas = [c["choices"][0]["delta"] for c in json_frames if c["choices"]]
    assert {"content": "pong"} in deltas

    rows = await _audit_rows("egress_llm_chat", status="success")
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["stream"] is True
    assert detail["prompt_tokens"] == 12
    assert detail["completion_tokens"] == 3
    assert detail["cost_usd"] == 0.000123
    assert detail["upstream_request_id"] == "req_stream_1"
    assert detail["backend"] == "litellm_embedded"


@pytest.mark.asyncio
async def test_chat_completions_streaming_consumes_tokens_post_drain(
    app_with_router, monkeypatch,
):
    """The per-principal token budget is consumed only after the stream
    drains (the upstream usage chunk is the source of truth). A peek
    before the request shows zero, after shows prompt + completion."""
    from mcp_proxy.auth.rate_limit import (
        get_token_sum_limiter, reset_agent_rate_limiter,
    )

    reset_agent_rate_limiter()
    limiter = get_token_sum_limiter()
    bucket = "principal:orga::alice:llm_tokens"
    assert await limiter.peek(bucket) == 0

    monkeypatch.setattr(
        router_module, "dispatch_stream",
        _build_fake_streamer(chunks=[
            {"id": "x", "choices": [
                {"index": 0, "delta": {"content": "hi"}, "finish_reason": None},
            ]},
            {"id": "x", "choices": [],
             "usage": {"prompt_tokens": 7, "completion_tokens": 2}},
        ], prompt_tokens=7, completion_tokens=2),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 200, r.text
    # Drain happened — bucket reflects 7 + 2.
    assert await limiter.peek(bucket) == 9

    reset_agent_rate_limiter()


@pytest.mark.asyncio
async def test_chat_completions_streaming_pre_flight_rate_limit(
    app_with_router, monkeypatch,
):
    """The token-budget gate runs BEFORE the stream is opened, so an
    over-budget principal gets a synchronous 429 (no SSE response). This
    keeps the rejection cheap and surfacable to OpenAI-shape clients
    that special-case the JSON body before flipping into SSE mode."""
    from mcp_proxy.auth.rate_limit import (
        get_token_sum_limiter, reset_agent_rate_limiter,
    )
    from mcp_proxy.config import get_settings

    reset_agent_rate_limiter()
    monkeypatch.setenv("MCP_PROXY_LLM_TOKENS_PER_MINUTE", "100")
    get_settings.cache_clear()

    await get_token_sum_limiter().consume(
        "principal:orga::alice:llm_tokens", 100,
    )

    monkeypatch.setattr(
        router_module, "dispatch_stream",
        _build_fake_streamer(chunks=[]),  # never reached
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 429, r.text
    assert r.headers["content-type"].startswith("application/json")

    rows = await _audit_rows("egress_llm_chat", status="error")
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["reason"] == "local_rate_limited_tokens"
    assert detail["stream"] is True

    reset_agent_rate_limiter()


@pytest.mark.asyncio
async def test_chat_completions_streaming_upstream_error_mid_stream(
    app_with_router, monkeypatch,
):
    """Once the SSE response is open, a mid-stream upstream failure can't
    be turned back into HTTP 5xx. The handler emits one terminal SSE
    frame ``data: {"error":...}`` so OpenAI-shape clients see a
    terminator, then writes an error audit row with whatever tokens were
    counted so ops can scope the cost of the partial call."""
    chunks = [
        {"id": "chatcmpl-err", "choices": [
            {"index": 0, "delta": {"content": "partial"}, "finish_reason": None},
        ]},
    ]
    monkeypatch.setattr(
        router_module, "dispatch_stream",
        _build_fake_streamer(
            chunks=chunks,
            prompt_tokens=5,
            completion_tokens=1,
            raise_mid=GatewayError(
                502, "provider_internal_error", detail="upstream 500 mid-stream",
            ),
        ),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    # The HTTP status is already 200 by the time the body errors —
    # this is the SSE contract.
    assert r.status_code == 200
    frames = _parse_sse_frames(r.text)
    assert "[DONE]" not in frames
    err_frame = frames[-1]
    assert isinstance(err_frame, dict) and "error" in err_frame
    assert err_frame["error"]["type"] == "provider_internal_error"
    assert err_frame["error"]["trace_id"].startswith("trace_")

    rows = await _audit_rows("egress_llm_chat", status="error")
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["reason"] == "provider_internal_error"
    assert detail["stream"] is True
    # Token counters from the partial stream survive into the audit row
    # so cost-attribution dashboards don't lose the burn.
    assert detail["prompt_tokens"] == 5
    assert detail["completion_tokens"] == 1


@pytest.mark.asyncio
async def test_chat_completions_streaming_setup_error_returns_json(
    app_with_router, monkeypatch,
):
    """A configuration-time GatewayError raised by ``dispatch_stream``
    BEFORE any chunk is yielded becomes a synchronous JSON HTTP error,
    not an SSE frame — the SSE response was never opened."""

    async def boom(**_kwargs):
        raise GatewayError(
            503, "provider_key_missing", detail="anthropic_api_key not set",
        )

    monkeypatch.setattr(router_module, "dispatch_stream", boom)

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 503, r.text
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["detail"]["reason"] == "provider_key_missing"

    rows = await _audit_rows("egress_llm_chat", status="error")
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail"])
    assert detail["reason"] == "provider_key_missing"
    assert detail["stream"] is True


# ────────────────────────────────────────────────────────────────────
# P1 Tier B — Cullis Chat SSE backend instrumentation
#
# The frontend SPA's parser (frontend/cullis-chat/src/lib/sse.ts)
# expects named SSE events ``tool_call_start``, ``tool_call_end``,
# and a trailing ``cullis_audit`` summary so the ToolCallIndicator
# chip renders against real backend traffic, not only the mock
# ambassador. These tests pin the Mastio emission shape.
# ────────────────────────────────────────────────────────────────────


def _parse_sse_events(body: str) -> list[dict]:
    """Parse an SSE body that may include both ``data:``-only frames
    and ``event: <name>\\ndata: ...`` named frames.

    Returns a list of records ``{event: str, data: <parsed>}``.
    Default event name is ``"message"`` per the SSE spec when only a
    data line is present; the literal ``[DONE]`` sentinel is preserved
    as a string in ``data``.
    """
    out: list[dict] = []
    for raw in body.split("\n\n"):
        block = raw.strip()
        if not block:
            continue
        event_name = "message"
        data_lines: list[str] = []
        for line in block.split("\n"):
            if line.startswith("event:"):
                event_name = line[len("event:"):].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:"):].lstrip())
        payload_raw = "\n".join(data_lines)
        if payload_raw == "[DONE]":
            out.append({"event": event_name, "data": "[DONE]"})
        else:
            out.append({"event": event_name, "data": json.loads(payload_raw)})
    return out


@pytest.mark.asyncio
async def test_chat_completions_streaming_emits_tool_call_named_events(
    app_with_router, monkeypatch,
):
    """A model that returns tool_calls must produce a paired
    ``tool_call_start`` + ``tool_call_end`` named event per index,
    interleaved with the regular ``data:`` chunk stream, and a
    trailing ``cullis_audit`` summary."""
    chunks = [
        # First delta carries the role.
        {"id": "x", "choices": [
            {"index": 0, "delta": {"role": "assistant"}, "finish_reason": None},
        ]},
        # Model emits the first tool block (name + arg fragment).
        {"id": "x", "choices": [
            {"index": 0, "delta": {"tool_calls": [
                {"index": 0, "id": "call_a", "type": "function",
                 "function": {"name": "search_docs", "arguments": "{\"q\":"}},
            ]}, "finish_reason": None},
        ]},
        # Argument increment for the same tool (no name → no new start).
        {"id": "x", "choices": [
            {"index": 0, "delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": "\"gdpr\"}"}},
            ]}, "finish_reason": None},
        ]},
        # Model emits a second parallel tool block.
        {"id": "x", "choices": [
            {"index": 0, "delta": {"tool_calls": [
                {"index": 1, "id": "call_b", "type": "function",
                 "function": {"name": "postgres.query", "arguments": "{}"}},
            ]}, "finish_reason": None},
        ]},
        # Model finishes the tool_calls assistant turn.
        {"id": "x", "choices": [
            {"index": 0, "delta": {}, "finish_reason": "tool_calls"},
        ]},
        {"id": "x", "choices": [],
         "usage": {"prompt_tokens": 20, "completion_tokens": 10}},
    ]
    monkeypatch.setattr(
        router_module, "dispatch_stream", _build_fake_streamer(chunks=chunks),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 200, r.text
    events = _parse_sse_events(r.text)

    # Two distinct tool blocks → two start + two end events, in order.
    starts = [e for e in events if e["event"] == "tool_call_start"]
    ends = [e for e in events if e["event"] == "tool_call_end"]
    assert [e["data"]["tool"] for e in starts] == ["search_docs", "postgres.query"]
    assert [e["data"]["tool"] for e in ends] == ["search_docs", "postgres.query"]
    for e in ends:
        assert "latency_ms" in e["data"]
        assert isinstance(e["data"]["latency_ms"], int)
        assert e["data"]["latency_ms"] >= 0

    # Trailing cullis_audit event sums up the turn.
    audits = [e for e in events if e["event"] == "cullis_audit"]
    assert len(audits) == 1, audits
    audit = audits[0]["data"]
    assert audit["trace_id"].startswith("trace_")
    assert {t["name"] for t in audit["tools"]} == {"search_docs", "postgres.query"}

    # Each tool_call writes its own audit row so the forensic chain
    # carries one entry per tool, plus the overall egress_llm_chat row.
    tool_rows = await _audit_rows("llm.tool_call", status="success")
    tools_logged = {json.loads(r["detail"])["tool"] for r in tool_rows}
    assert tools_logged == {"search_docs", "postgres.query"}
    for row in tool_rows:
        detail = json.loads(row["detail"])
        assert detail["event"] == "llm.tool_call"
        assert detail["principal_type"] == "agent"
        assert detail["model"] == "claude-haiku-4-5"
        assert detail["trace_id"].startswith("trace_")
        assert detail["latency_ms"] >= 0


@pytest.mark.asyncio
async def test_chat_completions_streaming_no_tool_calls_emits_no_named_events(
    app_with_router, monkeypatch,
):
    """The pure-text path stays a plain data:-only stream so callers
    that don't care about tool chips (CLI, raw curl) see no shape
    change vs. the pre-P1 baseline."""
    chunks = [
        {"id": "x", "choices": [
            {"index": 0, "delta": {"content": "hi"}, "finish_reason": None},
        ]},
        {"id": "x", "choices": [
            {"index": 0, "delta": {}, "finish_reason": "stop"},
        ]},
        {"id": "x", "choices": [],
         "usage": {"prompt_tokens": 5, "completion_tokens": 1}},
    ]
    monkeypatch.setattr(
        router_module, "dispatch_stream", _build_fake_streamer(chunks=chunks),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 200, r.text
    events = _parse_sse_events(r.text)
    assert all(e["event"] == "message" for e in events), [
        e["event"] for e in events
    ]
    tool_rows = await _audit_rows("llm.tool_call")
    assert tool_rows == []


@pytest.mark.asyncio
async def test_chat_completions_streaming_parallel_tool_calls_share_finish(
    app_with_router, monkeypatch,
):
    """Two tool blocks emitted within the same assistant turn both
    close out on the single ``finish_reason='tool_calls'`` chunk."""
    chunks = [
        {"id": "x", "choices": [
            {"index": 0, "delta": {"tool_calls": [
                {"index": 0, "id": "call_a", "type": "function",
                 "function": {"name": "tool_a", "arguments": "{}"}},
                {"index": 1, "id": "call_b", "type": "function",
                 "function": {"name": "tool_b", "arguments": "{}"}},
            ]}, "finish_reason": None},
        ]},
        {"id": "x", "choices": [
            {"index": 0, "delta": {}, "finish_reason": "tool_calls"},
        ]},
        {"id": "x", "choices": [],
         "usage": {"prompt_tokens": 8, "completion_tokens": 4}},
    ]
    monkeypatch.setattr(
        router_module, "dispatch_stream", _build_fake_streamer(chunks=chunks),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    events = _parse_sse_events(r.text)
    starts = [e["data"]["tool"] for e in events if e["event"] == "tool_call_start"]
    ends = [e["data"]["tool"] for e in events if e["event"] == "tool_call_end"]
    assert sorted(starts) == ["tool_a", "tool_b"]
    assert sorted(ends) == ["tool_a", "tool_b"]


@pytest.mark.asyncio
async def test_chat_completions_streaming_malformed_tool_chunk_does_not_break_stream(
    app_with_router, monkeypatch,
):
    """A misshapen ``tool_calls`` payload from a misbehaving provider
    must not poison the user-visible stream. The regular ``data:``
    chunks keep flowing; only the parser entry is skipped."""
    chunks = [
        {"id": "x", "choices": [
            {"index": 0, "delta": {"tool_calls": "not-a-list"},
             "finish_reason": None},
        ]},
        {"id": "x", "choices": [
            {"index": 0, "delta": {"content": "fallback text"},
             "finish_reason": None},
        ]},
        {"id": "x", "choices": [
            {"index": 0, "delta": {}, "finish_reason": "stop"},
        ]},
        {"id": "x", "choices": [],
         "usage": {"prompt_tokens": 5, "completion_tokens": 2}},
    ]
    monkeypatch.setattr(
        router_module, "dispatch_stream", _build_fake_streamer(chunks=chunks),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 200, r.text
    events = _parse_sse_events(r.text)
    # Text content survived.
    text_chunks = [
        e for e in events
        if e["event"] == "message" and isinstance(e["data"], dict)
        and e["data"].get("choices") and e["data"]["choices"][0]["delta"].get("content")
    ]
    assert any(
        c["data"]["choices"][0]["delta"]["content"] == "fallback text"
        for c in text_chunks
    )
    # No false tool events from the malformed payload.
    assert not any(e["event"] == "tool_call_start" for e in events)
