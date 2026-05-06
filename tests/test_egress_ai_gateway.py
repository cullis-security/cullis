"""ADR-017 Phase 1 — egress AI gateway dispatcher + /v1/llm/chat router.

The dispatcher is exercised against a httpx MockTransport so we can
assert the exact set of headers Mastio injects toward Portkey (the
trust boundary requirement: agent identity comes from the DPoP-bound
token, never from the client). The router is exercised with
``dependency_overrides`` to skip the full DPoP/JWT dance — that path
is covered by the auth suite. Here we only care that the router maps
GatewayError to HTTP correctly and writes the right audit row.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from sqlalchemy import select

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.config import Settings
from app.db.audit import AuditLog
from app.egress import ai_gateway as ai_gateway_mod
from app.egress.ai_gateway import (
    CULLIS_FORWARD_HEADERS,
    GatewayError,
    GatewayResult,
    dispatch,
)
from app.egress.schemas import ChatCompletionRequest, ChatCompletionResponse
from app.main import app


def _settings(**overrides) -> Settings:
    base = dict(
        admin_secret="test-secret-not-default",
        ai_gateway_backend="portkey",
        ai_gateway_url="http://gw.test",
        ai_gateway_provider="anthropic",
        anthropic_api_key="sk-test",
    )
    base.update(overrides)
    return Settings(**base)


def _request() -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model="claude-haiku-4-5",
        messages=[{"role": "user", "content": "ping"}],
        max_tokens=16,
    )


def _portkey_payload() -> dict:
    return {
        "id": "chatcmpl-upstream-1",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "claude-haiku-4-5",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "pong"},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 12,
            "completion_tokens": 3,
            "total_tokens": 15,
        },
    }


# ── Dispatcher ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_portkey_injects_trusted_headers_and_parses_response():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json=_portkey_payload(),
            headers={"x-portkey-request-id": "pk_req_42"},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await dispatch(
            req=_request(),
            agent_id="acme::mario",
            org_id="acme",
            trace_id="trace_abc",
            settings=_settings(),
            http_client=client,
        )

    assert isinstance(result, GatewayResult)
    assert result.backend == "portkey"
    assert result.provider == "anthropic"
    assert result.upstream_request_id == "pk_req_42"
    assert result.response.choices[0].message.content == "pong"
    assert result.response.usage.prompt_tokens == 12
    assert result.response.cullis_trace_id == "trace_abc"

    # Trust-boundary assertions: Mastio must overwrite identity headers
    # with values derived from the authenticated agent, regardless of
    # what the client sent.
    assert captured["url"] == "http://gw.test/v1/chat/completions"
    h = captured["headers"]
    assert h["authorization"] == "Bearer sk-test"
    assert h["x-portkey-provider"] == "anthropic"
    assert h["x-portkey-trace-id"] == "trace_abc"
    assert h["x-portkey-forward-headers"] == CULLIS_FORWARD_HEADERS
    assert h["x-cullis-agent"] == "acme::mario"
    assert h["x-cullis-org"] == "acme"
    assert h["x-cullis-trace"] == "trace_abc"
    meta = json.loads(h["x-portkey-metadata"])
    assert meta == {"_user": "acme::mario", "org_id": "acme", "trace_id": "trace_abc"}
    # Body must be the OpenAI-compat request (no Mastio fields leaked).
    assert captured["body"]["model"] == "claude-haiku-4-5"
    assert captured["body"]["messages"][0]["content"] == "ping"


@pytest.mark.asyncio
async def test_dispatch_portkey_upstream_5xx_raises_gateway_error():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream pool drained")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GatewayError) as exc_info:
            await dispatch(
                req=_request(),
                agent_id="acme::mario",
                org_id="acme",
                trace_id="t1",
                settings=_settings(),
                http_client=client,
            )

    assert exc_info.value.status_code == 502
    assert exc_info.value.reason == "upstream_status_503"
    assert "drained" in (exc_info.value.detail or "")


@pytest.mark.asyncio
async def test_dispatch_portkey_malformed_body_raises_gateway_error():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GatewayError) as exc_info:
            await dispatch(
                req=_request(),
                agent_id="acme::mario",
                org_id="acme",
                trace_id="t1",
                settings=_settings(),
                http_client=client,
            )

    assert exc_info.value.status_code == 502
    assert exc_info.value.reason == "malformed_upstream_body"


@pytest.mark.asyncio
async def test_dispatch_portkey_missing_provider_key():
    with pytest.raises(GatewayError) as exc_info:
        await dispatch(
            req=_request(),
            agent_id="acme::mario",
            org_id="acme",
            trace_id="t1",
            settings=_settings(anthropic_api_key=""),
        )
    assert exc_info.value.status_code == 503
    assert exc_info.value.reason == "provider_key_missing"


@pytest.mark.asyncio
async def test_dispatch_unimplemented_backend_returns_501():
    with pytest.raises(GatewayError) as exc_info:
        await dispatch(
            req=_request(),
            agent_id="acme::mario",
            org_id="acme",
            trace_id="t1",
            settings=_settings(ai_gateway_backend="litellm"),
        )
    assert exc_info.value.status_code == 501
    assert exc_info.value.reason == "backend_not_implemented:litellm"


@pytest.mark.asyncio
async def test_dispatch_unimplemented_provider_returns_501():
    with pytest.raises(GatewayError) as exc_info:
        await dispatch(
            req=_request(),
            agent_id="acme::mario",
            org_id="acme",
            trace_id="t1",
            settings=_settings(ai_gateway_provider="openai"),
        )
    assert exc_info.value.status_code == 501
    assert exc_info.value.reason.startswith("provider_not_implemented:openai")


# ── Router ──────────────────────────────────────────────────────────────


def _override_agent(agent_id: str = "acme::mario", org: str = "acme") -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.local/{org}/{agent_id.split('::')[-1]}",
        agent_id=agent_id,
        org=org,
        exp=9_999_999_999,
        iat=1_000_000_000,
        jti="jti-test",
        scope=[],
        cnf={"jkt": "test-jkt"},
    )


@pytest.fixture
def authed_agent():
    """Skip the DPoP/JWT dance for router-level tests."""
    app.dependency_overrides[get_current_agent] = lambda: _override_agent()
    yield
    app.dependency_overrides.pop(get_current_agent, None)


@pytest.mark.asyncio
async def test_chat_completion_writes_audit_ok(client, authed_agent, db_session):
    fake_result = GatewayResult(
        response=ChatCompletionResponse.model_validate(
            {**_portkey_payload(), "cullis_trace_id": "trace_xyz"}
        ),
        latency_ms=42,
        upstream_request_id="pk_req_99",
        backend="portkey",
        provider="anthropic",
        prompt_tokens=12,
        completion_tokens=3,
        cost_usd=None,
    )

    with patch.object(
        ai_gateway_mod, "dispatch", new=AsyncMock(return_value=fake_result),
    ):
        # The router imports ``dispatch`` by name, so patch the binding
        # in the router module too.
        with patch("app.egress.router.dispatch", new=AsyncMock(return_value=fake_result)):
            r = await client.post(
                "/v1/llm/chat",
                json={
                    "model": "claude-haiku-4-5",
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 16,
                },
            )

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["choices"][0]["message"]["content"] == "pong"
    assert body["cullis_trace_id"] == "trace_xyz"

    # Filter by trace id — the in-memory test DB is session-scoped and
    # accumulates rows across tests in this file.
    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.event_type == "egress.llm.request")
        )
    ).scalars().all()
    matching = [
        r for r in rows if r.details and json.loads(r.details).get("upstream_request_id") == "pk_req_99"
    ]
    assert len(matching) == 1
    row = matching[0]
    assert row.result == "ok"
    assert row.agent_id == "acme::mario"
    assert row.org_id == "acme"
    details = json.loads(row.details)
    assert details["event"] == "llm.chat_completion"
    assert details["principal_id"] == "acme::mario"
    assert details["principal_type"] == "agent"
    assert details["backend"] == "portkey"
    assert details["provider"] == "anthropic"
    assert details["model"] == "claude-haiku-4-5"
    assert details["latency_ms"] == 42
    assert details["prompt_tokens"] == 12
    assert details["completion_tokens"] == 3
    assert details["total_tokens"] == 15
    assert details["cost_usd"] is None
    assert details["cache_hit"] is False


@pytest.mark.asyncio
async def test_chat_completion_maps_gateway_error_and_logs_denied(
    client, authed_agent, db_session,
):
    err = GatewayError(504, "upstream_timeout", detail="boom")
    with patch("app.egress.router.dispatch", new=AsyncMock(side_effect=err)):
        r = await client.post(
            "/v1/llm/chat",
            json={
                "model": "claude-haiku-4-5",
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
    assert r.status_code == 504
    body = r.json()
    assert body["detail"]["reason"] == "upstream_timeout"

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.event_type == "egress.llm.request")
        )
    ).scalars().all()
    error_rows = [
        r for r in rows
        if r.result == "error"
        and r.details
        and json.loads(r.details).get("upstream_detail") == "boom"
    ]
    assert len(error_rows) == 1
    details = json.loads(error_rows[0].details)
    assert details["reason"] == "upstream_timeout"


@pytest.mark.asyncio
async def test_chat_completion_rejects_streaming_phase1(client, authed_agent):
    r = await client.post(
        "/v1/llm/chat",
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "ping"}],
            "stream": True,
        },
    )
    assert r.status_code == 400
    assert "stream" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_chat_completion_requires_dpop_auth(client):
    # No dependency override here — the real DPoP gate runs and rejects.
    r = await client.post(
        "/v1/llm/chat",
        json={
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "ping"}],
        },
    )
    assert r.status_code == 401
    assert "DPoP" in r.text
