"""ADR-017 Phase 2 — proxy /v1/chat/completions endpoint.

The router is exercised in isolation: a minimal FastAPI app mounts
only the llm_chat_router with the mTLS+DPoP dep overridden to return
a fixed InternalAgent. The proxy DB is initialized in a temp sqlite
so log_audit can write its hash-chained rows. The broker_bridge on
app.state is patched to return a mock CullisClient whose
chat_completion is monkey-patched to whatever the test needs.

We never try to set up real broker auth here — the SDK's
chat_completion (and its DPoP dance) is covered by the broker-side
test_egress_ai_gateway suite shipped in PR #401.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from sqlalchemy import text

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.egress.llm_chat_router import router as llm_chat_router
from mcp_proxy.models import InternalAgent


async def _audit_rows(action: str, status: str | None = None) -> list[dict]:
    """Read back audit rows for assertions. Direct SQL because the
    proxy module exposes only a hash-chain verifier, not a query API.
    """
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


def _mastio_response() -> dict:
    return {
        "id": "chatcmpl-mastio-1",
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
        "cullis_trace_id": "trace_proxy_test",
    }


@pytest_asyncio.fixture
async def app_with_router(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    await init_db(url)

    test_app = FastAPI()
    test_app.include_router(llm_chat_router)
    test_app.dependency_overrides[get_agent_from_dpop_client_cert] = _agent

    yield test_app

    test_app.dependency_overrides.clear()
    await dispose_db()


def _attach_bridge(app: FastAPI, *, chat_response: dict | None = None,
                   chat_exc: Exception | None = None,
                   get_client_exc: Exception | None = None):
    """Wire a fake broker_bridge onto app.state.

    chat_response / chat_exc control what the SDK call returns.
    get_client_exc simulates a broker-bridge bootstrap failure.
    """
    fake_client = MagicMock()
    if chat_exc is not None:
        fake_client.chat_completion = MagicMock(side_effect=chat_exc)
    else:
        fake_client.chat_completion = MagicMock(return_value=chat_response or {})

    fake_bridge = MagicMock()
    if get_client_exc is not None:
        fake_bridge.get_client = AsyncMock(side_effect=get_client_exc)
    else:
        fake_bridge.get_client = AsyncMock(return_value=fake_client)
    app.state.broker_bridge = fake_bridge
    return fake_bridge, fake_client


@pytest.mark.asyncio
async def test_chat_completions_happy_path_writes_audit(app_with_router):
    bridge, fake_client = _attach_bridge(
        app_with_router, chat_response=_mastio_response(),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["choices"][0]["message"]["content"] == "pong"
    assert body["cullis_trace_id"] == "trace_proxy_test"

    bridge.get_client.assert_awaited_once_with("orga::alice")
    fake_client.chat_completion.assert_called_once()
    forwarded_body = fake_client.chat_completion.call_args.args[0]
    assert forwarded_body["model"] == "claude-haiku-4-5"

    rows = await _audit_rows("egress_llm_chat", status="success")
    assert len(rows) == 1
    assert rows[0]["agent_id"] == "orga::alice"
    assert "trace_proxy_test" in (rows[0]["detail"] or "")
    assert "prompt_tokens=12" in (rows[0]["detail"] or "")
    assert "completion_tokens=3" in (rows[0]["detail"] or "")


@pytest.mark.asyncio
async def test_chat_completions_no_bridge_returns_503(app_with_router):
    # Don't attach a bridge — simulate standalone-mode proxy.
    app_with_router.state.broker_bridge = None

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 503
    assert "standalone" in r.json()["detail"].lower() or "broker" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_chat_completions_forwards_upstream_status(app_with_router):
    upstream_resp = httpx.Response(
        status_code=504,
        text='{"detail": {"reason": "upstream_timeout"}}',
        request=httpx.Request("POST", "http://mastio/v1/llm/chat"),
    )
    err = httpx.HTTPStatusError("timeout", request=upstream_resp.request, response=upstream_resp)
    _attach_bridge(app_with_router, chat_exc=err)

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 504
    body = r.json()
    assert body["detail"]["reason"] == "mastio_upstream_error"
    assert body["detail"]["upstream_status"] == 504

    rows = await _audit_rows("egress_llm_chat", status="error")
    assert len(rows) == 1
    assert "upstream_status=504" in (rows[0]["detail"] or "")


@pytest.mark.asyncio
async def test_chat_completions_rejects_streaming(app_with_router):
    _attach_bridge(app_with_router, chat_response=_mastio_response())

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            json={**_request_body(), "stream": True},
        )

    assert r.status_code == 400
    assert "stream" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_chat_completions_get_client_failure_returns_502(app_with_router):
    _attach_bridge(app_with_router, get_client_exc=RuntimeError("agent_credentials_missing"))

    async with AsyncClient(
        transport=ASGITransport(app=app_with_router), base_url="http://test",
    ) as c:
        r = await c.post("/v1/chat/completions", json=_request_body())

    assert r.status_code == 502
    assert "broker client" in r.json()["detail"].lower()

    rows = await _audit_rows("egress_llm_chat", status="error")
    assert len(rows) >= 1
    assert any("broker_bridge_get_client_failed" in (r["detail"] or "") for r in rows)
