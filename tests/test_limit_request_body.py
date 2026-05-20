"""F-A-303 — request body size limit middleware.

The middleware reads the ``Content-Length`` header on every inbound
HTTP request and short-circuits with ``413 Payload Too Large`` when
the advertised size exceeds the configured ceiling. The schema-level
``max_length`` constraints on ``ChatCompletionRequest`` /
``ChatMessage`` / ``ToolExecuteRequest`` catch oversized payloads
once parsed (defence in depth for chunked uploads).

These tests register a one-route FastAPI app behind the middleware
and assert the cap fires on oversize bodies, passes the small-body
path through, and bypasses observability endpoints. A separate
pytest path exercises the pydantic schemas directly so the schema +
middleware cooperation can be reasoned about layer-by-layer.
"""
from __future__ import annotations

import json

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError


# ── helpers ────────────────────────────────────────────────────────


def _build_app(max_bytes: int):
    """Single-route FastAPI app behind the size-limit middleware.

    The handler echoes a fixed payload so each test can read the
    response status + body without dragging in the full mcp_proxy
    app surface.
    """
    from mcp_proxy.middleware.limit_request_body import (
        LimitRequestBodyMiddleware,
    )

    app = FastAPI()
    app.add_middleware(LimitRequestBodyMiddleware, max_bytes=max_bytes)

    @app.post("/echo")
    async def echo() -> dict:
        return {"ok": True}

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.post("/metrics")
    async def metrics() -> dict:
        return {"counters": {}}

    return app


@pytest_asyncio.fixture
async def small_client():
    """Cap at 1 KiB — small enough to exercise the limit cheaply."""
    transport = ASGITransport(app=_build_app(max_bytes=1024))
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ── middleware unit behaviour ──────────────────────────────────────


@pytest.mark.asyncio
async def test_body_under_limit_passes_through(small_client):
    """Bodies below the ceiling reach the handler untouched."""
    resp = await small_client.post(
        "/echo", content=json.dumps({"msg": "hi"}),
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}


@pytest.mark.asyncio
async def test_body_over_limit_rejected_413(small_client):
    """A body above the ceiling triggers 413 before the handler
    fires. CWE-770 — defence-in-depth on the cheap declared-length
    path."""
    oversize = "x" * (1024 + 1024)  # 2 KiB, cap is 1 KiB
    resp = await small_client.post(
        "/echo", content=json.dumps({"msg": oversize}),
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 413, resp.text
    body = resp.json()
    assert body["error"] == "request_body_too_large"
    assert "exceeds" in body["detail"].lower()
    # Audit / metrics annotation header so operators can correlate
    # rejects with the rest of the shedding-reasons family.
    assert resp.headers.get("x-cullis-shed-reason") == "request_body_too_large"


@pytest.mark.asyncio
async def test_body_at_limit_is_accepted(small_client):
    """The ceiling is inclusive — a request whose declared length
    equals the cap passes (only strictly larger is rejected)."""
    # Build a body that lands exactly at the cap (1024 bytes).
    envelope = b'{"msg":""}'
    payload_len = 1024 - len(envelope)
    body = b'{"msg":"' + (b"x" * payload_len) + b'"}'
    assert len(body) == 1024
    resp = await small_client.post(
        "/echo", content=body,
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200, (resp.status_code, len(body))


@pytest.mark.asyncio
async def test_health_endpoint_bypassed(small_client):
    """``/health`` is in the bypass list — operators must never lose
    observability when the size cap fires."""
    resp = await small_client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_metrics_endpoint_bypassed():
    """``/metrics`` is bypassed even for oversize POSTs (scrapers may
    push a heavy body for a Prometheus pushgateway-shaped flow)."""
    transport = ASGITransport(app=_build_app(max_bytes=1024))
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        oversize = "x" * 4096
        resp = await ac.post(
            "/metrics", content=json.dumps({"payload": oversize}),
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_rejected_count_increments():
    """The middleware exposes ``rejected_count`` for metrics + tests."""
    from mcp_proxy.middleware.limit_request_body import (
        LimitRequestBodyMiddleware,
    )

    app = FastAPI()
    mw = None

    # Capture the middleware instance Starlette wraps. The cleanest way
    # is a subclass that records itself on construction.
    captured: list[LimitRequestBodyMiddleware] = []

    class _CapturingMW(LimitRequestBodyMiddleware):
        def __init__(self, app, max_bytes=1024):
            super().__init__(app, max_bytes=max_bytes)
            captured.append(self)

    app.add_middleware(_CapturingMW, max_bytes=1024)

    @app.post("/echo")
    async def echo() -> dict:
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # First the under-limit request.
        ok = await ac.post("/echo", content=b'{"x":1}',
                           headers={"content-type": "application/json"})
        assert ok.status_code == 200
        # Then two rejects.
        for _ in range(2):
            bad = await ac.post(
                "/echo", content=b'{"x":"' + b"y" * 2048 + b'"}',
                headers={"content-type": "application/json"},
            )
            assert bad.status_code == 413

    mw = captured[0]
    assert mw.rejected_count == 2
    assert mw.max_bytes == 1024


@pytest.mark.asyncio
async def test_constructor_rejects_non_positive_max():
    """Misconfiguration must fail loudly at startup, not silently
    disable the size cap."""
    from mcp_proxy.middleware.limit_request_body import (
        LimitRequestBodyMiddleware,
    )

    with pytest.raises(ValueError):
        LimitRequestBodyMiddleware(app=lambda *_: None, max_bytes=0)
    with pytest.raises(ValueError):
        LimitRequestBodyMiddleware(app=lambda *_: None, max_bytes=-1)


# ── schema-layer bounds (defence in depth) ─────────────────────────


def test_schema_messages_max_length_rejects_oversize_list():
    """``ChatCompletionRequest.messages`` is bounded — pydantic
    rejects a request that tries to balloon the message list past
    the per-request ceiling."""
    from mcp_proxy.egress.schemas import (
        MAX_CHAT_MESSAGES, ChatCompletionRequest, ChatMessage,
    )

    too_many = [
        ChatMessage(role="user", content="ping")
        for _ in range(MAX_CHAT_MESSAGES + 1)
    ]
    with pytest.raises(ValidationError) as exc_info:
        ChatCompletionRequest(model="claude-haiku-4-5", messages=too_many)
    assert any(
        "messages" in str(e.get("loc")) and "too_long" in (e.get("type") or "")
        for e in exc_info.value.errors()
    ), exc_info.value.errors()


def test_schema_message_content_max_length_rejects_oversize_string():
    """``ChatMessage.content`` is bounded so a single message cannot
    smuggle a 100 MB string past pydantic."""
    from mcp_proxy.egress.schemas import (
        MAX_CHAT_MESSAGE_CHARS, ChatMessage,
    )

    with pytest.raises(ValidationError):
        ChatMessage(role="user", content="x" * (MAX_CHAT_MESSAGE_CHARS + 1))


def test_schema_tools_max_length_rejects_oversize_list():
    """``ChatCompletionRequest.tools`` is bounded so a caller cannot
    declare a tool catalog far above the realistic ceiling."""
    from mcp_proxy.egress.schemas import (
        MAX_CHAT_TOOLS, ChatCompletionRequest, ChatMessage,
    )

    tools = [{"type": "function", "function": {"name": f"t{i}"}}
             for i in range(MAX_CHAT_TOOLS + 1)]
    with pytest.raises(ValidationError):
        ChatCompletionRequest(
            model="claude-haiku-4-5",
            messages=[ChatMessage(role="user", content="ping")],
            tools=tools,
        )


def test_tool_execute_request_rejects_oversize_parameters():
    """``ToolExecuteRequest.parameters`` carries a ``field_validator``
    that bounds the serialised JSON size. The MCP aggregator's
    ``tools/call`` path uses ``model_construct`` and re-implements
    the check at its call site; this test exercises the direct
    pydantic construction path."""
    from mcp_proxy.models import MAX_TOOL_PARAMETERS_BYTES, ToolExecuteRequest

    # Build a parameters dict whose serialised JSON is just over the
    # ceiling. One large string in a single key dominates the size.
    big_str = "x" * (MAX_TOOL_PARAMETERS_BYTES + 1024)
    with pytest.raises(ValidationError):
        ToolExecuteRequest(tool="echo", parameters={"payload": big_str})


def test_tool_execute_request_accepts_small_parameters():
    """Negative control — small parameter payloads still validate."""
    from mcp_proxy.models import ToolExecuteRequest

    req = ToolExecuteRequest(
        tool="echo",
        parameters={"payload": "hi"},
    )
    assert req.parameters["payload"] == "hi"


# ── aggregator-level guard ────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_aggregator_rejects_oversize_arguments(tmp_path, monkeypatch):
    """``mcp_aggregator._handle_tools_call`` builds
    ``ToolExecuteRequest`` via ``model_construct`` to keep MCP tool
    names with hyphens (regex bypass). That path skips the pydantic
    ``field_validator``, so the aggregator does an explicit
    serialised-size check before invoking the executor. The check
    must fire even though the MCP tool name is well-formed and the
    binding row exists.
    """
    from fastapi.testclient import TestClient

    from mcp_proxy.auth.dependencies import get_authenticated_agent
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import dispose_db, init_db
    from mcp_proxy.models import MAX_TOOL_PARAMETERS_BYTES, TokenPayload
    from mcp_proxy.tools.registry import ToolDefinition, tool_registry

    db_file = tmp_path / "agg_size.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("PROXY_DB_URL", url)
    get_settings.cache_clear()  # type: ignore[attr-defined]
    await init_db(url)

    def _agent() -> TokenPayload:
        return TokenPayload(
            sub="spiffe://cullis.test/acme::buyer",
            agent_id="acme::buyer",
            org="acme",
            exp=9_999_999_999,
            iat=0,
            jti="jti-size",
            scope=["echo.call"],
            cnf={"jkt": "fake-jkt"},
            principal_type="agent",
        )

    # Snapshot + restore tool registry so the test stays isolated.
    saved = dict(tool_registry._tools)
    tool_registry._tools.clear()

    async def _handler(ctx):  # noqa: ARG001
        return {"ok": True}

    tool_registry.register_definition(ToolDefinition(
        name="echo_tool",
        description="echo",
        required_capability="echo.call",
        allowed_domains=[],
        handler=_handler,
    ))

    from mcp_proxy.main import app
    app.dependency_overrides[get_authenticated_agent] = _agent

    try:
        with TestClient(app) as client:
            # Build an arguments dict whose serialised JSON exceeds
            # the per-call cap. The middleware's request-body cap
            # (2 MiB default) is larger than the tool-arguments cap
            # (128 KiB default), so the request body itself stays
            # under the middleware ceiling — the aggregator's
            # explicit JSON-size check is what fires.
            big = "x" * (MAX_TOOL_PARAMETERS_BYTES + 1024)
            resp = client.post("/v1/mcp", json={
                "jsonrpc": "2.0", "id": 99, "method": "tools/call",
                "params": {"name": "echo_tool", "arguments": {"payload": big}},
            })
            assert resp.status_code == 200, resp.text  # JSON-RPC error in body
            body = resp.json()
            # JSON-RPC application error: ERR_INVALID_PARAMS = -32602.
            assert body["error"]["code"] == -32602, body
            assert "exceeds" in body["error"]["message"].lower()
            assert "limit" in body["error"]["message"].lower()
    finally:
        app.dependency_overrides.pop(get_authenticated_agent, None)
        tool_registry._tools.clear()
        tool_registry._tools.update(saved)
        await dispose_db()
        get_settings.cache_clear()  # type: ignore[attr-defined]
