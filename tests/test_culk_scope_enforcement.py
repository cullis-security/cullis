"""Wave A PR3 — culk_ token scope_paths + scope_providers enforcement.

Audit ref: imp/audits/2026-05-11-MASTER.md Tema A (Track 1 HIGH /
Track 2 H1 / Track 6 M-1 — found by 3 audit subagents independently).

Pre-fix:
- ``scope_paths`` was stored at mint time, displayed in the dashboard,
  but never read at request time. A token "for /v1/chat/completions
  only" worked on every endpoint guarded by
  ``get_agent_from_dpop_client_cert`` (the entire egress + A2A
  surface).
- ``scope_providers`` ditto: a token "anthropic only" worked on every
  provider configured on this Mastio.

Post-fix:
- Resolver enforces ``scope_paths`` glob match against
  ``request.url.path`` and 403s on miss.
- ``llm_chat_router.chat_completions`` enforces ``scope_providers``
  against the provider parsed from the request model and 403s on
  miss with reason ``token_scope_provider_mismatch``.
"""
from __future__ import annotations

import os

os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("KMS_BACKEND", "local")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("ALLOWED_ORIGINS", "")
os.environ.setdefault("ADMIN_SECRET", "test-secret-not-default")
os.environ.setdefault("SKIP_ALEMBIC", "1")

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from mcp_proxy.db import (
    dispose_db,
    init_db,
    mint_user_api_token,
)
from mcp_proxy.egress import llm_chat_router as router_module
from mcp_proxy.egress.llm_chat_router import router as llm_chat_router

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def app_with_real_dep(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.setenv("MCP_PROXY_ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("MCP_PROXY_AI_GATEWAY_BACKEND", "litellm_embedded")
    monkeypatch.setenv("MCP_PROXY_AI_GATEWAY_PROVIDER", "anthropic")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "orga")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)

    async def fake_list_available_models(enabled):
        return [
            {"id": "claude-haiku-4-5", "object": "model", "owned_by": "anthropic"},
            {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
        ]
    monkeypatch.setattr(
        router_module, "list_available_models", fake_list_available_models,
    )

    test_app = FastAPI()
    test_app.include_router(llm_chat_router)
    yield test_app
    get_settings.cache_clear()
    await dispose_db()


# ─── scope_paths ───


async def test_scope_paths_default_v1_glob_allows_v1_models(app_with_real_dep):
    """Default mint sets scope_paths=['/v1/*']. /v1/models is on that
    subtree → resolver lets it through → 200."""
    minted = await mint_user_api_token(
        principal_id="orga::user::alice",
        label="default-scope",
        created_by="orga::admin",
    )
    token = minted["token"]
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get("/v1/models", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text


async def test_scope_paths_narrow_blocks_other_v1_endpoint(app_with_real_dep):
    """Token minted with scope_paths=['/v1/chat/completions'] (a
    legitimate "OpenAI-compat only" intent). Calling /v1/models is
    refused 403 with the resolver's deny message."""
    minted = await mint_user_api_token(
        principal_id="orga::user::bob",
        label="chat-only",
        created_by="orga::admin",
        scope_paths=["/v1/chat/completions"],
    )
    token = minted["token"]
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get("/v1/models", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403, r.text
    assert "scope_paths" in r.text or "scope" in r.text.lower()


async def test_scope_paths_empty_list_unscoped(app_with_real_dep):
    """An explicit empty ``scope_paths=[]`` means "no path restriction"
    — same effect as None (unscoped). Useful when an admin wants a
    token that can hit anything."""
    minted = await mint_user_api_token(
        principal_id="orga::user::carol",
        label="unscoped",
        created_by="orga::admin",
        scope_paths=[],
    )
    token = minted["token"]
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.get("/v1/models", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text


async def test_scope_paths_glob_matches_full_subtree(app_with_real_dep):
    """The ``*`` glob crosses ``/`` so ``/v1/*`` matches every nested
    /v1/... route. Confirms the permissive-glob design vs a strict
    no-slash interpretation."""
    minted = await mint_user_api_token(
        principal_id="orga::user::dave",
        label="default",
        created_by="orga::admin",
        # explicit default
        scope_paths=["/v1/*"],
    )
    token = minted["token"]
    # Both /v1/models and any deeper /v1/foo/bar should pass at the
    # resolver level (downstream may 404 on unknown route, that's OK).
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r1 = await c.get("/v1/models", headers={"Authorization": f"Bearer {token}"})
        r2 = await c.get(
            "/v1/nonexistent/path",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r1.status_code == 200
    # 404 means the resolver passed and the route is just unknown —
    # not a 403 from the scope gate.
    assert r2.status_code in (404,), r2.text


# ─── scope_providers ───


async def test_scope_providers_match_anthropic_succeeds(
    app_with_real_dep, monkeypatch,
):
    """Token scoped to ['anthropic']. Request model claude-haiku-4-5 →
    parse_provider returns 'anthropic' → in list → resolver allows.
    We mock ai_gateway.dispatch so the test doesn't touch upstream."""

    async def fake_dispatch(**kwargs):
        from mcp_proxy.egress.schemas import ChatCompletionResponse
        from types import SimpleNamespace
        # Minimal valid response shape.
        resp = ChatCompletionResponse.model_validate({
            "id": "chatcmpl-test", "object": "chat.completion",
            "created": 1, "model": kwargs["req"].model,
            "cullis_trace_id": kwargs["trace_id"],
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })
        return SimpleNamespace(
            response=resp, latency_ms=10, upstream_request_id="req-x",
            backend="litellm_embedded", provider="anthropic",
            prompt_tokens=1, completion_tokens=1, cost_usd=None,
        )
    monkeypatch.setattr(router_module, "dispatch", fake_dispatch)

    minted = await mint_user_api_token(
        principal_id="orga::user::eve",
        label="anthropic-only",
        created_by="orga::admin",
        scope_providers=["anthropic"],
    )
    token = minted["token"]
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "model": "claude-haiku-4-5",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
    assert r.status_code == 200, r.text


async def test_scope_providers_mismatch_denied(app_with_real_dep, monkeypatch):
    """Token scoped to ['anthropic']. Request model gpt-4o-mini →
    parse_provider returns 'openai' → NOT in list → 403 with
    ``token_scope_provider_mismatch`` reason."""
    minted = await mint_user_api_token(
        principal_id="orga::user::frank",
        label="anthropic-only-tries-openai",
        created_by="orga::admin",
        scope_providers=["anthropic"],
    )
    token = minted["token"]
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
    assert r.status_code == 403, r.text
    body = r.json()
    detail = body.get("detail") or body
    # detail is a dict here per the router's structured 403 body.
    assert detail.get("reason") == "token_scope_provider_mismatch", body
    assert "anthropic" in detail.get("allowed_providers", [])


async def test_scope_providers_empty_no_gate(app_with_real_dep, monkeypatch):
    """Token with scope_providers=[] (default mint state) → provider
    gate skipped entirely. Any model goes through to dispatch."""
    from types import SimpleNamespace
    async def fake_dispatch(**kwargs):
        from mcp_proxy.egress.schemas import ChatCompletionResponse
        resp = ChatCompletionResponse.model_validate({
            "id": "chatcmpl-test", "object": "chat.completion",
            "created": 1, "model": kwargs["req"].model,
            "cullis_trace_id": kwargs["trace_id"],
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })
        return SimpleNamespace(
            response=resp, latency_ms=10, upstream_request_id="req-x",
            backend="litellm_embedded", provider="openai",
            prompt_tokens=1, completion_tokens=1, cost_usd=None,
        )
    monkeypatch.setattr(router_module, "dispatch", fake_dispatch)

    minted = await mint_user_api_token(
        principal_id="orga::user::grace",
        label="any-provider",
        created_by="orga::admin",
        scope_providers=[],
    )
    token = minted["token"]
    async with AsyncClient(
        transport=ASGITransport(app=app_with_real_dep), base_url="http://test",
    ) as c:
        r = await c.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
    assert r.status_code == 200, r.text
