"""Multi-provider routing in ``mcp_proxy.egress.ai_gateway``.

We test the resolver in isolation (no LiteLLM, no HTTP) and validate
that ``_call_litellm_embedded`` plumbs the right credentials kwargs
when LiteLLM is mocked.

Background: the gateway used to hard-code ``provider == "anthropic"``
and read the key from ``settings.anthropic_api_key``. After ADR-017
Phase 4 it reads from ``ai_provider_credentials`` per provider parsed
out of the model id.
"""
from __future__ import annotations

import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


async def _spin_proxy(tmp_path, monkeypatch, org_id: str):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    from mcp_proxy.db import init_db
    await init_db(f"sqlite+aiosqlite:///{db_file}")
    return app


# ── _resolve_provider_creds ─────────────────────────────────────────


async def test_resolver_reads_from_db(tmp_path, monkeypatch):
    await _spin_proxy(tmp_path, monkeypatch, "rsv-db")
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import upsert_ai_provider_creds
    from mcp_proxy.egress.ai_gateway import _resolve_provider_creds

    await upsert_ai_provider_creds(
        "anthropic", {"api_key": "sk-ant-DB"},
        enabled=True, updated_by="test",
    )
    provider, creds = await _resolve_provider_creds(
        "claude-haiku-4-5", get_settings(),
    )
    assert provider == "anthropic"
    assert creds["api_key"] == "sk-ant-DB"


async def test_resolver_routes_openai_model(tmp_path, monkeypatch):
    await _spin_proxy(tmp_path, monkeypatch, "rsv-oai")
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import upsert_ai_provider_creds
    from mcp_proxy.egress.ai_gateway import _resolve_provider_creds

    await upsert_ai_provider_creds(
        "openai", {"api_key": "sk-o-1"}, enabled=True,
    )
    provider, creds = await _resolve_provider_creds(
        "gpt-4o-mini", get_settings(),
    )
    assert provider == "openai"
    assert creds["api_key"] == "sk-o-1"


async def test_resolver_503_when_provider_missing(tmp_path, monkeypatch):
    await _spin_proxy(tmp_path, monkeypatch, "rsv-miss")
    from mcp_proxy.config import get_settings
    from mcp_proxy.egress.ai_gateway import GatewayError, _resolve_provider_creds

    # No env fallback, no DB row.
    monkeypatch.setenv("MCP_PROXY_ANTHROPIC_API_KEY", "")
    get_settings.cache_clear()
    with pytest.raises(GatewayError) as ei:
        await _resolve_provider_creds("gemini-1.5-pro", get_settings())
    assert ei.value.status_code == 503
    assert ei.value.reason == "provider_not_configured"


async def test_resolver_503_when_disabled(tmp_path, monkeypatch):
    await _spin_proxy(tmp_path, monkeypatch, "rsv-disabled")
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import upsert_ai_provider_creds
    from mcp_proxy.egress.ai_gateway import GatewayError, _resolve_provider_creds

    await upsert_ai_provider_creds(
        "anthropic", {"api_key": "sk"}, enabled=False,
    )
    with pytest.raises(GatewayError) as ei:
        await _resolve_provider_creds("claude-haiku-4-5", get_settings())
    assert ei.value.reason == "provider_disabled"


async def test_resolver_falls_back_to_env_anthropic(tmp_path, monkeypatch):
    """Backward compat: deployments that haven't seeded the DB row keep working
    when ``ANTHROPIC_API_KEY`` is set the legacy way."""
    monkeypatch.setenv("MCP_PROXY_ANTHROPIC_API_KEY", "sk-env-fallback")
    await _spin_proxy(tmp_path, monkeypatch, "rsv-env")
    from mcp_proxy.config import get_settings
    from mcp_proxy.egress.ai_gateway import _resolve_provider_creds

    provider, creds = await _resolve_provider_creds(
        "claude-haiku-4-5", get_settings(),
    )
    assert provider == "anthropic"
    assert creds == {"api_key": "sk-env-fallback"}


async def test_resolver_no_env_fallback_for_other_providers(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_PROXY_ANTHROPIC_API_KEY", "sk-env")
    await _spin_proxy(tmp_path, monkeypatch, "rsv-noenv")
    from mcp_proxy.config import get_settings
    from mcp_proxy.egress.ai_gateway import GatewayError, _resolve_provider_creds

    # Anthropic env is set but the request asks for OpenAI — must not
    # silently fall back across providers.
    with pytest.raises(GatewayError) as ei:
        await _resolve_provider_creds("gpt-4o", get_settings())
    assert ei.value.reason == "provider_not_configured"


# ── litellm dispatch (mocked) ────────────────────────────────────────


def _install_fake_litellm(monkeypatch, response_payload: dict):
    """Inject a stand-in ``litellm`` module into ``sys.modules``.

    The gateway imports ``litellm`` lazily inside the call functions, so
    patching ``sys.modules`` before the call is enough.
    """
    fake_module = types.ModuleType("litellm")
    fake_module.drop_params = False

    fake_response = MagicMock()
    fake_response.model_dump = MagicMock(return_value=response_payload)
    fake_response.id = response_payload.get("id", "chatcmpl-fake")
    fake_response.usage = types.SimpleNamespace(
        prompt_tokens=10, completion_tokens=20,
    )

    fake_acompletion = AsyncMock(return_value=fake_response)
    fake_module.acompletion = fake_acompletion
    fake_module.completion_cost = MagicMock(return_value=0.000123)
    fake_module.cost_per_token = MagicMock(return_value=(0.0001, 0.0002))

    monkeypatch.setitem(sys.modules, "litellm", fake_module)
    return fake_acompletion


async def test_dispatch_uses_db_credentials_for_anthropic(tmp_path, monkeypatch):
    await _spin_proxy(tmp_path, monkeypatch, "disp-ant")
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import upsert_ai_provider_creds
    from mcp_proxy.egress.ai_gateway import _call_litellm_embedded
    from mcp_proxy.egress.schemas import ChatCompletionRequest

    await upsert_ai_provider_creds(
        "anthropic", {"api_key": "sk-ant-from-db"}, enabled=True,
    )
    fake = _install_fake_litellm(monkeypatch, {
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "created": 0,
        "model": "claude-haiku-4-5",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hi"},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    })

    req = ChatCompletionRequest(
        model="claude-haiku-4-5",
        messages=[{"role": "user", "content": "hi"}],
    )
    out = await _call_litellm_embedded(
        req=req, agent_id="agent-x", org_id="org-x",
        trace_id="t1", settings=get_settings(),
    )
    assert out.provider == "anthropic"
    assert out.backend == "litellm_embedded"
    fake.assert_called_once()
    call = fake.call_args
    assert call.kwargs["api_key"] == "sk-ant-from-db"
    assert call.kwargs["model"] == "claude-haiku-4-5"


async def test_dispatch_routes_openai_with_correct_kwargs(tmp_path, monkeypatch):
    await _spin_proxy(tmp_path, monkeypatch, "disp-oai")
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import upsert_ai_provider_creds
    from mcp_proxy.egress.ai_gateway import _call_litellm_embedded
    from mcp_proxy.egress.schemas import ChatCompletionRequest

    await upsert_ai_provider_creds(
        "openai", {"api_key": "sk-o-9", "api_base": "https://acme/v1"},
        enabled=True,
    )
    fake = _install_fake_litellm(monkeypatch, {
        "id": "chatcmpl-y",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15},
    })

    req = ChatCompletionRequest(
        model="gpt-4o",
        messages=[{"role": "user", "content": "hello"}],
    )
    out = await _call_litellm_embedded(
        req=req, agent_id="agent-y", org_id="org-y",
        trace_id="t2", settings=get_settings(),
    )
    assert out.provider == "openai"
    fake.assert_called_once()
    call = fake.call_args
    assert call.kwargs["api_key"] == "sk-o-9"
    assert call.kwargs["api_base"] == "https://acme/v1"
    # The gateway must NOT inject anthropic kwargs into the openai call.
    assert "aws_region_name" not in call.kwargs


async def test_dispatch_503_when_provider_disabled(tmp_path, monkeypatch):
    await _spin_proxy(tmp_path, monkeypatch, "disp-disabled")
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import upsert_ai_provider_creds
    from mcp_proxy.egress.ai_gateway import (
        GatewayError,
        _call_litellm_embedded,
    )
    from mcp_proxy.egress.schemas import ChatCompletionRequest

    await upsert_ai_provider_creds(
        "anthropic", {"api_key": "sk"}, enabled=False,
    )
    req = ChatCompletionRequest(
        model="claude-haiku-4-5",
        messages=[{"role": "user", "content": "x"}],
    )
    with pytest.raises(GatewayError) as ei:
        await _call_litellm_embedded(
            req=req, agent_id="a", org_id="o",
            trace_id="t", settings=get_settings(),
        )
    assert ei.value.reason == "provider_disabled"
