"""ADR-017 Phase 3 — embedded LiteLLM backend tests.

The Phase 1 suite covers the Portkey backend; this module covers the
new in-process LiteLLM path. We never call the real ``litellm.acompletion``
here — that's what the live spike in
``imp/sandbox-gateways/test/spike_litellm_acompletion.py`` is for.
The unit tests verify:

  - happy path returns a parsed ChatCompletionResponse with usage
    canonicalized and ``cullis_trace_id`` injected;
  - LiteLLM provider exceptions map to GatewayError with the right
    HTTP status (auth=401, rate=429, timeout=504, ...);
  - missing provider key + wrong provider both refuse with the
    matching reason tags.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.config import Settings
from app.egress.ai_gateway import (
    GatewayError,
    GatewayResult,
    _map_litellm_exception,
    dispatch,
)
from app.egress.schemas import ChatCompletionRequest


def _settings(**overrides) -> Settings:
    base = dict(
        admin_secret="test-secret-not-default",
        ai_gateway_backend="litellm_embedded",
        ai_gateway_provider="anthropic",
        anthropic_api_key="sk-test",
    )
    base.update(overrides)
    return Settings(**base)


def _request() -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model="anthropic/claude-haiku-4-5",
        messages=[{"role": "user", "content": "ping"}],
        max_tokens=16,
    )


def _fake_litellm_response() -> SimpleNamespace:
    """Approximate a LiteLLM ModelResponse: pydantic-flavoured object
    with ``usage`` + ``model_dump()`` + ``id``."""
    usage = SimpleNamespace(
        prompt_tokens=12,
        completion_tokens=3,
        total_tokens=15,
    )
    full_dict = {
        "id": "chatcmpl-litellm-1",
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
            # provider-specific extras LiteLLM forwards from Anthropic
            "cached_tokens": 0,
            "prompt_tokens_details": {"text_tokens": 12},
        },
    }
    return SimpleNamespace(
        id=full_dict["id"],
        usage=usage,
        model_dump=lambda: full_dict,
    )


# ── Happy path ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_litellm_embedded_returns_parsed_response():
    fake_resp = _fake_litellm_response()

    with patch("litellm.acompletion", new=AsyncMock(return_value=fake_resp)) as mock_acomp, \
         patch("litellm.completion_cost", return_value=0.00004):
        result = await dispatch(
            req=_request(),
            agent_id="acme::mario",
            org_id="acme",
            trace_id="trace_litellm_test",
            settings=_settings(),
        )

    assert isinstance(result, GatewayResult)
    assert result.backend == "litellm_embedded"
    assert result.provider == "anthropic"
    assert result.upstream_request_id == "chatcmpl-litellm-1"
    assert result.response.choices[0].message.content == "pong"
    assert result.response.cullis_trace_id == "trace_litellm_test"
    # Phase 1 schema only knows the canonical 3 usage fields; provider
    # extras must not leak through and break model validation.
    assert result.response.usage.prompt_tokens == 12
    assert result.response.usage.completion_tokens == 3
    assert result.response.usage.total_tokens == 15

    # The dispatcher must inject Cullis metadata so any LiteLLM
    # callback the operator wires up (Datadog, Langfuse, ...) sees the
    # trusted agent identity.
    mock_acomp.assert_awaited_once()
    kwargs = mock_acomp.call_args.kwargs
    assert kwargs["model"] == "anthropic/claude-haiku-4-5"
    assert kwargs["api_key"] == "sk-test"
    assert kwargs["metadata"] == {
        "cullis_agent_id": "acme::mario",
        "cullis_org_id": "acme",
        "cullis_trace_id": "trace_litellm_test",
    }
    # max_tokens forwarded from the OpenAI-shape body
    assert kwargs["max_tokens"] == 16


@pytest.mark.asyncio
async def test_dispatch_survives_missing_completion_cost():
    """response_cost lookup is best-effort; a failure must not block
    the call (audit row will record cost as unknown)."""
    fake_resp = _fake_litellm_response()
    with patch("litellm.acompletion", new=AsyncMock(return_value=fake_resp)), \
         patch("litellm.completion_cost", side_effect=Exception("model not in catalogue")):
        result = await dispatch(
            req=_request(),
            agent_id="acme::mario",
            org_id="acme",
            trace_id="trace_no_cost",
            settings=_settings(),
        )
    assert result.backend == "litellm_embedded"
    assert result.response.usage.prompt_tokens == 12


# ── Error mapping ───────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc_class_name,expected_status,expected_reason",
    [
        ("AuthenticationError", 401, "provider_auth_failed"),
        ("PermissionDeniedError", 403, "provider_permission_denied"),
        ("RateLimitError", 429, "provider_rate_limited"),
        ("BadRequestError", 400, "provider_bad_request"),
        ("Timeout", 504, "provider_timeout"),
        ("APIConnectionError", 502, "provider_unreachable"),
        ("ContextWindowExceededError", 400, "provider_context_too_long"),
        ("ServiceUnavailableError", 502, "provider_unavailable"),
        ("InternalServerError", 502, "provider_internal_error"),
    ],
)
async def test_dispatch_maps_litellm_exceptions(
    exc_class_name, expected_status, expected_reason,
):
    """Build a fake exception class with the LiteLLM name. The map is
    keyed by class name (not isinstance) so this is the right level to
    test it."""
    FakeExc = type(exc_class_name, (Exception,), {})
    with patch("litellm.acompletion", new=AsyncMock(side_effect=FakeExc("upstream boom"))):
        with pytest.raises(GatewayError) as exc_info:
            await dispatch(
                req=_request(),
                agent_id="acme::mario",
                org_id="acme",
                trace_id="t-err",
                settings=_settings(),
            )
    assert exc_info.value.status_code == expected_status
    assert exc_info.value.reason == expected_reason
    assert "upstream boom" in (exc_info.value.detail or "")


@pytest.mark.asyncio
async def test_dispatch_unknown_exception_falls_back_to_502():
    class WeirdProviderError(Exception):
        pass

    with patch("litellm.acompletion", new=AsyncMock(side_effect=WeirdProviderError("???"))):
        with pytest.raises(GatewayError) as exc_info:
            await dispatch(
                req=_request(),
                agent_id="acme::mario",
                org_id="acme",
                trace_id="t",
                settings=_settings(),
            )
    assert exc_info.value.status_code == 502
    assert exc_info.value.reason == "provider_unknown_error"


def test_map_litellm_exception_truncates_long_detail():
    long = "x" * 2000
    err = _map_litellm_exception(type("APIError", (Exception,), {})(long))
    assert err.detail is not None
    assert len(err.detail) <= 512


# ── Refusals before calling litellm ─────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_refuses_missing_provider_key():
    with pytest.raises(GatewayError) as exc_info:
        await dispatch(
            req=_request(),
            agent_id="acme::mario",
            org_id="acme",
            trace_id="t",
            settings=_settings(anthropic_api_key=""),
        )
    assert exc_info.value.status_code == 503
    assert exc_info.value.reason == "provider_key_missing"


@pytest.mark.asyncio
async def test_dispatch_refuses_unimplemented_provider():
    with pytest.raises(GatewayError) as exc_info:
        await dispatch(
            req=_request(),
            agent_id="acme::mario",
            org_id="acme",
            trace_id="t",
            settings=_settings(ai_gateway_provider="openai"),
        )
    assert exc_info.value.status_code == 501
    assert exc_info.value.reason.startswith("provider_not_implemented:openai")
