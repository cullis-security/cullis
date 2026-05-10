"""Unit tests for ``mcp_proxy.egress.provider_catalog``.

Pure logic — no DB, no HTTP. Pins the credential validation,
masking, and model-id parsing rules so refactors can move things
around without breaking the dashboard contract.
"""
from __future__ import annotations

import pytest

from mcp_proxy.egress.provider_catalog import (
    InvalidCredentialsError,
    PROVIDERS,
    fetch_ollama_models,
    get_spec,
    list_available_models,
    litellm_kwargs,
    mask_creds,
    parse_provider_from_model,
    validate_creds,
)


# ── parse_provider_from_model ────────────────────────────────────────


@pytest.mark.parametrize("model,expected", [
    ("claude-haiku-4-5", "anthropic"),
    ("anthropic/claude-haiku-4-5", "anthropic"),
    ("gpt-4o", "openai"),
    ("openai/gpt-4o", "openai"),
    ("o1-mini", "openai"),
    ("gemini-1.5-pro", "gemini"),
    ("gemini/gemini-1.5-pro", "gemini"),
    ("vertex_ai/gemini-1.5-pro", "vertex"),
    ("bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0", "bedrock"),
    ("ollama/qwen2.5:7b", "ollama"),
    ("ollama_chat/llama3.1:8b", "ollama"),
])
def test_parse_provider_from_model_known(model, expected):
    assert parse_provider_from_model(model) == expected


def test_parse_provider_from_model_falls_back_to_anthropic():
    # Unknown id without a recognised prefix — keep legacy single-provider
    # deployments alive instead of raising.
    assert parse_provider_from_model("nemo-mistral-7b") == "anthropic"


# ── validate_creds ───────────────────────────────────────────────────


def test_validate_creds_strips_unknown_keys_and_returns_clean_dict():
    cleaned = validate_creds("anthropic", {
        "api_key": "sk-ant-test",
        "junk_field": "should_be_dropped",
    })
    assert cleaned == {"api_key": "sk-ant-test"}


def test_validate_creds_missing_required_raises():
    with pytest.raises(InvalidCredentialsError, match="api_key"):
        validate_creds("anthropic", {})


def test_validate_creds_optional_field_skipped_when_empty():
    cleaned = validate_creds("openai", {
        "api_key": "sk-test",
        "api_base": "",  # optional
    })
    assert cleaned == {"api_key": "sk-test"}


def test_validate_creds_unknown_provider():
    with pytest.raises(InvalidCredentialsError, match="unknown provider"):
        validate_creds("does-not-exist", {})


def test_validate_creds_rejects_non_string_value():
    with pytest.raises(InvalidCredentialsError, match="must be a string"):
        validate_creds("anthropic", {"api_key": 12345})


def test_validate_creds_bedrock_full_triplet():
    cleaned = validate_creds("bedrock", {
        "aws_access_key_id": "AKIA...",
        "aws_secret_access_key": "secret",
        "aws_region_name": "us-east-1",
    })
    assert cleaned["aws_region_name"] == "us-east-1"


# ── mask_creds ───────────────────────────────────────────────────────


def test_mask_creds_replaces_secret_fields():
    masked = mask_creds("openai", {
        "api_key": "sk-real",
        "api_base": "https://example.invalid/v1",
    })
    assert masked["api_key"] == "***"
    assert masked["api_base"] == "https://example.invalid/v1"


def test_mask_creds_skips_missing_fields():
    masked = mask_creds("openai", {"api_key": "sk-real"})
    assert "api_base" not in masked
    assert masked == {"api_key": "***"}


# ── litellm_kwargs ───────────────────────────────────────────────────


def test_litellm_kwargs_anthropic():
    kwargs = litellm_kwargs("anthropic", {"api_key": "sk-a"})
    assert kwargs == {"api_key": "sk-a"}


def test_litellm_kwargs_openai_with_base():
    kwargs = litellm_kwargs("openai", {
        "api_key": "sk-o",
        "api_base": "https://azure.example/v1",
    })
    assert kwargs["api_key"] == "sk-o"
    assert kwargs["api_base"] == "https://azure.example/v1"


def test_litellm_kwargs_openai_without_base_omits_key():
    kwargs = litellm_kwargs("openai", {"api_key": "sk-o"})
    assert kwargs == {"api_key": "sk-o"}


def test_litellm_kwargs_bedrock():
    kwargs = litellm_kwargs("bedrock", {
        "aws_access_key_id": "AKIA",
        "aws_secret_access_key": "sec",
        "aws_region_name": "us-west-2",
    })
    assert kwargs == {
        "aws_access_key_id": "AKIA",
        "aws_secret_access_key": "sec",
        "aws_region_name": "us-west-2",
    }


def test_litellm_kwargs_ollama():
    kwargs = litellm_kwargs("ollama", {"api_base": "http://host:11434"})
    assert kwargs == {"api_base": "http://host:11434"}


def test_litellm_kwargs_vertex_passes_credentials_when_present():
    kwargs = litellm_kwargs("vertex", {
        "vertex_project": "my-proj",
        "vertex_location": "us-central1",
        "vertex_credentials_json": '{"type":"service_account"}',
    })
    assert kwargs["vertex_project"] == "my-proj"
    assert kwargs["vertex_credentials"] == '{"type":"service_account"}'


def test_litellm_kwargs_unknown_provider_returns_empty():
    assert litellm_kwargs("not-a-provider", {}) == {}


# ── catalog spec sanity ──────────────────────────────────────────────


def test_all_providers_have_at_least_one_field():
    for name, spec in PROVIDERS.items():
        assert spec.fields, f"{name} has no credential fields"


def test_get_spec_case_insensitive():
    assert get_spec("Anthropic") is not None
    assert get_spec("ANTHROPIC") is not None
    assert get_spec("nope") is None


# ── list_available_models ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_available_models_filters_to_configured():
    enabled = [("anthropic", {"api_key": "sk"})]
    out = await list_available_models(enabled)
    assert len(out) > 0
    assert all(item["provider"] == "anthropic" for item in out)


@pytest.mark.asyncio
async def test_list_available_models_dedup_across_providers():
    # Anthropic + Bedrock both surface Claude family — test that the
    # caller picks them in order without duplicates.
    enabled = [
        ("anthropic", {"api_key": "sk"}),
        ("bedrock", {
            "aws_access_key_id": "k",
            "aws_secret_access_key": "s",
            "aws_region_name": "us-east-1",
        }),
    ]
    out = await list_available_models(enabled)
    ids = [item["id"] for item in out]
    assert len(ids) == len(set(ids))


@pytest.mark.asyncio
async def test_list_available_models_unknown_provider_skipped():
    out = await list_available_models([("not-a-thing", {})])
    assert out == []


@pytest.mark.asyncio
async def test_fetch_ollama_models_unreachable_returns_empty():
    # Use a port that nothing is listening on; httpx fails fast.
    out = await fetch_ollama_models("http://127.0.0.1:1", timeout_s=0.5)
    assert out == []


@pytest.mark.asyncio
async def test_fetch_ollama_models_empty_base_returns_empty():
    assert await fetch_ollama_models("") == []
