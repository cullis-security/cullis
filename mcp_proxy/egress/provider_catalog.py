"""Catalog of AI providers supported by the embedded LiteLLM gateway.

Three responsibilities:

1. Declare the credential shape for each provider — which JSON fields
   the dashboard form must collect, which are secret, which are optional.
2. Surface the static model list per provider (Anthropic / OpenAI / Gemini
   / Bedrock / Vertex). Ollama is dynamic and resolved by hitting
   ``{base_url}/api/tags`` at request time.
3. Translate a stored credentials row into the kwargs that
   ``litellm.acompletion(...)`` expects (``api_key``, ``api_base``,
   ``aws_access_key_id``, ``vertex_project``, ...) and into a model id
   that LiteLLM disambiguates the right way.

The catalog is intentionally hard-coded rather than mirrored from the
LiteLLM ``model_cost`` registry so that the dashboard offers a curated
shortlist (chat models only, no embeddings or moderation, no deprecated
ids). When a new model lands and the operator wants it before we ship
the catalog bump, they pick ``custom`` model id and pay the LiteLLM
auto-detect tax — ``parse_provider_from_model`` falls back to the
prefix-based router that LiteLLM itself uses internally.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Iterable

import httpx


_log = logging.getLogger("mcp_proxy.egress.provider_catalog")


# ── credential field definitions ─────────────────────────────────────


@dataclass(frozen=True)
class CredentialField:
    """One field on the dashboard form for a provider."""

    name: str
    label: str
    secret: bool = False
    required: bool = True
    placeholder: str = ""
    help_text: str = ""


@dataclass(frozen=True)
class ProviderSpec:
    provider: str
    display_name: str
    fields: tuple[CredentialField, ...]
    static_models: tuple[str, ...] = field(default_factory=tuple)
    dynamic_models: bool = False
    default_model_for_route: str | None = None
    docs_url: str = ""


# Curated chat-completion model lists. Operators can still call any
# model id LiteLLM recognises by passing ``provider/model`` directly;
# this is just the shortlist that the SPA shows in the dropdown.
ANTHROPIC_MODELS: tuple[str, ...] = (
    "claude-haiku-4-5",
    "claude-sonnet-4-6",
    "claude-opus-4-7",
)
OPENAI_MODELS: tuple[str, ...] = (
    "gpt-4o",
    "gpt-4o-mini",
    "o1",
    "o1-mini",
)
GEMINI_MODELS: tuple[str, ...] = (
    "gemini/gemini-1.5-pro",
    "gemini/gemini-1.5-flash",
    "gemini/gemini-2.0-flash",
)
BEDROCK_MODELS: tuple[str, ...] = (
    "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0",
    "bedrock/meta.llama3-1-70b-instruct-v1:0",
)
VERTEX_MODELS: tuple[str, ...] = (
    "vertex_ai/gemini-1.5-pro",
    "vertex_ai/claude-3-5-sonnet@20240620",
)


PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        provider="anthropic",
        display_name="Anthropic",
        fields=(
            CredentialField("api_key", "API key", secret=True,
                            placeholder="sk-ant-..."),
        ),
        static_models=ANTHROPIC_MODELS,
        docs_url="https://docs.anthropic.com/en/api/getting-started",
    ),
    "openai": ProviderSpec(
        provider="openai",
        display_name="OpenAI",
        fields=(
            CredentialField("api_key", "API key", secret=True,
                            placeholder="sk-..."),
            CredentialField("api_base", "Base URL (optional)",
                            required=False,
                            placeholder="https://api.openai.com/v1",
                            help_text="Override for Azure/compatible "
                                      "endpoints."),
        ),
        static_models=OPENAI_MODELS,
        docs_url="https://platform.openai.com/docs/api-reference",
    ),
    "gemini": ProviderSpec(
        provider="gemini",
        display_name="Google Gemini (AI Studio)",
        fields=(
            CredentialField("api_key", "API key", secret=True,
                            placeholder="AIza..."),
        ),
        static_models=GEMINI_MODELS,
        docs_url="https://ai.google.dev/gemini-api/docs/api-key",
    ),
    "bedrock": ProviderSpec(
        provider="bedrock",
        display_name="AWS Bedrock",
        fields=(
            CredentialField("aws_access_key_id", "Access key ID",
                            secret=True),
            CredentialField("aws_secret_access_key", "Secret access key",
                            secret=True),
            CredentialField("aws_region_name", "Region",
                            placeholder="us-east-1"),
        ),
        static_models=BEDROCK_MODELS,
        docs_url="https://docs.aws.amazon.com/bedrock/",
    ),
    "vertex": ProviderSpec(
        provider="vertex",
        display_name="Google Vertex AI",
        fields=(
            CredentialField("vertex_project", "GCP project id"),
            CredentialField("vertex_location", "Location",
                            placeholder="us-central1"),
            CredentialField("vertex_credentials_json",
                            "Service account JSON",
                            secret=True,
                            help_text="Paste the full JSON. Stored "
                                      "verbatim; LiteLLM consumes it via "
                                      "the ``vertex_credentials`` kwarg."),
        ),
        static_models=VERTEX_MODELS,
        docs_url="https://cloud.google.com/vertex-ai/docs",
    ),
    "ollama": ProviderSpec(
        provider="ollama",
        display_name="Ollama (local)",
        fields=(
            CredentialField("api_base", "Base URL",
                            placeholder="http://host.docker.internal:11434",
                            help_text="The Ollama HTTP endpoint reachable "
                                      "from the Mastio container."),
        ),
        dynamic_models=True,
        docs_url="https://github.com/ollama/ollama/blob/main/docs/api.md",
    ),
}


def all_provider_names() -> list[str]:
    return list(PROVIDERS.keys())


def get_spec(provider: str) -> ProviderSpec | None:
    return PROVIDERS.get(provider.lower())


# ── credential validation ────────────────────────────────────────────


class InvalidCredentialsError(ValueError):
    """Raised when a credentials dict is missing required fields."""


def validate_creds(provider: str, creds: dict[str, Any]) -> dict[str, str]:
    """Strip unknown keys, enforce required ones, return a clean dict.

    The returned dict is what the admin endpoint stores in the DB.
    """
    spec = get_spec(provider)
    if spec is None:
        raise InvalidCredentialsError(f"unknown provider {provider!r}")
    cleaned: dict[str, str] = {}
    for fld in spec.fields:
        raw = creds.get(fld.name)
        if raw is None or raw == "":
            if fld.required:
                raise InvalidCredentialsError(
                    f"missing required field {fld.name!r} for {provider}",
                )
            continue
        if not isinstance(raw, str):
            raise InvalidCredentialsError(
                f"{provider}.{fld.name} must be a string, got {type(raw).__name__}",
            )
        cleaned[fld.name] = raw.strip()
    return cleaned


def mask_creds(provider: str, creds: dict[str, Any]) -> dict[str, str]:
    """Return a copy with secret fields replaced by ``"***"``.

    Used by GET endpoints so the dashboard can show "configured" state
    without ever returning the raw key.
    """
    spec = get_spec(provider)
    if spec is None:
        return {}
    out: dict[str, str] = {}
    for fld in spec.fields:
        val = creds.get(fld.name)
        if val is None or val == "":
            continue
        if fld.secret:
            out[fld.name] = "***"
        else:
            out[fld.name] = str(val)
    return out


# ── model id parsing ─────────────────────────────────────────────────


_PROVIDER_PREFIXES: tuple[tuple[str, str], ...] = (
    ("anthropic/", "anthropic"),
    ("openai/", "openai"),
    ("gemini/", "gemini"),
    ("vertex_ai/", "vertex"),
    ("bedrock/", "bedrock"),
    ("ollama/", "ollama"),
    ("ollama_chat/", "ollama"),
)


def parse_provider_from_model(model: str) -> str:
    """Map a model id to a provider key in :data:`PROVIDERS`.

    Resolution order:
      1. explicit ``provider/...`` prefix
      2. heuristic on bare ids (``claude-*`` → anthropic, ``gpt-*``/
         ``o1*`` → openai, ``gemini-*`` → gemini)
      3. fallback ``"anthropic"`` to keep the legacy single-provider
         deployments working without code changes.
    """
    m = model.strip()
    lower = m.lower()
    for prefix, provider in _PROVIDER_PREFIXES:
        if lower.startswith(prefix):
            return provider
    if lower.startswith("claude-") or lower.startswith("anthropic."):
        return "anthropic"
    if lower.startswith("gpt-") or lower.startswith("o1"):
        return "openai"
    if lower.startswith("gemini-"):
        return "gemini"
    return "anthropic"


# ── litellm kwargs translation ───────────────────────────────────────


def litellm_kwargs(provider: str, creds: dict[str, str]) -> dict[str, Any]:
    """Translate a stored credentials row into ``litellm.acompletion`` kwargs.

    The caller is responsible for passing them via ``**kwargs``. Empty
    dicts are returned for unknown providers so the gateway can raise a
    clean 503 ``provider_not_configured`` upstream.
    """
    p = provider.lower()
    if p == "anthropic":
        return {"api_key": creds.get("api_key", "")}
    if p == "openai":
        kwargs: dict[str, Any] = {"api_key": creds.get("api_key", "")}
        if creds.get("api_base"):
            kwargs["api_base"] = creds["api_base"]
        return kwargs
    if p == "gemini":
        return {"api_key": creds.get("api_key", "")}
    if p == "bedrock":
        return {
            "aws_access_key_id": creds.get("aws_access_key_id", ""),
            "aws_secret_access_key": creds.get("aws_secret_access_key", ""),
            "aws_region_name": creds.get("aws_region_name", ""),
        }
    if p == "vertex":
        kwargs = {
            "vertex_project": creds.get("vertex_project", ""),
            "vertex_location": creds.get("vertex_location", ""),
        }
        raw = creds.get("vertex_credentials_json", "")
        if raw:
            try:
                json.loads(raw)
                kwargs["vertex_credentials"] = raw
            except json.JSONDecodeError:
                _log.warning(
                    "vertex_credentials_json is not valid JSON; "
                    "passing raw string to LiteLLM",
                )
                kwargs["vertex_credentials"] = raw
        return kwargs
    if p == "ollama":
        return {"api_base": creds.get("api_base", "")}
    return {}


# ── ollama dynamic model discovery ───────────────────────────────────


async def fetch_ollama_models(api_base: str, *, timeout_s: float = 2.0) -> list[str]:
    """Return the chat-capable model names that a local Ollama serves.

    Returns ``[]`` (and logs a debug line) on any failure: the dashboard
    treats Ollama as "not reachable" and the admin can hit the Test
    button for a verbose error.
    """
    if not api_base:
        return []
    url = api_base.rstrip("/") + "/api/tags"
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            payload = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        _log.debug("ollama tag fetch failed url=%s err=%s", url, exc)
        return []
    raw = payload.get("models") or []
    out: list[str] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("model")
        if not name:
            continue
        out.append(f"ollama/{name}")
    return out


# ── canonical model list (read-side) ─────────────────────────────────


async def list_available_models(
    enabled_providers: Iterable[tuple[str, dict[str, str]]],
) -> list[dict[str, str]]:
    """Return the OpenAI-compatible ``/v1/models`` ``data`` array.

    ``enabled_providers`` is an iterable of ``(provider, creds)`` tuples
    coming from the DB. Disabled rows are filtered by the caller before
    we get here.
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for provider, creds in enabled_providers:
        spec = get_spec(provider)
        if spec is None:
            continue
        if spec.dynamic_models and provider == "ollama":
            api_base = creds.get("api_base", "")
            for mid in await fetch_ollama_models(api_base):
                if mid in seen:
                    continue
                seen.add(mid)
                out.append({
                    "id": mid,
                    "object": "model",
                    "owned_by": provider,
                    "provider": provider,
                })
            continue
        for mid in spec.static_models:
            if mid in seen:
                continue
            seen.add(mid)
            out.append({
                "id": mid,
                "object": "model",
                "owned_by": provider,
                "provider": provider,
            })
    return out
