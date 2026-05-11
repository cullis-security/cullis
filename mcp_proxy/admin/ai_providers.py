"""Admin API for managing AI provider credentials at runtime.

Lifts the embedded LiteLLM gateway off the single ``ANTHROPIC_API_KEY``
environment variable. An org admin authenticates with the
``X-Admin-Secret`` header (same pattern used by ``/v1/admin/agents``)
and configures Anthropic / OpenAI / Gemini / Bedrock / Vertex / Ollama
credentials. Every mutation lands in the hash-chained audit log and the
Mastio process picks up the new value on the next gateway call (no
restart needed).

Endpoints:

  GET    /v1/admin/ai-providers
         List all providers with masked credentials. Not-yet-configured
         providers are returned with ``configured=false`` so the dashboard
         can render the full catalog in one round-trip.

  GET    /v1/admin/ai-providers/{provider}
         Single-provider read; same masked shape.

  PUT    /v1/admin/ai-providers/{provider}
         Upsert credentials. Validates required fields against the
         catalog and returns 400 with a structured error on miss.

  DELETE /v1/admin/ai-providers/{provider}
         Remove credentials. The gateway falls back to
         ``ANTHROPIC_API_KEY`` env for ``anthropic`` to keep legacy
         deployments alive after the row is dropped.

  POST   /v1/admin/ai-providers/{provider}/enable
         Toggle the ``enabled`` flag without rotating credentials. The
         body carries ``{"enabled": true|false}``.

  POST   /v1/admin/ai-providers/{provider}/test
         Live connectivity probe. Sends a minimal authenticated request
         to the provider's catalog endpoint (Anthropic models / OpenAI
         models / Gemini models / Ollama tags). Returns ``ok`` / latency
         / a sanitised error string. Not all providers support a ping
         today (Bedrock, Vertex) — those return ``status="unsupported"``
         and the operator falls back to the first chat completion.
"""
from __future__ import annotations

import hmac
import logging
import time
from typing import Any

import httpx
from fastapi import APIRouter, Body, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from mcp_proxy.config import get_settings
from mcp_proxy.db import (
    delete_ai_provider_creds,
    get_ai_provider_creds,
    list_ai_provider_creds,
    log_audit,
    set_ai_provider_enabled,
    upsert_ai_provider_creds,
)
from mcp_proxy.egress.provider_catalog import (
    PROVIDERS,
    InvalidCredentialsError,
    fetch_ollama_models,
    get_spec,
    mask_creds,
    validate_creds,
)


_log = logging.getLogger("mcp_proxy.admin.ai_providers")

router = APIRouter(prefix="/v1/admin/ai-providers", tags=["admin"])


# ── auth ────────────────────────────────────────────────────────────────


def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


# ── models ──────────────────────────────────────────────────────────────


class FieldDef(BaseModel):
    name: str
    label: str
    secret: bool = False
    required: bool = True
    placeholder: str = ""
    help_text: str = ""


class ProviderInfo(BaseModel):
    """Public-facing description of one provider, masked credentials only."""

    provider: str
    display_name: str
    docs_url: str
    fields: list[FieldDef]
    static_models: list[str] = Field(default_factory=list)
    dynamic_models: bool = False
    configured: bool = False
    enabled: bool = False
    creds_masked: dict[str, str] = Field(default_factory=dict)
    updated_at: str | None = None
    updated_by: str | None = None


class ProviderUpsertRequest(BaseModel):
    """Inbound credentials. Empty/missing optional fields are dropped."""

    creds: dict[str, str]
    enabled: bool = True
    updated_by: str | None = None


class ProviderEnableRequest(BaseModel):
    enabled: bool


class TestResult(BaseModel):
    provider: str
    status: str  # "ok" | "error" | "unsupported"
    latency_ms: int | None = None
    detail: str | None = None
    sample_models: list[str] = Field(default_factory=list)


# ── helpers ─────────────────────────────────────────────────────────────


def _spec_to_info(provider: str, row: dict | None) -> ProviderInfo:
    spec = get_spec(provider)
    if spec is None:  # pragma: no cover — guarded by router validation
        raise HTTPException(404, f"unknown provider {provider!r}")
    fields = [
        FieldDef(
            name=f.name,
            label=f.label,
            secret=f.secret,
            required=f.required,
            placeholder=f.placeholder,
            help_text=f.help_text,
        )
        for f in spec.fields
    ]
    info = ProviderInfo(
        provider=spec.provider,
        display_name=spec.display_name,
        docs_url=spec.docs_url,
        fields=fields,
        static_models=list(spec.static_models),
        dynamic_models=spec.dynamic_models,
    )
    if row is not None:
        info.configured = True
        info.enabled = bool(row["enabled"])
        info.creds_masked = mask_creds(provider, row["creds"] or {})
        info.updated_at = row.get("updated_at")
        info.updated_by = row.get("updated_by")
    return info


def _require_known_provider(provider: str) -> str:
    p = provider.lower()
    if p not in PROVIDERS:
        raise HTTPException(
            status_code=404,
            detail=f"unknown provider {provider!r}; "
                   f"valid: {sorted(PROVIDERS.keys())}",
        )
    return p


# ── routes ──────────────────────────────────────────────────────────────


@router.get(
    "",
    response_model=list[ProviderInfo],
    dependencies=[Depends(_require_admin_secret)],
)
async def list_providers() -> list[ProviderInfo]:
    rows = await list_ai_provider_creds()
    by_name = {r["provider"]: r for r in rows}
    out: list[ProviderInfo] = []
    for provider in PROVIDERS:
        out.append(_spec_to_info(provider, by_name.get(provider)))
    return out


@router.get(
    "/{provider}",
    response_model=ProviderInfo,
    dependencies=[Depends(_require_admin_secret)],
)
async def get_provider(provider: str) -> ProviderInfo:
    p = _require_known_provider(provider)
    row = await get_ai_provider_creds(p)
    return _spec_to_info(p, row)


@router.put(
    "/{provider}",
    response_model=ProviderInfo,
    dependencies=[Depends(_require_admin_secret)],
)
async def upsert_provider(
    provider: str,
    body: ProviderUpsertRequest,
) -> ProviderInfo:
    p = _require_known_provider(provider)
    try:
        cleaned = validate_creds(p, body.creds)
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    await upsert_ai_provider_creds(
        p, cleaned,
        enabled=body.enabled,
        updated_by=body.updated_by,
    )
    await log_audit(
        agent_id=body.updated_by or "admin",
        action="ai_provider.upsert",
        status="success",
        details={
            "provider": p,
            "enabled": body.enabled,
            "fields": sorted(cleaned.keys()),
        },
    )
    _log.info(
        "ai-provider upsert provider=%s enabled=%s by=%s fields=%s",
        p, body.enabled, body.updated_by, sorted(cleaned.keys()),
    )
    row = await get_ai_provider_creds(p)
    return _spec_to_info(p, row)


@router.delete(
    "/{provider}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_require_admin_secret)],
)
async def delete_provider(provider: str) -> None:
    p = _require_known_provider(provider)
    deleted = await delete_ai_provider_creds(p)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"provider {p!r} has no stored credentials",
        )
    await log_audit(
        agent_id="admin",
        action="ai_provider.delete",
        status="success",
        details={"provider": p},
    )
    _log.info("ai-provider deleted provider=%s", p)


@router.post(
    "/{provider}/enable",
    response_model=ProviderInfo,
    dependencies=[Depends(_require_admin_secret)],
)
async def toggle_enabled(
    provider: str,
    body: ProviderEnableRequest,
) -> ProviderInfo:
    p = _require_known_provider(provider)
    changed = await set_ai_provider_enabled(p, body.enabled)
    if not changed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"provider {p!r} not configured",
        )
    await log_audit(
        agent_id="admin",
        action=("ai_provider.enable" if body.enabled
                else "ai_provider.disable"),
        status="success",
        details={"provider": p},
    )
    row = await get_ai_provider_creds(p)
    return _spec_to_info(p, row)


@router.post(
    "/{provider}/test",
    response_model=TestResult,
    dependencies=[Depends(_require_admin_secret)],
)
async def test_provider(
    provider: str,
    overrides: dict[str, Any] | None = Body(default=None),
) -> TestResult:
    """Probe the provider with a lightweight read.

    The optional body lets the dashboard test creds before saving them
    (``{"creds": {...}}``). When no body is sent we use the stored row.
    """
    p = _require_known_provider(provider)
    creds: dict[str, str] = {}

    if isinstance(overrides, dict) and isinstance(overrides.get("creds"), dict):
        try:
            creds = validate_creds(p, overrides["creds"])
        except InvalidCredentialsError as exc:
            raise HTTPException(400, str(exc)) from exc
    else:
        row = await get_ai_provider_creds(p)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"provider {p!r} not configured",
            )
        creds = dict(row["creds"] or {})

    started = time.perf_counter()
    try:
        result = await _live_probe(p, creds)
    except Exception as exc:  # pragma: no cover — defensive
        _log.warning("ai-provider test failed provider=%s err=%s", p, exc)
        result = TestResult(
            provider=p, status="error",
            detail=f"{type(exc).__name__}: {exc}"[:512],
        )
    result.latency_ms = int((time.perf_counter() - started) * 1000)
    return result


# ── live probes ─────────────────────────────────────────────────────────


async def _live_probe(provider: str, creds: dict[str, str]) -> TestResult:
    if provider == "anthropic":
        return await _probe_anthropic(creds)
    if provider == "openai":
        return await _probe_openai(creds)
    if provider == "gemini":
        return await _probe_gemini(creds)
    if provider == "ollama":
        return await _probe_ollama(creds)
    return TestResult(
        provider=provider,
        status="unsupported",
        detail=(
            f"Live probe not implemented for {provider!r}. "
            "Issue a chat completion to validate."
        ),
    )


# Wave B B3 (audit 2026-05-11) — endpoint allow-list for the
# OpenAI-compatible live-probe path. Default-allowed hosts are the
# upstream APIs themselves; any other ``api_base`` is refused unless
# the operator explicitly opted in via env (BYO endpoint pattern,
# e.g. Azure OpenAI / corporate proxy). The check fires BEFORE we
# ever ship the ``Authorization: Bearer <api_key>`` header so the
# upstream key never reaches an unallowed host.

_OPENAI_COMPAT_DEFAULT_HOSTS: frozenset[str] = frozenset({
    "api.openai.com",
    "api.anthropic.com",
})


def _byo_endpoint_allowed() -> bool:
    """True when the operator has explicitly opted into "bring-your-own"
    api_base values (Azure OpenAI deployments, corporate proxies, etc.)."""
    import os
    return os.environ.get("MCP_PROXY_AI_PROBE_ALLOW_BYO_ENDPOINT", "").lower() in (
        "1", "true", "yes",
    )


def _enforce_openai_compat_endpoint(api_base: str, *, allow_byo: bool) -> None:
    """Refuse to probe with an Authorization header against an api_base
    that is neither one of the well-known OpenAI-compatible hosts nor
    explicitly allow-listed via env."""
    from urllib.parse import urlparse
    parsed = urlparse(api_base)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"api_base scheme {parsed.scheme!r} not allowed (use https)"
        )
    if parsed.scheme != "https":
        # An http:// api_base would ship the API key in cleartext to
        # the upstream — refuse outright.
        raise ValueError(
            "api_base must use https (live-probe ships the API key)"
        )
    host = (parsed.hostname or "").lower()
    if host in _OPENAI_COMPAT_DEFAULT_HOSTS:
        return
    if allow_byo:
        return
    raise ValueError(
        f"api_base host {host!r} is not on the live-probe allow-list. "
        "Set MCP_PROXY_AI_PROBE_ALLOW_BYO_ENDPOINT=true to enable "
        "bring-your-own endpoints (Azure OpenAI / corporate proxies)."
    )


def _enforce_self_hosted_endpoint(api_base: str) -> None:
    """Lightweight check for the Ollama path — refuse non-http schemes
    and unparseable URLs but allow RFC1918 since self-hosted is the
    documented topology."""
    from urllib.parse import urlparse
    parsed = urlparse(api_base)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"api_base scheme {parsed.scheme!r} not allowed (use http/https)"
        )
    if not parsed.hostname:
        raise ValueError("api_base has no hostname")


async def _probe_anthropic(creds: dict[str, str]) -> TestResult:
    api_key = creds.get("api_key", "")
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            "https://api.anthropic.com/v1/models", headers=headers,
        )
    if resp.status_code != 200:
        return TestResult(
            provider="anthropic", status="error",
            detail=f"HTTP {resp.status_code}: {resp.text[:256]}",
        )
    try:
        data = resp.json().get("data", [])
        sample = [d.get("id") for d in data[:5] if d.get("id")]
    except ValueError:
        sample = []
    return TestResult(
        provider="anthropic", status="ok", sample_models=sample,
    )


async def _probe_openai(creds: dict[str, str]) -> TestResult:
    api_key = creds.get("api_key", "")
    base = creds.get("api_base") or "https://api.openai.com/v1"
    # Wave B B3 (audit 2026-05-11) — refuse to ship an Authorization
    # header containing the upstream API key to a host that is not on
    # the allow-list. Pre-fix the admin could (accidentally or via
    # admin-secret leak) set ``api_base`` to an attacker-controlled
    # URL and the live-probe would POST the key over HTTPS. Same shape
    # as the third-party-gateway leak class flagged in
    # ``feedback_third_party_ai_gateway_key_leak.md``.
    try:
        _enforce_openai_compat_endpoint(base, allow_byo=_byo_endpoint_allowed())
    except ValueError as exc:
        return TestResult(
            provider="openai", status="error", detail=str(exc),
        )
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"{base.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {api_key}"},
        )
    if resp.status_code != 200:
        return TestResult(
            provider="openai", status="error",
            detail=f"HTTP {resp.status_code}: {resp.text[:256]}",
        )
    try:
        data = resp.json().get("data", [])
        sample = [d.get("id") for d in data[:5] if d.get("id")]
    except ValueError:
        sample = []
    return TestResult(provider="openai", status="ok", sample_models=sample)


async def _probe_gemini(creds: dict[str, str]) -> TestResult:
    api_key = creds.get("api_key", "")
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models"
        f"?key={api_key}"
    )
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(url)
    if resp.status_code != 200:
        return TestResult(
            provider="gemini", status="error",
            detail=f"HTTP {resp.status_code}: {resp.text[:256]}",
        )
    try:
        data = resp.json().get("models", [])
        sample = [d.get("name", "").split("/")[-1] for d in data[:5]]
        sample = [s for s in sample if s]
    except ValueError:
        sample = []
    return TestResult(provider="gemini", status="ok", sample_models=sample)


async def _probe_ollama(creds: dict[str, str]) -> TestResult:
    api_base = creds.get("api_base", "")
    if not api_base:
        return TestResult(
            provider="ollama", status="error", detail="api_base missing",
        )
    # Wave B B3 — Ollama is designed for self-hosted so RFC1918 is the
    # legitimate case (docker network etc.). Allow private IPs but
    # still refuse non-http schemes and validate the URL is parseable.
    try:
        _enforce_self_hosted_endpoint(api_base)
    except ValueError as exc:
        return TestResult(
            provider="ollama", status="error", detail=str(exc),
        )
    models = await fetch_ollama_models(api_base, timeout_s=3.0)
    if not models:
        return TestResult(
            provider="ollama", status="error",
            detail=f"No models reachable at {api_base}/api/tags",
        )
    return TestResult(
        provider="ollama", status="ok",
        sample_models=models[:5],
    )
