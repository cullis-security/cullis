"""Tests for ``mcp_proxy.kms.vault.VaultKMSProvider`` (ADR-031).

Exercises load + store paths via ``httpx.MockTransport`` so the test
suite stays hermetic (no real Vault required). Covers:

- 404 → ``load_org_ca`` returns None (first-boot path)
- 200 with both fields → returns ``(key_pem, cert_pem)``
- 200 missing fields → treated as unseeded (returns None)
- 200 malformed JSON → ``RuntimeError``
- 5xx → ``RuntimeError``
- Network error → ``RuntimeError``
- ``store_org_ca`` first write (404 pre-read) → POST without CAS
- ``store_org_ca`` overwrite (200 pre-read) → POST with CAS and merged data
- HTTP-only URL without ``VAULT_ALLOW_HTTP=true`` → ``ValueError`` at init
- HTTP-only URL with ``VAULT_ALLOW_HTTP=true`` → init succeeds with warning
- Missing required init args → ``ValueError``
- Factory dispatches ``kms_backend="vault"`` to ``VaultKMSProvider``
"""
from __future__ import annotations

import json

import httpx
import pytest

from mcp_proxy.kms.vault import VaultKMSProvider


_VAULT_ADDR = "https://vault.example:8200"
_TOKEN = "hvs.test-token-1234567890"
_PATH = "secret/data/cullis-mastio/org-ca"


def _client_patch(monkeypatch, transport: httpx.MockTransport):
    real_async_client = httpx.AsyncClient

    def patched_async_client(*args, **kwargs):
        kwargs.setdefault("transport", transport)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_async_client)


def _make_provider() -> VaultKMSProvider:
    return VaultKMSProvider(
        vault_addr=_VAULT_ADDR,
        vault_token=_TOKEN,
        org_ca_path=_PATH,
        verify_tls=True,
        ca_cert_path="",
    )


@pytest.mark.asyncio
async def test_load_org_ca_returns_none_on_404(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == f"/v1/{_PATH}"
        assert request.headers["X-Vault-Token"] == _TOKEN
        return httpx.Response(404, json={"errors": []})

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    assert await provider.load_org_ca() is None


@pytest.mark.asyncio
async def test_load_org_ca_returns_tuple_on_200(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "data": {
                        "key_pem": "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----",
                        "cert_pem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
                    },
                    "metadata": {"version": 3},
                },
            },
        )

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    result = await provider.load_org_ca()
    assert result is not None
    key_pem, cert_pem = result
    assert "PRIVATE KEY" in key_pem
    assert "CERTIFICATE" in cert_pem


@pytest.mark.asyncio
async def test_load_org_ca_returns_none_when_fields_missing(monkeypatch):
    """Operator initialised the path with unrelated keys: treat as unseeded."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"data": {"unrelated": "x"}, "metadata": {"version": 1}}},
        )

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    assert await provider.load_org_ca() is None


@pytest.mark.asyncio
async def test_load_org_ca_raises_on_malformed_kv_payload(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        # Missing data.data — looks like a non-KV-v2 mount.
        return httpx.Response(200, json={"errors": []})

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    with pytest.raises(RuntimeError, match="malformed KV v2"):
        await provider.load_org_ca()


@pytest.mark.asyncio
async def test_load_org_ca_raises_on_5xx(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="sealed")

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    with pytest.raises(RuntimeError, match="HTTP 503"):
        await provider.load_org_ca()


@pytest.mark.asyncio
async def test_load_org_ca_raises_on_network_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    with pytest.raises(RuntimeError, match="Vault unreachable"):
        await provider.load_org_ca()


@pytest.mark.asyncio
async def test_store_org_ca_first_write_no_cas(monkeypatch):
    """First-boot path: Vault returns 404 on read, write goes through without ``options.cas``."""
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404, json={"errors": []})
        # POST: capture the body for assertion.
        body = json.loads(request.content)
        calls.append(body)
        return httpx.Response(200, json={"data": {"version": 1}})

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    await provider.store_org_ca("KEY_PEM", "CERT_PEM")

    assert len(calls) == 1
    body = calls[0]
    assert "options" not in body, "first write must omit CAS constraint"
    assert body["data"] == {"key_pem": "KEY_PEM", "cert_pem": "CERT_PEM"}


@pytest.mark.asyncio
async def test_store_org_ca_overwrite_with_cas(monkeypatch):
    """Subsequent write: read current version, merge fields, POST with cas=version."""
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "data": {
                            "key_pem": "OLD_KEY",
                            "cert_pem": "OLD_CERT",
                            "operator_note": "preserve me",
                        },
                        "metadata": {"version": 7},
                    },
                },
            )
        body = json.loads(request.content)
        calls.append(body)
        return httpx.Response(200, json={"data": {"version": 8}})

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    await provider.store_org_ca("NEW_KEY", "NEW_CERT")

    assert len(calls) == 1
    body = calls[0]
    assert body["options"]["cas"] == 7
    assert body["data"]["key_pem"] == "NEW_KEY"
    assert body["data"]["cert_pem"] == "NEW_CERT"
    assert body["data"]["operator_note"] == "preserve me", (
        "merge must preserve operator-set fields under the same path"
    )


@pytest.mark.asyncio
async def test_store_org_ca_raises_on_write_5xx(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404, json={})
        return httpx.Response(500, text="internal error")

    _client_patch(monkeypatch, httpx.MockTransport(handler))
    provider = _make_provider()
    with pytest.raises(RuntimeError, match="HTTP 500"):
        await provider.store_org_ca("k", "c")


def test_init_refuses_http_without_override(monkeypatch):
    monkeypatch.delenv("VAULT_ALLOW_HTTP", raising=False)
    with pytest.raises(ValueError, match="must use https://"):
        VaultKMSProvider(
            vault_addr="http://vault.internal:8200",
            vault_token=_TOKEN,
            org_ca_path=_PATH,
        )


def test_init_allows_http_when_override_set(monkeypatch):
    monkeypatch.setenv("VAULT_ALLOW_HTTP", "true")
    provider = VaultKMSProvider(
        vault_addr="http://vault.internal:8200",
        vault_token=_TOKEN,
        org_ca_path=_PATH,
    )
    assert provider.name == "vault"


def test_init_refuses_http_override_in_production(monkeypatch):
    """F-A-103: VAULT_ALLOW_HTTP=true must be rejected when the Mastio
    is configured for production. The override exists for local dev
    flows; promoting a stale dev .env to prod must not silently leak
    the Vault token over plaintext HTTP."""
    monkeypatch.setenv("VAULT_ALLOW_HTTP", "true")
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="rejected in production"):
            VaultKMSProvider(
                vault_addr="http://vault.internal:8200",
                vault_token=_TOKEN,
                org_ca_path=_PATH,
            )
    finally:
        get_settings.cache_clear()


def test_init_allows_http_override_in_development(monkeypatch):
    """Mirror of the production refuse: development must still
    accept the override so dev/test workflows keep working."""
    monkeypatch.setenv("VAULT_ALLOW_HTTP", "true")
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "development")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    try:
        provider = VaultKMSProvider(
            vault_addr="http://vault.internal:8200",
            vault_token=_TOKEN,
            org_ca_path=_PATH,
        )
        assert provider._vault_addr == "http://vault.internal:8200"
    finally:
        get_settings.cache_clear()


def test_init_requires_addr():
    with pytest.raises(ValueError, match="vault_addr"):
        VaultKMSProvider(vault_addr="", vault_token=_TOKEN, org_ca_path=_PATH)


def test_init_requires_token():
    with pytest.raises(ValueError, match="vault_token"):
        VaultKMSProvider(vault_addr=_VAULT_ADDR, vault_token="", org_ca_path=_PATH)


def test_init_requires_path():
    with pytest.raises(ValueError, match="org_ca_path"):
        VaultKMSProvider(vault_addr=_VAULT_ADDR, vault_token=_TOKEN, org_ca_path="")


def test_factory_dispatches_vault_backend(monkeypatch):
    """Factory must resolve ``kms_backend="vault"`` to the in-tree provider
    without going through the cullis-enterprise plugin registry."""
    from mcp_proxy.kms import factory

    factory.reset_kms_provider()
    monkeypatch.setattr(
        "mcp_proxy.config.get_settings",
        lambda: _FakeSettings(
            kms_backend="vault",
            vault_addr=_VAULT_ADDR,
            vault_token=_TOKEN,
            vault_org_ca_path=_PATH,
            vault_verify_tls=True,
            vault_ca_cert_path="",
        ),
    )
    provider = factory.get_kms_provider()
    assert isinstance(provider, VaultKMSProvider)
    factory.reset_kms_provider()


class _FakeSettings:
    """Minimal settings stand-in for the factory test — only the fields
    the ``vault`` branch reads."""

    def __init__(
        self,
        kms_backend: str,
        vault_addr: str,
        vault_token: str,
        vault_org_ca_path: str,
        vault_verify_tls: bool,
        vault_ca_cert_path: str,
    ) -> None:
        self.kms_backend = kms_backend
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self.vault_org_ca_path = vault_org_ca_path
        self.vault_verify_tls = vault_verify_tls
        self.vault_ca_cert_path = vault_ca_cert_path
