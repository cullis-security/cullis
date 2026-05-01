"""Contract tests for the Mastio KMS abstraction.

Cover both the in-tree LocalKMSProvider (current default behavior) and
the plugin dispatch path used by cullis-enterprise cloud KMS providers.
"""
from __future__ import annotations

import pytest

from mcp_proxy import db as core_db
from mcp_proxy import kms as core_kms
from mcp_proxy import plugins as core_plugins
from mcp_proxy.kms.factory import get_kms_provider, reset_kms_provider
from mcp_proxy.kms.local import LocalKMSProvider


@pytest.fixture(autouse=True)
async def _fresh_state(monkeypatch):
    """Each test starts with a fresh in-memory DB + clean caches."""
    reset_kms_provider()
    core_plugins.reset_registry()
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "local")
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "1")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await core_db.init_db("sqlite+aiosqlite:///:memory:")
    yield
    await core_db.dispose_db()
    reset_kms_provider()
    core_plugins.reset_registry()
    get_settings.cache_clear()


# ── LocalKMSProvider ───────────────────────────────────────────────────────


async def test_local_provider_returns_none_when_unset():
    provider = LocalKMSProvider()
    assert await provider.load_org_ca() is None


async def test_local_provider_round_trips_org_ca():
    provider = LocalKMSProvider()
    await provider.store_org_ca("KEY-PEM", "CERT-PEM")
    loaded = await provider.load_org_ca()
    assert loaded == ("KEY-PEM", "CERT-PEM")


async def test_local_provider_overwrite():
    provider = LocalKMSProvider()
    await provider.store_org_ca("KEY-1", "CERT-1")
    await provider.store_org_ca("KEY-2", "CERT-2")
    loaded = await provider.load_org_ca()
    assert loaded == ("KEY-2", "CERT-2")


# ── factory ─────────────────────────────────────────────────────────────────


async def test_factory_default_returns_local_provider():
    provider = get_kms_provider()
    assert isinstance(provider, LocalKMSProvider)


async def test_factory_caches_singleton():
    a = get_kms_provider()
    b = get_kms_provider()
    assert a is b


async def test_factory_unknown_backend_raises_clearly(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "aws")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    reset_kms_provider()

    with pytest.raises(RuntimeError, match="MCP_PROXY_KMS_BACKEND='aws'"):
        get_kms_provider()


async def test_factory_dispatches_to_plugin(monkeypatch):
    """A plugin's kms_factory hook gets to provide an alternate backend."""

    class FakeProvider:
        name = "aws"

        async def load_org_ca(self):
            return ("FAKE-KEY", "FAKE-CERT")

        async def store_org_ca(self, key_pem, cert_pem):
            self.last_store = (key_pem, cert_pem)

    class FakePlugin(core_plugins.Plugin):
        name = "fake-aws-kms"
        instance = FakeProvider()

        def kms_factory(self, provider):
            if provider == "aws":
                return lambda settings: self.instance
            return None

    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "aws")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    reset_kms_provider()

    fake_registry = core_plugins.PluginRegistry(plugins=[FakePlugin()])
    monkeypatch.setattr(core_plugins, "_registry", fake_registry)

    provider = get_kms_provider()
    assert isinstance(provider, FakeProvider)
    assert await provider.load_org_ca() == ("FAKE-KEY", "FAKE-CERT")


async def test_factory_rejects_plugin_returning_non_provider(monkeypatch):
    """A misbehaving plugin must be flagged loudly, not silently used."""

    class BadPlugin(core_plugins.Plugin):
        name = "bad"

        def kms_factory(self, provider):
            if provider == "aws":
                return lambda settings: "not a provider"
            return None

    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "aws")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    reset_kms_provider()

    fake_registry = core_plugins.PluginRegistry(plugins=[BadPlugin()])
    monkeypatch.setattr(core_plugins, "_registry", fake_registry)

    with pytest.raises(RuntimeError, match="does not satisfy the KMSProvider protocol"):
        get_kms_provider()


# ── public-package surface ──────────────────────────────────────────────────


def test_module_exports_are_stable():
    """The cullis-enterprise plugins import these names — keep them stable."""
    assert core_kms.KMSProvider is not None
    assert core_kms.LocalKMSProvider is LocalKMSProvider
    assert core_kms.get_kms_provider is get_kms_provider
    assert core_kms.reset_kms_provider is reset_kms_provider
