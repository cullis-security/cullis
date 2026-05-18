"""KMS provider resolution — local default, plugins for everything else.

Reads ``MCP_PROXY_KMS_BACKEND`` from settings. When it equals ``local``
(the default), returns the in-tree :class:`LocalKMSProvider`. Any other
value goes through the plugin registry's ``kms_factory(name)`` hook;
the first plugin that returns a non-None factory wins. The factory
callable is invoked with the active :class:`Settings` so the plugin can
read its own config (region, key id, secret path).

Module-level cache ensures every call site shares the same provider
instance through the lifetime of the process. Tests use
:func:`reset_kms_provider` to clear it.
"""
from __future__ import annotations

import logging
from typing import Optional

from mcp_proxy.kms.local import LocalKMSProvider
from mcp_proxy.kms.provider import KMSProvider

_log = logging.getLogger("mcp_proxy.kms")
_provider: Optional[KMSProvider] = None


def reset_kms_provider() -> None:
    """Test-only: drop the cached provider so the next ``get_kms_provider`` re-resolves."""
    global _provider
    _provider = None


def get_kms_provider() -> KMSProvider:
    """Return the active Mastio KMS provider, resolving once per process.

    Resolution order:
      1. ``MCP_PROXY_KMS_BACKEND`` == ``local`` (default) → :class:`LocalKMSProvider`.
      2. Any other value → the plugin registry's ``kms_factory(backend)``
         hook. First plugin that returns a non-None factory provides
         the implementation.
      3. Unknown backend with no plugin handler → :class:`RuntimeError`.
    """
    global _provider
    if _provider is not None:
        return _provider

    from mcp_proxy.config import get_settings
    settings = get_settings()
    backend = (settings.kms_backend or "local").strip().lower()

    if backend == "local":
        _provider = LocalKMSProvider()
        _log.info("KMS provider: local (proxy_config DB)")
        return _provider

    if backend == "vault":
        # In-tree provider (ADR-031). Vault is part of the open-core
        # stack alongside the dashboard /proxy/vault page and the
        # mcp_proxy.tools.secrets.VaultSecretProvider used for tool
        # credentials, so it does not gate on the enterprise plugin.
        from mcp_proxy.kms.vault import VaultKMSProvider
        _provider = VaultKMSProvider(
            vault_addr=settings.vault_addr,
            vault_token=settings.vault_token,
            org_ca_path=settings.vault_org_ca_path,
            verify_tls=settings.vault_verify_tls,
            ca_cert_path=settings.vault_ca_cert_path,
            intermediate_ca_path=getattr(
                settings, "vault_intermediate_ca_path", "",
            ),
        )
        _log.info(
            "KMS provider: vault (path=%s)",
            settings.vault_org_ca_path,
        )
        return _provider

    # Plugin-provided backend.
    from mcp_proxy.plugins import get_registry
    factory = get_registry().kms_factory(backend)
    if factory is None:
        raise RuntimeError(
            f"MCP_PROXY_KMS_BACKEND={backend!r} but no plugin handles "
            "this backend. Either install the matching cullis-enterprise "
            "extra (e.g. ``pip install cullis-enterprise[cloud_kms_aws]``) "
            "and license the feature, or set MCP_PROXY_KMS_BACKEND=local "
            "or vault.",
        )

    provider = factory(settings)
    if not isinstance(provider, KMSProvider):
        raise RuntimeError(
            f"plugin kms_factory({backend!r}) returned {type(provider)!r} "
            "which does not satisfy the KMSProvider protocol",
        )
    _provider = provider
    _log.info("KMS provider: %s (plugin-provided)", backend)
    return _provider
