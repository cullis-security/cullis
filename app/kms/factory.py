"""
KMS factory — returns the configured KMSProvider based on KMS_BACKEND.

Usage (in jwt.py or anywhere broker keys are needed):
    from app.kms.factory import get_kms_provider
    kms = get_kms_provider()
    private_key_pem = await kms.get_broker_private_key_pem()

Supported backends (KMS_BACKEND env var):
  local   — reads from disk (default; dev + tests)
  vault   — HashiCorp Vault KV v2

The provider instance is a module-level singleton — instantiated once and
reused.  Keys are cached inside the provider after the first fetch.
"""
import logging

from app.kms.provider import KMSProvider

_log = logging.getLogger("agent_trust")
_provider: KMSProvider | None = None


def get_kms_provider() -> KMSProvider:
    """Return the singleton KMSProvider for this process."""
    global _provider
    if _provider is None:
        _provider = _build_provider()
    return _provider


def _build_provider() -> KMSProvider:
    from app.config import get_settings
    settings = get_settings()

    backend = settings.kms_backend.lower()

    if backend == "vault":
        from app.kms.vault import VaultKMSProvider
        if not settings.vault_addr or not settings.vault_token:
            raise RuntimeError(
                "KMS_BACKEND=vault requires VAULT_ADDR and VAULT_TOKEN to be set"
            )
        _log.info("KMS backend: vault  (%s  path=%s)", settings.vault_addr, settings.vault_secret_path)
        return VaultKMSProvider(
            vault_addr=settings.vault_addr,
            vault_token=settings.vault_token,
            secret_path=settings.vault_secret_path,
        )

    # Default: local filesystem
    if backend != "local":
        _log.warning("Unknown KMS_BACKEND '%s' — falling back to local", backend)
    _log.info("KMS backend: local  (key=%s)", settings.broker_ca_key_path)
    from app.kms.local import LocalKMSProvider
    return LocalKMSProvider(
        key_path=settings.broker_ca_key_path,
        cert_path=settings.broker_ca_cert_path,
    )
