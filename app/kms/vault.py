"""
VaultKMSProvider — retrieves broker keys from HashiCorp Vault KV v2.

The private key PEM is stored in Vault at VAULT_SECRET_PATH.
The public key is derived from the broker CA certificate stored alongside it.

Compatible with any Vault-compatible API:
  - HashiCorp Vault (on-premise or HCP)
  - OpenBao (open-source Vault fork)

For Azure Key Vault or AWS KMS, implement a separate provider following
the same KMSProvider protocol and set KMS_BACKEND accordingly.

Environment variables:
  VAULT_ADDR         Vault server URL  (e.g. http://vault:8200)
  VAULT_TOKEN        Vault token with read access to VAULT_SECRET_PATH
  VAULT_SECRET_PATH  KV v2 path        (e.g. secret/data/broker)
                     defaults to "secret/data/broker"
"""
import logging
import os
from pathlib import Path

import httpx
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization

_log = logging.getLogger("agent_trust")

_VAULT_READ_TIMEOUT = 10


class VaultSecretNotFound(Exception):
    """Raised when Vault returns 404 for the broker secret path.

    Distinct from other Vault errors so callers can choose to fall back
    to an alternative source (e.g. filesystem Secret mount) only on
    not-yet-seeded paths, without masking real Vault outages.
    """


class VaultKMSProvider:
    """
    Fetches the broker CA private key from HashiCorp Vault KV v2.

    Keys are fetched once at first use and cached in memory for the
    lifetime of the process.  Call invalidate_cache() to force a refresh
    (e.g. after key rotation).

    If Vault returns 404 for the secret path (i.e. not yet seeded — e.g.
    first boot on a fresh cluster before the post-install push Job has
    run) and filesystem fallback paths were provided to the constructor,
    the provider reads the PEMs from disk. This breaks the readyz /
    Vault-push deadlock that occurs under `helm install --wait` when
    the chart seeds Vault post-install. Other Vault errors (500,
    timeout, connection refused) still propagate so real outages are
    not silently masked.
    """

    def __init__(
        self,
        vault_addr: str,
        vault_token: str,
        secret_path: str,
        fallback_key_path: str | None = None,
        fallback_cert_path: str | None = None,
    ) -> None:
        self._vault_addr = vault_addr.rstrip("/")
        self._vault_token = vault_token
        self._secret_path = secret_path  # e.g. "secret/data/broker"
        self._fallback_key_path = fallback_key_path
        self._fallback_cert_path = fallback_cert_path
        self._private_key_pem: str | None = None
        self._public_key_pem: str | None = None

        # Enforce TLS — Vault token is the most sensitive credential
        if not self._vault_addr.startswith("https://"):
            allow_http = os.environ.get("VAULT_ALLOW_HTTP", "").lower() == "true"
            if allow_http:
                _log.warning("Vault address uses HTTP (TLS disabled via VAULT_ALLOW_HTTP=true) — NOT safe for production")
            else:
                _log.critical("Vault address '%s' does not use HTTPS — refusing to send token over plaintext", self._vault_addr)
                raise ValueError(
                    f"Vault address must use https:// (got '{self._vault_addr}'). "
                    "Set VAULT_ALLOW_HTTP=true to override for development only."
                )

    def invalidate_cache(self) -> None:
        """Force re-fetch on next access (e.g. after key rotation)."""
        self._private_key_pem = None
        self._public_key_pem = None

    async def _fetch_secret(self) -> dict:
        """Fetch the secret dict from Vault KV v2.

        Raises VaultSecretNotFound on 404, RuntimeError on any other
        non-200. The distinction matters: callers fall back to the
        filesystem only on not-yet-seeded (404), never on real outages.
        """
        url = f"{self._vault_addr}/v1/{self._secret_path}"
        _ca_cert = os.environ.get("VAULT_CA_CERT", "")
        _verify: bool | str = _ca_cert if _ca_cert else True
        async with httpx.AsyncClient(timeout=_VAULT_READ_TIMEOUT, verify=_verify) as client:
            resp = await client.get(url, headers={"X-Vault-Token": self._vault_token})
            if resp.status_code == 404:
                raise VaultSecretNotFound(
                    f"Vault path '{self._secret_path}' returned 404 (not yet seeded)"
                )
            if resp.status_code != 200:
                _log.error("Vault returned HTTP %d for %s: %s",
                           resp.status_code, self._secret_path, resp.text)
                raise RuntimeError(
                    f"Vault returned HTTP {resp.status_code} — check broker logs for details"
                )
            return resp.json()["data"]["data"]

    def _read_fallback_private_key(self) -> str | None:
        if self._fallback_key_path and Path(self._fallback_key_path).exists():
            _log.warning(
                "KMS[vault] secret not seeded yet — falling back to filesystem key at %s. "
                "This is expected on first boot before the Vault-push Job runs; "
                "subsequent boots will read from Vault.",
                self._fallback_key_path,
            )
            return Path(self._fallback_key_path).read_text()
        return None

    def _read_fallback_cert(self) -> str | None:
        if self._fallback_cert_path and Path(self._fallback_cert_path).exists():
            _log.warning(
                "KMS[vault] secret not seeded yet — falling back to filesystem cert at %s.",
                self._fallback_cert_path,
            )
            return Path(self._fallback_cert_path).read_text()
        return None

    async def get_broker_private_key_pem(self) -> str:
        if self._private_key_pem is None:
            secret: dict | None = None
            try:
                secret = await self._fetch_secret()
            except VaultSecretNotFound:
                pass
            # Fallback when either the Vault path doesn't exist (404) or the
            # path exists but doesn't carry the broker CA yet. The latter
            # happens because admin_secret.ensure_bootstrapped may write
            # `admin_secret_hash` into the same KV path first, so the path
            # is 200 but without `private_key_pem`. Both are "CA not yet
            # seeded" from the broker's perspective — fall back to the
            # filesystem Secret mount.
            if secret is None or "private_key_pem" not in secret:
                pem = self._read_fallback_private_key()
                if pem is None:
                    raise RuntimeError(
                        f"Vault secret at '{self._secret_path}' missing "
                        f"'private_key_pem' and no filesystem fallback key "
                        f"available. Seed Vault or mount the CA Secret at "
                        f"the configured fallback path."
                    )
                self._private_key_pem = pem
                return self._private_key_pem
            self._private_key_pem = secret["private_key_pem"]
            _log.info("KMS[vault] broker private key fetched from %s", self._secret_path)
        return self._private_key_pem

    async def get_broker_public_key_pem(self) -> str:
        if self._public_key_pem is None:
            secret: dict | None = None
            try:
                secret = await self._fetch_secret()
            except VaultSecretNotFound:
                pass
            # Same fallback logic as get_broker_private_key_pem: 404 or
            # path-exists-without-CA-fields both trigger filesystem fallback.
            if secret is None or (
                "ca_cert_pem" not in secret and "public_key_pem" not in secret
            ):
                pem = self._read_fallback_cert()
                if pem is None:
                    raise RuntimeError(
                        f"Vault secret at '{self._secret_path}' missing "
                        f"'ca_cert_pem' / 'public_key_pem' and no filesystem "
                        f"fallback cert available."
                    )
                cert = crypto_x509.load_pem_x509_certificate(pem.encode())
                self._public_key_pem = cert.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
                return self._public_key_pem
            if "ca_cert_pem" in secret:
                # Derive public key from the CA certificate
                cert = crypto_x509.load_pem_x509_certificate(
                    secret["ca_cert_pem"].encode()
                )
                self._public_key_pem = cert.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode()
            elif "public_key_pem" in secret:
                self._public_key_pem = secret["public_key_pem"]
            else:
                raise RuntimeError(
                    f"Vault secret at '{self._secret_path}' missing 'ca_cert_pem' or 'public_key_pem'"
                )
            _log.info("KMS[vault] broker public key fetched from %s", self._secret_path)
        return self._public_key_pem

    async def encrypt_secret(self, plaintext: str) -> str:
        from app.kms.secret_encrypt import encrypt_secret
        pem = await self.get_broker_private_key_pem()
        return encrypt_secret(pem, plaintext)

    async def decrypt_secret(self, stored: str) -> str:
        from app.kms.secret_encrypt import decrypt_secret
        pem = await self.get_broker_private_key_pem()
        return decrypt_secret(pem, stored)
