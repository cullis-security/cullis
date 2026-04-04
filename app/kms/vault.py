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

import httpx
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization

_log = logging.getLogger("agent_trust")

_VAULT_READ_TIMEOUT = 10


class VaultKMSProvider:
    """
    Fetches the broker CA private key from HashiCorp Vault KV v2.

    Keys are fetched once at first use and cached in memory for the
    lifetime of the process.  Call invalidate_cache() to force a refresh
    (e.g. after key rotation).
    """

    def __init__(self, vault_addr: str, vault_token: str, secret_path: str) -> None:
        self._vault_addr = vault_addr.rstrip("/")
        self._vault_token = vault_token
        self._secret_path = secret_path  # e.g. "secret/data/broker"
        self._private_key_pem: str | None = None
        self._public_key_pem: str | None = None

    def invalidate_cache(self) -> None:
        """Force re-fetch on next access (e.g. after key rotation)."""
        self._private_key_pem = None
        self._public_key_pem = None

    async def _fetch_secret(self) -> dict:
        """Fetch the secret dict from Vault KV v2."""
        url = f"{self._vault_addr}/v1/{self._secret_path}"
        async with httpx.AsyncClient(timeout=_VAULT_READ_TIMEOUT) as client:
            resp = await client.get(url, headers={"X-Vault-Token": self._vault_token})
            if resp.status_code != 200:
                _log.error("Vault returned HTTP %d for %s: %s",
                           resp.status_code, self._secret_path, resp.text)
                raise RuntimeError(
                    f"Vault returned HTTP {resp.status_code} — check broker logs for details"
                )
            return resp.json()["data"]["data"]

    async def get_broker_private_key_pem(self) -> str:
        if self._private_key_pem is None:
            secret = await self._fetch_secret()
            if "private_key_pem" not in secret:
                raise RuntimeError(
                    f"Vault secret at '{self._secret_path}' missing field 'private_key_pem'"
                )
            self._private_key_pem = secret["private_key_pem"]
            _log.info("KMS[vault] broker private key fetched from %s", self._secret_path)
        return self._private_key_pem

    async def get_broker_public_key_pem(self) -> str:
        if self._public_key_pem is None:
            secret = await self._fetch_secret()
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
