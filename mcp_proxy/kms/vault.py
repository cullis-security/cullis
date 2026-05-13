"""``VaultKMSProvider`` — Mastio Org CA persisted in HashiCorp Vault KV v2.

Implements the :class:`KMSProvider` protocol (load/store the Org CA
keypair as PEM strings) on top of an HTTPS KV v2 mount. The default path
is ``secret/data/cullis-mastio/org-ca`` with fields ``key_pem`` +
``cert_pem``; override via :setting:`vault_org_ca_path`.

The provider is activated by ``MCP_PROXY_KMS_BACKEND=vault`` and resolved
in :mod:`mcp_proxy.kms.factory` before the plugin registry — Vault is
open-core, not an enterprise plugin.

See ADR-031 for the design and threat-model delta. Cloud KMS providers
(AWS, Azure, GCP) live under ``cullis_enterprise.mastio.cloud_kms_*``.
"""
from __future__ import annotations

import logging
import os

import httpx

_log = logging.getLogger("mcp_proxy.kms.vault")

_DEFAULT_TIMEOUT = 10.0


class VaultKMSProvider:
    """Persist the Mastio Org CA keypair in HashiCorp Vault KV v2."""

    name = "vault"

    def __init__(
        self,
        vault_addr: str,
        vault_token: str,
        org_ca_path: str,
        verify_tls: bool = True,
        ca_cert_path: str = "",
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        if not vault_addr:
            raise ValueError(
                "VaultKMSProvider requires vault_addr. Set MCP_PROXY_VAULT_ADDR "
                "or the dashboard /proxy/vault page.",
            )
        if not vault_token:
            raise ValueError(
                "VaultKMSProvider requires vault_token. Set MCP_PROXY_VAULT_TOKEN "
                "or the dashboard /proxy/vault page.",
            )
        if not org_ca_path:
            raise ValueError(
                "VaultKMSProvider requires org_ca_path (KV v2 path, e.g. "
                "secret/data/cullis-mastio/org-ca).",
            )

        self._vault_addr = vault_addr.rstrip("/")
        self._vault_token = vault_token
        self._org_ca_path = org_ca_path.lstrip("/")

        # TLS enforcement: refuse plaintext HTTP unless the operator
        # explicitly opts in for dev. Mirrors app/kms/vault.py.
        if not self._vault_addr.startswith("https://"):
            allow_http = os.environ.get("VAULT_ALLOW_HTTP", "").lower() == "true"
            if not allow_http:
                raise ValueError(
                    f"Vault address must use https:// (got {self._vault_addr!r}). "
                    "Set VAULT_ALLOW_HTTP=true to override for development only.",
                )
            _log.warning(
                "Vault address uses HTTP (VAULT_ALLOW_HTTP=true) — NOT safe for production",
            )

        # When ca_cert_path is provided, httpx uses it as the CA bundle;
        # else it falls back to verify_tls (bool). Operator can disable
        # verification only via verify_tls=False, which we surface via
        # MCP_PROXY_VAULT_VERIFY_TLS in settings.
        self._verify: bool | str = ca_cert_path if ca_cert_path else verify_tls
        self._timeout = timeout

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._vault_addr,
            headers={"X-Vault-Token": self._vault_token},
            timeout=self._timeout,
            verify=self._verify,
        )

    async def load_org_ca(self) -> tuple[str, str] | None:
        """Fetch the Org CA keypair from Vault KV v2.

        Returns ``(key_pem, cert_pem)`` on success, ``None`` when the
        path has not been seeded yet (Vault 404) or when the secret
        exists but lacks both fields (operator initialised the path with
        unrelated keys). Any other error (5xx, network, malformed JSON)
        raises ``RuntimeError`` so the Mastio fails to start rather than
        silently degrading to a missing-CA state.
        """
        url = f"/v1/{self._org_ca_path}"
        async with self._client() as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                raise RuntimeError(
                    f"Vault unreachable at {self._vault_addr}{url}: {exc}",
                ) from exc

            if resp.status_code == 404:
                _log.info(
                    "KMS[vault] Org CA path %s not seeded yet (404) — "
                    "agent_manager will generate and store",
                    self._org_ca_path,
                )
                return None
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Vault returned HTTP {resp.status_code} for "
                    f"{self._org_ca_path}: {resp.text[:200]}",
                )

            try:
                data = resp.json()["data"]["data"]
            except (KeyError, ValueError) as exc:
                raise RuntimeError(
                    f"Vault returned malformed KV v2 response for "
                    f"{self._org_ca_path}: missing data.data ({exc})",
                ) from exc

        key_pem = data.get("key_pem")
        cert_pem = data.get("cert_pem")
        if not key_pem or not cert_pem:
            _log.warning(
                "KMS[vault] Org CA path %s exists but is missing "
                "key_pem/cert_pem fields — treating as unseeded",
                self._org_ca_path,
            )
            return None

        _log.info("KMS[vault] Org CA loaded from %s", self._org_ca_path)
        return key_pem, cert_pem

    async def store_org_ca(self, key_pem: str, cert_pem: str) -> None:
        """Write the Org CA keypair to Vault KV v2 with CAS.

        Reads the current version to construct a Compare-And-Set write
        (preserves any other fields the operator may have stored under
        the same path), then POSTs. On first write the secret does not
        exist yet and we POST without a ``cas`` constraint.

        Idempotent on identical inputs; raises ``RuntimeError`` on any
        non-2xx response or network error so the caller (typically
        ``AgentManager.generate_org_ca`` after a first-boot key gen)
        does not silently lose the key material.
        """
        url = f"/v1/{self._org_ca_path}"
        async with self._client() as client:
            # Step 1: read current secret to get the CAS version + merge
            # with any pre-existing fields (e.g. operator-set metadata).
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                raise RuntimeError(
                    f"Vault unreachable during store_org_ca at "
                    f"{self._vault_addr}{url}: {exc}",
                ) from exc

            if resp.status_code == 200:
                payload = resp.json().get("data", {})
                merged = dict(payload.get("data") or {})
                version = (payload.get("metadata") or {}).get("version", 0)
                merged["key_pem"] = key_pem
                merged["cert_pem"] = cert_pem
                body = {"options": {"cas": version}, "data": merged}
            elif resp.status_code == 404:
                # First write — no prior version, no CAS constraint.
                body = {"data": {"key_pem": key_pem, "cert_pem": cert_pem}}
            else:
                raise RuntimeError(
                    f"Vault returned HTTP {resp.status_code} during "
                    f"store_org_ca pre-read of {self._org_ca_path}: "
                    f"{resp.text[:200]}",
                )

            # Step 2: write.
            try:
                write_resp = await client.post(url, json=body)
            except httpx.HTTPError as exc:
                raise RuntimeError(
                    f"Vault POST failed for {self._org_ca_path}: {exc}",
                ) from exc

            if write_resp.status_code not in (200, 204):
                raise RuntimeError(
                    f"Vault returned HTTP {write_resp.status_code} writing "
                    f"{self._org_ca_path}: {write_resp.text[:200]}",
                )

        _log.info("KMS[vault] Org CA stored to %s", self._org_ca_path)
