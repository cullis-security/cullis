"""``KMSProvider`` protocol — Mastio PKI persistence backend.

Today the protocol covers load + store for both the Org CA (root) and
the Mastio Intermediate CA. Pre-three-tier-hardening the Intermediate
bypassed the KMS layer and went straight into ``proxy_config``; the new
contract routes both through the same backend so cloud KMS / Vault /
HSM plugins can govern the full PKI chain. A future Phase adds a
sign-only interface (``sign(message, hash_alg)``) for HSM-backed keys
that never leave the device.

Implementations live in :mod:`mcp_proxy.kms.local` (default,
``pki_key_store`` table with Fernet at-rest encryption) and in
``cullis_enterprise.mastio.cloud_kms_*`` (proprietary providers).
"""
from typing import Protocol, runtime_checkable


@runtime_checkable
class KMSProvider(Protocol):
    """Persistence backend for the Mastio PKI keypairs (Root + Intermediate)."""

    async def load_org_ca(self) -> tuple[str, str] | None:
        """Return ``(key_pem, cert_pem)`` if the Org CA has been stored.

        Returns ``None`` when the CA has never been generated (first
        boot in standalone mode, or before the attach-ca flow on a
        federated deploy).
        """
        ...

    async def store_org_ca(self, key_pem: str, cert_pem: str) -> None:
        """Persist a freshly generated Org CA keypair + cert.

        Implementations must be idempotent on identical inputs and must
        replace any earlier value atomically.
        """
        ...

    async def load_intermediate_ca(self) -> tuple[str, str] | None:
        """Return ``(key_pem, cert_pem)`` for the active Mastio Intermediate CA.

        Returns ``None`` when no Intermediate has been minted yet (first
        boot post-Org-CA, or after a rotation that staged but never
        activated).
        """
        ...

    async def store_intermediate_ca(self, key_pem: str, cert_pem: str) -> None:
        """Persist a freshly generated Mastio Intermediate CA keypair + cert.

        Implementations must be idempotent on identical inputs and must
        replace any earlier value atomically.
        """
        ...
