"""
KMS Provider Protocol — abstract interface for key management backends.

All backends must implement this protocol.  The broker uses only these
methods, so swapping the backend (Vault → Azure → AWS) requires only
changing KMS_BACKEND in the environment — no code changes elsewhere.
"""
from typing import Protocol, runtime_checkable


@runtime_checkable
class KMSProvider(Protocol):
    async def get_broker_private_key_pem(self) -> str:
        """Return the broker CA private key in PEM format."""
        ...

    async def get_broker_public_key_pem(self) -> str:
        """Return the broker CA public key in PEM format."""
        ...

    async def get_secret_encryption_key(self) -> bytes:
        """Return the 32-byte master key used to derive at-rest secret KEKs.

        H8 audit fix: the secret-encryption master key is decoupled from
        the broker CA private key. Each backend manages its own
        lifecycle (filesystem file, Vault KV field, cloud KMS-wrapped
        material). On first call the backend may auto-generate it
        (random 32 bytes) and persist it; subsequent calls return the
        same bytes for the lifetime of the deployment until rotated.
        """
        ...

    async def encrypt_secret(self, plaintext: str) -> str:
        """Encrypt a secret string for storage at rest."""
        ...

    async def decrypt_secret(self, stored: str) -> str:
        """Decrypt a stored secret. Legacy plaintext returned as-is."""
        ...
