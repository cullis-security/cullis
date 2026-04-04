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
