"""
LocalKMSProvider — reads broker keys from the local filesystem.

Used for development, tests, and environments without a KMS backend.
KMS_BACKEND=local (default when VAULT_ADDR is not set).
"""
import logging
from pathlib import Path

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization

_log = logging.getLogger("agent_trust")


class LocalKMSProvider:
    """Reads the broker CA private key and certificate from disk."""

    def __init__(self, key_path: str, cert_path: str) -> None:
        self._key_path = key_path
        self._cert_path = cert_path
        # Cached values — loaded once on first access
        self._private_key_pem: str | None = None
        self._public_key_pem: str | None = None

    async def get_broker_private_key_pem(self) -> str:
        if self._private_key_pem is None:
            self._private_key_pem = Path(self._key_path).read_text()
            _log.info("KMS[local] broker private key loaded from %s", self._key_path)
        return self._private_key_pem

    async def get_broker_public_key_pem(self) -> str:
        if self._public_key_pem is None:
            cert = crypto_x509.load_pem_x509_certificate(
                Path(self._cert_path).read_bytes()
            )
            self._public_key_pem = cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
            _log.info("KMS[local] broker public key loaded from %s", self._cert_path)
        return self._public_key_pem
