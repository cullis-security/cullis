"""Elliptic-curve keypair generation and PEM serialisation.

EC P-256 is the target: matches the proxy's SPIFFE-friendly SAN format and
is the modern default for agent-to-agent mTLS in the Cullis stack. RSA
could be added here without changing callers (``generate_keypair`` returns
an opaque handle usable for signing / serialisation).
"""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)


def generate_keypair() -> PrivateKeyTypes:
    """Return a fresh EC P-256 private key. The public half is accessible
    via ``key.public_key()``."""
    return ec.generate_private_key(ec.SECP256R1())


def private_key_to_pem(key: PrivateKeyTypes) -> bytes:
    """Serialise the private key as unencrypted PKCS#8 PEM.

    Unencrypted is acceptable because the file on disk is guarded by
    ``chmod 600`` and lives under the user's home directory. Future work
    can opt into OS keyring / Vault-backed storage.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: PublicKeyTypes) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
