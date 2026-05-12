"""On-disk private-key store for provisioned user principals.

ADR-021 v0.1 kept the per-user EC keypair only in process memory inside
``UserCredentialCache``. The cache evicts on container restart, on TTL
expiry (1h), or on explicit invalidate. When Mastio's CRIT-1 TOFU pin
landed (``mcp_proxy/registry/principals_csr.py``), every cache miss
started minting a fresh keypair which then failed the pin check, so
the second provisioning attempt for the same user — restart, idle 1h,
or admin password reset — broke with ``CSR validation failed``.

This keystore decouples key persistence from the in-memory cred cache:

  - one PEM file per principal_id, deterministic filename keyed by the
    SHA-256 of the principal_id (no filesystem injection from user
    names; same principal_id always lands on the same path)
  - ``chmod 0600`` matches ``identity/agent.key``
  - atomic write via tmp+rename so a crash mid-write leaves the prior
    PEM intact (or no file at all)
  - async-safe per-principal access through a single asyncio lock that
    serialises read-then-create for the same principal

Cert lifetime stays short (~1h) and is always refreshed against
Mastio. The keypair survives across restarts so Mastio's TOFU pin keeps
matching.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

_log = logging.getLogger("cullis_connector.ambassador.shared.keystore")


_KEY_DIRNAME = "user_keys"
_KEY_SUFFIX = ".key.pem"


def _principal_to_filename(principal_id: str) -> str:
    """Return the deterministic filename for ``principal_id``.

    SHA-256 hex over the UTF-8 bytes — collision-resistant and avoids
    encoding the raw principal name (which may contain ``/``, ``::``,
    ``@`` or shell-unfriendly characters) on disk.
    """
    digest = hashlib.sha256(principal_id.encode("utf-8")).hexdigest()
    return f"{digest}{_KEY_SUFFIX}"


def _key_pem_from_priv(priv: ec.EllipticCurvePrivateKey) -> str:
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


class UserKeyStore:
    """Persist per-principal EC P-256 keypairs under a base directory.

    Layout::

        <base_dir>/
        ├── <sha256(principal_a)>.key.pem
        └── <sha256(principal_b)>.key.pem

    Files are ``chmod 0600``. The store is async-safe; concurrent
    ``get_or_create`` for the same principal returns the same PEM.
    """

    def __init__(self, base_dir: Path) -> None:
        if not isinstance(base_dir, Path):
            base_dir = Path(base_dir)
        self._base_dir = base_dir
        self._lock = asyncio.Lock()

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    async def get_or_create(self, principal_id: str) -> str:
        """Return the PEM-encoded private key for ``principal_id``.

        Creates and persists a fresh EC P-256 keypair on first call;
        every subsequent call returns the bytes read from disk so the
        Mastio TOFU pin keeps matching.

        Raises:
            ValueError: empty / whitespace ``principal_id``.
        """
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise ValueError("principal_id must be a non-empty string")
        path = self._base_dir / _principal_to_filename(principal_id)
        async with self._lock:
            if path.exists():
                try:
                    pem = path.read_text(encoding="utf-8")
                except OSError as exc:
                    raise RuntimeError(
                        f"failed to read user keypair at {path}: {exc}",
                    ) from exc
                _log.debug(
                    "keystore hit principal_id=%s path=%s", principal_id, path,
                )
                return pem

            priv = ec.generate_private_key(ec.SECP256R1())
            pem = _key_pem_from_priv(priv)
            self._base_dir.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(pem, encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            _log.info(
                "keystore created principal_id=%s path=%s",
                principal_id, path,
            )
            return pem

    async def invalidate(self, principal_id: str) -> bool:
        """Remove the persisted key for ``principal_id``.

        Returns True if a file was deleted, False if none existed.
        Used by admin "revoke user" actions that should also clear the
        Mastio TOFU pin — caller is responsible for the Mastio side.
        """
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise ValueError("principal_id must be a non-empty string")
        path = self._base_dir / _principal_to_filename(principal_id)
        async with self._lock:
            if not path.exists():
                return False
            try:
                path.unlink()
            except OSError as exc:
                raise RuntimeError(
                    f"failed to delete user keypair at {path}: {exc}",
                ) from exc
            _log.info(
                "keystore invalidated principal_id=%s path=%s",
                principal_id, path,
            )
            return True


def keystore_dir_for(config_dir: Path) -> Path:
    """Conventional location: ``<config_dir>/user_keys``."""
    return Path(config_dir) / _KEY_DIRNAME


__all__ = [
    "UserKeyStore",
    "keystore_dir_for",
]
