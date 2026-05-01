"""
LocalKMSProvider — reads broker keys from the local filesystem.

Used for development, tests, and environments without a KMS backend.
KMS_BACKEND=local (default when VAULT_ADDR is not set).
"""
import logging
import os
import secrets
from pathlib import Path

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization

_log = logging.getLogger("agent_trust")


class LocalKMSProvider:
    """Reads the broker CA private key and certificate from disk."""

    def __init__(
        self,
        key_path: str,
        cert_path: str,
        secret_encryption_key_path: str | None = None,
    ) -> None:
        self._key_path = key_path
        self._cert_path = cert_path
        # H8 audit fix — separate master key for at-rest secret
        # encryption. Defaults to a sibling of the CA private key when
        # the operator hasn't pinned a path, so a fresh deploy gets a
        # working setup without extra config.
        if secret_encryption_key_path is None:
            secret_encryption_key_path = str(
                Path(key_path).parent / "secret_encryption.key",
            )
        self._secret_encryption_key_path = secret_encryption_key_path
        # Cached values — loaded once on first access
        self._private_key_pem: str | None = None
        self._public_key_pem: str | None = None
        self._secret_encryption_key: bytes | None = None

    async def get_broker_private_key_pem(self) -> str:
        if self._private_key_pem is None:
            path = Path(self._key_path)
            self._check_key_file_perms(path)
            self._private_key_pem = path.read_text()
            _log.info("KMS[local] broker private key loaded from %s", self._key_path)
        return self._private_key_pem

    @staticmethod
    def _check_key_file_perms(path: Path) -> None:
        """Refuse to load the Org CA private key from a world/group-readable file.

        H-kms-perms audit fix: the broker CA private key signs every
        agent cert and JWT the Mastio issues; its compromise blasts
        the entire Org's trust. A POSIX file with mode ``0644`` (or
        anything with bits set in ``0o077``) lets every local process
        on the host read it — the file system stops being a defence.

        Production deployments fail-closed: refuse to read and raise.
        Development can opt out via
        ``MCP_PROXY_ALLOW_LOOSE_CA_KEY_PERMS=1`` for shared-fs
        scenarios where the operator accepts the trade-off.
        """
        import os
        try:
            mode = path.stat().st_mode & 0o777
        except OSError as exc:
            raise RuntimeError(
                f"Cannot stat Org CA private key at {path}: {exc}",
            ) from exc

        loose_bits = mode & 0o077
        if loose_bits == 0:
            return

        env_override = os.environ.get(
            "MCP_PROXY_ALLOW_LOOSE_CA_KEY_PERMS", "",
        ).lower() in ("1", "true", "yes")

        msg = (
            f"Org CA private key {path} has loose POSIX perms {oct(mode)}. "
            "Tighten with `chmod 0600 %s` so only the Mastio process "
            "user can read it. Loose perms let any local process steal "
            "the key that signs every Org cert."
        ) % path

        from app.config import get_settings as _get_settings
        settings = _get_settings()
        is_production = getattr(settings, "environment", "") == "production"

        if env_override:
            _log.warning(
                "%s — MCP_PROXY_ALLOW_LOOSE_CA_KEY_PERMS=1 override "
                "in effect, accepting the trade-off.", msg,
            )
            return
        if is_production:
            _log.critical(msg)
            raise RuntimeError(
                f"Refusing to load Org CA private key with loose perms "
                f"{oct(mode)} in production. Set "
                "MCP_PROXY_ALLOW_LOOSE_CA_KEY_PERMS=1 to override "
                "(not recommended).",
            )
        _log.warning(
            "%s — proceeding because environment != production.", msg,
        )

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

    async def get_secret_encryption_key(self) -> bytes:
        """Load or generate the 32-byte secret-encryption master key.

        H8 audit fix: the master key is decoupled from the Org CA. On
        first boot we generate 32 random bytes, write them to
        ``secret_encryption.key`` with 0600 perms, and reuse that file
        on subsequent boots. Operators wanting deterministic keys for
        backup/restore can pre-populate the file (must be 32 bytes
        binary or 64 hex chars).
        """
        if self._secret_encryption_key is not None:
            return self._secret_encryption_key
        path = Path(self._secret_encryption_key_path)
        if path.exists():
            raw = path.read_bytes().strip()
            # Allow either raw 32-byte binary OR a 64-char hex string
            # (operators commonly paste hex from `openssl rand -hex 32`).
            if len(raw) == 32:
                key = bytes(raw)
            elif len(raw) == 64 and all(0x30 <= b <= 0x66 for b in raw):
                try:
                    key = bytes.fromhex(raw.decode("ascii"))
                except ValueError:
                    key = bytes(raw)
            else:
                raise RuntimeError(
                    f"KMS[local] {path} must be 32 raw bytes or 64 hex "
                    f"chars (got {len(raw)} bytes). Regenerate with "
                    "`openssl rand -out secret_encryption.key 32`.",
                )
            _log.info("KMS[local] secret-encryption master key loaded from %s", path)
        else:
            key = secrets.token_bytes(32)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write atomically with restrictive perms — the master key
            # has the same sensitivity as the broker CA private key.
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(key)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            _log.warning(
                "KMS[local] generated new secret-encryption master key at %s "
                "(0600). Back this up alongside the broker CA private key — "
                "losing it makes every enc:v2 stored secret unrecoverable.",
                path,
            )
        self._secret_encryption_key = key
        return key

    async def encrypt_secret(self, plaintext: str) -> str:
        from app.kms.secret_encrypt import encrypt_secret_v2
        master_key = await self.get_secret_encryption_key()
        return encrypt_secret_v2(master_key, plaintext)

    async def decrypt_secret(self, stored: str) -> str:
        """Decrypt a stored secret. Tries v2 (master-key derived) first
        and falls back to v1 (legacy CA-derived) so existing data
        keeps decrypting through the H8 cutover.
        """
        from app.kms.secret_encrypt import (
            _ENC_PREFIX_V2,
            decrypt_secret,
            decrypt_secret_v2,
        )
        if stored.startswith(_ENC_PREFIX_V2):
            master_key = await self.get_secret_encryption_key()
            return decrypt_secret_v2(master_key, stored)
        # Legacy enc:v1 or plaintext — keep using the CA private key.
        pem = await self.get_broker_private_key_pem()
        return decrypt_secret(pem, stored)
