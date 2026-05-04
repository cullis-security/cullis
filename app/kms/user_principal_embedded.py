"""Embedded UserPrincipalKMS backend — SQLite + AES-256-GCM at rest.

Fallback backend for deployments without a real KMS (small mid-market
customers without Vault/AWS KMS/Azure KV, plus dev sandboxes and the
test suite). Keys live in a SQLite file at ``<config_dir>/user_principals.db``,
each private key wrapped with AES-256-GCM under a master key supplied
through the environment.

Security caveat (documented in ``imp/adr-021-shared-mode-multi-user-kms.md``
§11 T2): a process compromise leaks the master key + the SQLite, which
is full key exfiltration for every provisioned user. This backend is
NOT recommended for compliance-sensitive deployments — Vault/AWS/Azure
backends keep the private key server-side and limit blast radius.

The master key MUST be supplied explicitly via ``CULLIS_USER_KMS_MASTER_KEY``
(64 hex chars = 32 bytes). The backend refuses to auto-generate one,
so the operator cannot accidentally ship with a default secret.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.kms.user_principal import (
    ALG_ES256,
    SUPPORTED_ALGS,
    CertificateNotAttachedError,
    PrincipalAlreadyExistsError,
    PrincipalNotFoundError,
    PrincipalRevokedError,
    ProvisioningResult,
)

_log = logging.getLogger("agent_trust")

# Env var name that supplies the wrapping key. Must be 64 hex chars
# (32 bytes). Generate with ``openssl rand -hex 32``.
ENV_MASTER_KEY = "CULLIS_USER_KMS_MASTER_KEY"

# AES-GCM nonce length: 12 bytes is the recommended default.
_NONCE_LEN = 12

# Maximum principal_id length (matches the planned ``user_principals``
# table column in PR2). 255 is generous for ``<td>/<org>/<type>/<name>``.
_MAX_PRINCIPAL_ID_LEN = 255

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS user_principals_keys (
    principal_id           TEXT PRIMARY KEY,
    alg                    TEXT NOT NULL,
    encrypted_private_key  BLOB NOT NULL,
    public_key_pem         TEXT NOT NULL,
    certificate_pem        TEXT,
    created_at             TEXT NOT NULL,
    revoked_at             TEXT
);
"""


def _load_master_key() -> bytes:
    """Read the master key from the environment.

    Raises ``RuntimeError`` if the env var is missing or malformed.
    """
    raw = os.environ.get(ENV_MASTER_KEY, "").strip()
    if not raw:
        raise RuntimeError(
            f"{ENV_MASTER_KEY} is required for the embedded "
            "UserPrincipalKMS backend. Generate one with "
            "`openssl rand -hex 32` and export it. The backend refuses "
            "to auto-generate the master key so you can't accidentally "
            "ship with a default secret.",
        )
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise RuntimeError(
            f"{ENV_MASTER_KEY} must be 64 hex chars; got non-hex input.",
        ) from exc
    if len(key) != 32:
        raise RuntimeError(
            f"{ENV_MASTER_KEY} must decode to 32 bytes (64 hex chars); "
            f"got {len(key)} bytes.",
        )
    return key


def _validate_principal_id(principal_id: str) -> None:
    if not principal_id:
        raise ValueError("principal_id must be a non-empty string")
    if len(principal_id) > _MAX_PRINCIPAL_ID_LEN:
        raise ValueError(
            f"principal_id exceeds {_MAX_PRINCIPAL_ID_LEN} chars "
            f"(got {len(principal_id)})",
        )
    if not principal_id.isascii() or not principal_id.isprintable():
        raise ValueError("principal_id must be ASCII printable")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class EmbeddedUserPrincipalKMS:
    """SQLite + AES-256-GCM implementation of ``UserPrincipalKMS``.

    Concurrency model: SQLite is sync. We wrap every operation in
    ``asyncio.to_thread`` so the surrounding async code is not blocked.
    Within the worker thread we open a fresh ``sqlite3.Connection`` per
    operation — SQLite connections are not safe to share across
    threads without explicit ``check_same_thread=False`` and locking.
    File-level locking (SQLite's default) gives us serialization for
    free at this scale (single-process, low-contention).
    """

    def __init__(self, db_path: str | Path, master_key: bytes | None = None) -> None:
        self._db_path = Path(db_path)
        if master_key is None:
            master_key = _load_master_key()
        if len(master_key) != 32:
            raise ValueError(
                "master_key must be exactly 32 bytes (got %d)" % len(master_key),
            )
        self._aead = AESGCM(master_key)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        # Initialise schema synchronously at construction; subsequent
        # async ops can rely on the table existing.
        self._init_schema()

    # ── schema / connection ────────────────────────────────────────

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA_SQL)
        # Tighten file perms — same sensitivity as the broker CA key.
        try:
            os.chmod(self._db_path, 0o600)
        except OSError:
            _log.info(
                "could not chmod 0600 on %s (filesystem may not support it)",
                self._db_path,
            )

    def _connect(self) -> sqlite3.Connection:
        # ``isolation_level=None`` puts us in autocommit; we issue
        # explicit transactions for write paths via ``BEGIN``.
        conn = sqlite3.connect(
            self._db_path,
            isolation_level=None,
            timeout=5.0,
        )
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    # ── crypto helpers ─────────────────────────────────────────────

    def _wrap(self, plaintext: bytes, principal_id: str) -> bytes:
        """AES-256-GCM seal. AAD binds the ciphertext to the principal_id
        so a stolen ciphertext cannot be replayed under a different id.
        """
        nonce = os.urandom(_NONCE_LEN)
        ct = self._aead.encrypt(nonce, plaintext, principal_id.encode("utf-8"))
        return nonce + ct

    def _unwrap(self, blob: bytes, principal_id: str) -> bytes:
        if len(blob) < _NONCE_LEN + 16:
            raise InvalidTag("ciphertext too short")
        nonce = blob[:_NONCE_LEN]
        ct = blob[_NONCE_LEN:]
        return self._aead.decrypt(nonce, ct, principal_id.encode("utf-8"))

    # ── Protocol implementation ────────────────────────────────────

    async def has_principal(self, principal_id: str) -> bool:
        _validate_principal_id(principal_id)
        return await asyncio.to_thread(self._has_sync, principal_id)

    def _has_sync(self, principal_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM user_principals_keys WHERE principal_id = ?",
                (principal_id,),
            ).fetchone()
        return row is not None

    async def create_keypair(
        self,
        principal_id: str,
        *,
        alg: str = ALG_ES256,
    ) -> ProvisioningResult:
        _validate_principal_id(principal_id)
        if alg not in SUPPORTED_ALGS:
            raise ValueError(
                f"alg '{alg}' not supported (v0.1 ships {sorted(SUPPORTED_ALGS)})",
            )
        return await asyncio.to_thread(self._create_keypair_sync, principal_id, alg)

    def _create_keypair_sync(self, principal_id: str, alg: str) -> ProvisioningResult:
        # ES256 = ECC P-256. RS256 will land alongside its first user.
        priv = ec.generate_private_key(ec.SECP256R1())
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        wrapped = self._wrap(priv_pem, principal_id)
        created_at = _now_iso()

        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO user_principals_keys "
                    "(principal_id, alg, encrypted_private_key, "
                    " public_key_pem, certificate_pem, created_at, revoked_at) "
                    "VALUES (?, ?, ?, ?, NULL, ?, NULL)",
                    (principal_id, alg, wrapped, pub_pem, created_at),
                )
        except sqlite3.IntegrityError as exc:
            raise PrincipalAlreadyExistsError(
                f"principal '{principal_id}' already provisioned; "
                "revoke first to re-provision",
            ) from exc

        return ProvisioningResult(
            public_key_pem=pub_pem,
            key_handle=f"embedded:{principal_id}",
            alg=alg,
        )

    async def attach_certificate(
        self,
        principal_id: str,
        cert_pem: str,
    ) -> None:
        _validate_principal_id(principal_id)
        if not cert_pem.strip():
            raise ValueError("cert_pem must be a non-empty PEM string")
        await asyncio.to_thread(
            self._attach_certificate_sync, principal_id, cert_pem,
        )

    def _attach_certificate_sync(
        self, principal_id: str, cert_pem: str,
    ) -> None:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE user_principals_keys SET certificate_pem = ? "
                "WHERE principal_id = ?",
                (cert_pem, principal_id),
            )
            if cur.rowcount == 0:
                raise PrincipalNotFoundError(principal_id)

    async def get_certificate(self, principal_id: str) -> str:
        _validate_principal_id(principal_id)
        return await asyncio.to_thread(
            self._get_certificate_sync, principal_id,
        )

    def _get_certificate_sync(self, principal_id: str) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT certificate_pem FROM user_principals_keys "
                "WHERE principal_id = ?",
                (principal_id,),
            ).fetchone()
        if row is None:
            raise PrincipalNotFoundError(principal_id)
        cert = row[0]
        if cert is None:
            raise CertificateNotAttachedError(principal_id)
        return cert

    async def sign(self, principal_id: str, payload: bytes) -> bytes:
        _validate_principal_id(principal_id)
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        return await asyncio.to_thread(self._sign_sync, principal_id, bytes(payload))

    def _sign_sync(self, principal_id: str, payload: bytes) -> bytes:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT encrypted_private_key, alg, revoked_at "
                "FROM user_principals_keys WHERE principal_id = ?",
                (principal_id,),
            ).fetchone()
        if row is None:
            raise PrincipalNotFoundError(principal_id)
        encrypted_pk, alg, revoked_at = row
        if revoked_at is not None:
            raise PrincipalRevokedError(principal_id)

        priv_pem = self._unwrap(encrypted_pk, principal_id)
        try:
            priv = serialization.load_pem_private_key(priv_pem, password=None)
        finally:
            # Best-effort scrub of the in-process plaintext copy. Python
            # bytes are immutable so this only zeroes the local name; the
            # original buffer may linger in memory until GC. The KMS
            # backends in PR3+ avoid this by never decrypting.
            priv_pem = b"\x00" * len(priv_pem)
            del priv_pem

        if alg == ALG_ES256:
            return priv.sign(payload, ec.ECDSA(hashes.SHA256()))
        # Defensive: schema constrains alg, but be explicit.
        raise ValueError(f"stored alg '{alg}' not supported by this backend")

    async def revoke_principal(self, principal_id: str) -> None:
        _validate_principal_id(principal_id)
        await asyncio.to_thread(self._revoke_sync, principal_id)

    def _revoke_sync(self, principal_id: str) -> None:
        revoked_at = _now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE user_principals_keys "
                "SET revoked_at = COALESCE(revoked_at, ?) "
                "WHERE principal_id = ?",
                (revoked_at, principal_id),
            )
            if cur.rowcount == 0:
                raise PrincipalNotFoundError(principal_id)


__all__ = [
    "ENV_MASTER_KEY",
    "EmbeddedUserPrincipalKMS",
]
