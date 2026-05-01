"""
H8 regression: at-rest secret encryption uses a dedicated master key,
not the broker CA private key.

The audit flagged ``app/kms/secret_encrypt.py`` for deriving the KEK
from the Org CA private key PEM. Two consequences: (1) rotating the CA
breaks every encrypted secret, and (2) compromising the CA discloses
every encrypted secret. The v2 path keeps the CA out of the secret-
encryption path entirely; this file locks the property in.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.kms.local import LocalKMSProvider
from app.kms.secret_encrypt import (
    _ENC_PREFIX,
    _ENC_PREFIX_V2,
    decrypt_secret,
    decrypt_secret_v2,
    encrypt_secret,
    encrypt_secret_v2,
    is_encrypted,
)

# Throwaway CA private key — used only to drive the legacy v1 codepath
# in tests; the v2 codepath never sees it.
_DUMMY_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIdummy1234567890\n-----END RSA PRIVATE KEY-----\n"


# ── encrypt_secret_v2 / decrypt_secret_v2 ──────────────────────────────


def test_v2_roundtrip() -> None:
    master_key = os.urandom(32)
    plaintext = "client-secret-9000"
    ct = encrypt_secret_v2(master_key, plaintext)
    assert ct.startswith(_ENC_PREFIX_V2)
    assert plaintext not in ct
    assert decrypt_secret_v2(master_key, ct) == plaintext


def test_v2_wrong_master_key_fails() -> None:
    ct = encrypt_secret_v2(os.urandom(32), "hello")
    with pytest.raises(ValueError, match="Failed to decrypt"):
        decrypt_secret_v2(os.urandom(32), ct)


def test_v2_short_master_key_rejected() -> None:
    """Catch operators who paste a 16-char string thinking it's the key."""
    with pytest.raises(ValueError, match="at least 16 bytes"):
        encrypt_secret_v2(b"short", "x")


def test_v1_decrypt_refuses_v2_input() -> None:
    """An enc:v2 ciphertext must not silently fall through to the v1 KEK."""
    ct = encrypt_secret_v2(os.urandom(32), "x")
    with pytest.raises(ValueError, match="enc:v2"):
        decrypt_secret(_DUMMY_PEM, ct)


def test_v2_decrypt_refuses_v1_input() -> None:
    """An enc:v1 ciphertext must not silently feed the master key path."""
    ct = encrypt_secret(_DUMMY_PEM, "x")
    assert ct.startswith(_ENC_PREFIX)
    with pytest.raises(ValueError, match="enc:v2"):
        decrypt_secret_v2(os.urandom(32), ct)


def test_is_encrypted_matches_both_prefixes() -> None:
    assert is_encrypted(encrypt_secret(_DUMMY_PEM, "a"))
    assert is_encrypted(encrypt_secret_v2(os.urandom(32), "a"))
    assert not is_encrypted("plain text")


# ── LocalKMSProvider master-key handling ───────────────────────────────


@pytest.mark.asyncio
async def test_local_kms_generates_master_key_on_first_boot(tmp_path: Path) -> None:
    """First call creates the file with 32 random bytes and 0600 perms."""
    cert_path = tmp_path / "ca.pem"
    cert_path.write_text(
        "-----BEGIN CERTIFICATE-----\nMIIdummy\n-----END CERTIFICATE-----\n",
    )
    key_path = tmp_path / "ca-key.pem"
    key_path.write_text(_DUMMY_PEM)
    secret_key_path = tmp_path / "secret_encryption.key"

    kms = LocalKMSProvider(
        key_path=str(key_path), cert_path=str(cert_path),
        secret_encryption_key_path=str(secret_key_path),
    )
    assert not secret_key_path.exists()
    key = await kms.get_secret_encryption_key()
    assert len(key) == 32
    assert secret_key_path.exists()
    assert secret_key_path.stat().st_mode & 0o777 == 0o600
    # Subsequent calls return the same value (cached + persisted).
    assert await kms.get_secret_encryption_key() == key


@pytest.mark.asyncio
async def test_local_kms_master_key_is_independent_of_ca(tmp_path: Path) -> None:
    """Encrypting under two LocalKMS instances with the SAME CA key but
    different ``secret_encryption_key_path`` files must NOT interop —
    proves the at-rest KEK no longer derives from the CA.
    """
    cert_path = tmp_path / "ca.pem"
    cert_path.write_text(
        "-----BEGIN CERTIFICATE-----\nMIIdummy\n-----END CERTIFICATE-----\n",
    )
    key_path = tmp_path / "ca-key.pem"
    key_path.write_text(_DUMMY_PEM)
    a_master = tmp_path / "a.key"
    b_master = tmp_path / "b.key"

    kms_a = LocalKMSProvider(
        key_path=str(key_path), cert_path=str(cert_path),
        secret_encryption_key_path=str(a_master),
    )
    kms_b = LocalKMSProvider(
        key_path=str(key_path), cert_path=str(cert_path),
        secret_encryption_key_path=str(b_master),
    )
    ct = await kms_a.encrypt_secret("alpha")
    with pytest.raises(ValueError, match="Failed to decrypt"):
        await kms_b.decrypt_secret(ct)


@pytest.mark.asyncio
async def test_local_kms_legacy_v1_still_decrypts(tmp_path: Path) -> None:
    """Existing enc:v1 ciphertexts (CA-derived KEK) must keep decrypting
    after the H8 cutover so deployments don't lose access to data."""
    cert_path = tmp_path / "ca.pem"
    cert_path.write_text(
        "-----BEGIN CERTIFICATE-----\nMIIdummy\n-----END CERTIFICATE-----\n",
    )
    key_path = tmp_path / "ca-key.pem"
    key_path.write_text(_DUMMY_PEM)
    kms = LocalKMSProvider(
        key_path=str(key_path), cert_path=str(cert_path),
        secret_encryption_key_path=str(tmp_path / "se.key"),
    )
    legacy_ct = encrypt_secret(_DUMMY_PEM, "old-data")
    assert legacy_ct.startswith(_ENC_PREFIX)
    assert await kms.decrypt_secret(legacy_ct) == "old-data"


@pytest.mark.asyncio
async def test_local_kms_new_encrypts_emit_v2(tmp_path: Path) -> None:
    cert_path = tmp_path / "ca.pem"
    cert_path.write_text(
        "-----BEGIN CERTIFICATE-----\nMIIdummy\n-----END CERTIFICATE-----\n",
    )
    key_path = tmp_path / "ca-key.pem"
    key_path.write_text(_DUMMY_PEM)
    kms = LocalKMSProvider(
        key_path=str(key_path), cert_path=str(cert_path),
        secret_encryption_key_path=str(tmp_path / "se.key"),
    )
    ct = await kms.encrypt_secret("new-data")
    assert ct.startswith(_ENC_PREFIX_V2)
    assert await kms.decrypt_secret(ct) == "new-data"


@pytest.mark.asyncio
async def test_local_kms_accepts_hex_master_key(tmp_path: Path) -> None:
    """Operators commonly produce keys with `openssl rand -hex 32`. The
    provider must accept either raw 32 bytes or 64 hex chars."""
    cert_path = tmp_path / "ca.pem"
    cert_path.write_text(
        "-----BEGIN CERTIFICATE-----\nMIIdummy\n-----END CERTIFICATE-----\n",
    )
    key_path = tmp_path / "ca-key.pem"
    key_path.write_text(_DUMMY_PEM)
    secret_key_path = tmp_path / "se.key"
    raw = bytes(range(32))
    secret_key_path.write_text(raw.hex())

    kms = LocalKMSProvider(
        key_path=str(key_path), cert_path=str(cert_path),
        secret_encryption_key_path=str(secret_key_path),
    )
    loaded = await kms.get_secret_encryption_key()
    assert loaded == raw
