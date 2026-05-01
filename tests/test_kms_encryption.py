"""
Tests for KMS secret encryption (OIDC client secret at-rest encryption).
"""
import pytest

from app.kms.secret_encrypt import (
    encrypt_secret,
    decrypt_secret,
    is_encrypted,
    _ENC_PREFIX,
    _ENC_PREFIX_V2,
)

# Use a deterministic "fake" PEM for testing — only the bytes matter for HKDF
_TEST_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIItest1234567890abcdef\n-----END RSA PRIVATE KEY-----\n"
_OTHER_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIdifferentkey9999999\n-----END RSA PRIVATE KEY-----\n"


def test_encrypt_decrypt_roundtrip():
    """Encrypt then decrypt returns the original plaintext."""
    plaintext = "super-secret-oidc-client-secret"
    encrypted = encrypt_secret(_TEST_KEY_PEM, plaintext)
    assert encrypted.startswith(_ENC_PREFIX)
    assert plaintext not in encrypted
    decrypted = decrypt_secret(_TEST_KEY_PEM, encrypted)
    assert decrypted == plaintext


def test_encrypted_has_prefix():
    """Encrypted values carry the enc:v1: prefix."""
    encrypted = encrypt_secret(_TEST_KEY_PEM, "test")
    assert encrypted.startswith("enc:v1:")
    assert is_encrypted(encrypted)


def test_legacy_plaintext_passthrough():
    """Plaintext values without the prefix are returned as-is (transparent migration)."""
    legacy = "plain-text-secret-from-old-version"
    assert decrypt_secret(_TEST_KEY_PEM, legacy) == legacy
    assert not is_encrypted(legacy)


def test_wrong_key_fails():
    """Decryption with a different key raises ValueError."""
    encrypted = encrypt_secret(_TEST_KEY_PEM, "secret")
    with pytest.raises(ValueError, match="Failed to decrypt"):
        decrypt_secret(_OTHER_KEY_PEM, encrypted)


def test_corrupted_ciphertext_fails():
    """Corrupted ciphertext raises ValueError."""
    corrupted = f"{_ENC_PREFIX}not-a-valid-fernet-token"
    with pytest.raises(ValueError, match="Failed to decrypt"):
        decrypt_secret(_TEST_KEY_PEM, corrupted)


def test_empty_string_passthrough():
    """Empty string is not encrypted (treated as legacy plaintext)."""
    assert decrypt_secret(_TEST_KEY_PEM, "") == ""
    assert not is_encrypted("")


def test_encrypt_different_values_produce_different_ciphertexts():
    """Different plaintexts produce different ciphertexts."""
    a = encrypt_secret(_TEST_KEY_PEM, "alpha")
    b = encrypt_secret(_TEST_KEY_PEM, "beta")
    assert a != b


def test_encrypt_same_value_produces_different_ciphertexts():
    """Same plaintext encrypted twice produces different ciphertexts (Fernet uses random IV)."""
    a = encrypt_secret(_TEST_KEY_PEM, "same")
    b = encrypt_secret(_TEST_KEY_PEM, "same")
    assert a != b
    # But both decrypt to the same value
    assert decrypt_secret(_TEST_KEY_PEM, a) == "same"
    assert decrypt_secret(_TEST_KEY_PEM, b) == "same"


@pytest.mark.asyncio
async def test_kms_provider_encrypt_decrypt(client):
    """KMS provider encrypt/decrypt methods work end-to-end. H8: v2 prefix."""
    from app.kms.factory import get_kms_provider
    kms = get_kms_provider()
    plaintext = "oidc-client-secret-via-kms"
    encrypted = await kms.encrypt_secret(plaintext)
    # H8 audit: providers always emit enc:v2 (master-key derived) for
    # new ciphertexts. Decrypt still tolerates legacy enc:v1 from
    # pre-cutover data.
    assert encrypted.startswith(_ENC_PREFIX_V2)
    decrypted = await kms.decrypt_secret(encrypted)
    assert decrypted == plaintext


@pytest.mark.asyncio
async def test_kms_provider_legacy_passthrough(client):
    """KMS provider decrypt returns legacy plaintext as-is."""
    from app.kms.factory import get_kms_provider
    kms = get_kms_provider()
    legacy = "old-plain-secret"
    assert await kms.decrypt_secret(legacy) == legacy
