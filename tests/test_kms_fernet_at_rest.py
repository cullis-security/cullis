"""Contract tests for the PKI at-rest Fernet envelope.

Three-tier PKI hardening (audit 2026-05-18). Verifies:

* PBKDF2 derivation from ``MCP_PROXY_DB_ENCRYPTION_KEY`` produces a
  deterministic Fernet key for a given passphrase.
* :func:`encrypt_pki_payload` + :func:`decrypt_pki_payload` round-trip
  cleanly.
* A row encrypted under one passphrase fails loudly when decrypted
  under a different passphrase (no plaintext fallback).
* :func:`pki_master_key_configured` returns False when the env var is
  empty (validate_config gate input).
* The ``LocalKMSProvider`` lands key material in ``pki_key_store``
  under the envelope, not as plaintext PEM in ``proxy_config``.
"""
from __future__ import annotations

import pytest

from mcp_proxy import db as core_db
from mcp_proxy.kms.factory import reset_kms_provider
from mcp_proxy.kms.pki_at_rest import (
    PKIKeyMissingError,
    _reset_cache_for_tests,
    decrypt_pki_payload,
    derive_master_key,
    encrypt_pki_payload,
    pki_master_key_configured,
)


@pytest.fixture(autouse=True)
async def _fresh_state(monkeypatch, tmp_path):
    reset_kms_provider()
    _reset_cache_for_tests()
    db_file = tmp_path / "fernet_at_rest.sqlite"
    db_url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "local")
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", db_url)
    # File-backed SQLite so the Alembic migrations and runtime queries
    # share a persistent DB (in-memory ``:memory:`` resets per connection).
    monkeypatch.setenv("PROXY_SKIP_MIGRATIONS", "0")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await core_db.init_db(db_url)
    yield
    await core_db.dispose_db()
    reset_kms_provider()
    _reset_cache_for_tests()
    get_settings.cache_clear()


async def test_master_key_missing_raises_clearly(monkeypatch):
    monkeypatch.delenv("MCP_PROXY_DB_ENCRYPTION_KEY", raising=False)
    _reset_cache_for_tests()
    assert pki_master_key_configured() is False
    with pytest.raises(PKIKeyMissingError, match="MCP_PROXY_DB_ENCRYPTION_KEY"):
        derive_master_key()


async def test_master_key_too_short_raises(monkeypatch):
    monkeypatch.setenv("MCP_PROXY_DB_ENCRYPTION_KEY", "short")
    _reset_cache_for_tests()
    with pytest.raises(PKIKeyMissingError, match="at least 16"):
        derive_master_key()


async def test_round_trip_with_valid_passphrase(monkeypatch):
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "test-passphrase-32-chars-minimum-for-pbkdf2",
    )
    _reset_cache_for_tests()
    key_pem = "-----BEGIN PRIVATE KEY-----\nfake-key-pem-body\n-----END PRIVATE KEY-----"
    cert_pem = "-----BEGIN CERTIFICATE-----\nfake-cert-pem-body\n-----END CERTIFICATE-----"
    envelope = encrypt_pki_payload(key_pem=key_pem, cert_pem=cert_pem)
    assert envelope.startswith("enc:pki:v1:")
    # No plaintext leak through the envelope.
    assert "fake-key-pem-body" not in envelope
    assert "fake-cert-pem-body" not in envelope

    out_key, out_cert = decrypt_pki_payload(envelope)
    assert out_key == key_pem
    assert out_cert == cert_pem


async def test_wrong_passphrase_fails_loud(monkeypatch):
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "first-passphrase-32-chars-minimum-for-test",
    )
    _reset_cache_for_tests()
    envelope = encrypt_pki_payload(
        key_pem="K", cert_pem="C",
    )
    # Rotate passphrase without re-encrypting.
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "different-passphrase-32-chars-minimum-x",
    )
    _reset_cache_for_tests()
    with pytest.raises(RuntimeError, match="cannot be decrypted"):
        decrypt_pki_payload(envelope)


async def test_envelope_prefix_required(monkeypatch):
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "test-passphrase-32-chars-minimum-for-pbkdf2",
    )
    _reset_cache_for_tests()
    # Plaintext blob — no enc:pki:v1: prefix.
    with pytest.raises(ValueError, match="does not start with"):
        decrypt_pki_payload("not-an-envelope")


def _mint_fake_ca() -> tuple[str, str, str]:
    """Mint a real EC P-256 self-signed cert so LocalKMSProvider can
    parse it for key_id derivation. Returns ``(key_pem, cert_pem, marker)``
    where ``marker`` is a substring of the private key PEM useful for
    asserting absence in the encrypted ciphertext.
    """
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    # Marker is a non-base64 string we sprinkle into a comment-bearing
    # variant of the key PEM so we can assert plaintext is absent.
    # Fernet-wrap whatever we hand it, but we must hand it parseable
    # PEMs so the key_id derivation works. Just check the actual key
    # body bytes are absent from the ciphertext.
    return key_pem, cert_pem, key_pem.split("\n")[1][:40]


async def test_local_kms_lands_encrypted_in_pki_key_store(monkeypatch):
    """LocalKMSProvider.store_org_ca writes a Fernet-wrapped row, not plaintext."""
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "kms-provider-test-32-chars-minimum-passphrase",
    )
    _reset_cache_for_tests()

    from mcp_proxy.kms.local import LocalKMSProvider

    provider = LocalKMSProvider()
    key_pem, cert_pem, marker = _mint_fake_ca()
    await provider.store_org_ca(key_pem, cert_pem)

    # Read back via the provider: should round-trip cleanly.
    loaded = await provider.load_org_ca()
    assert loaded is not None
    out_key, out_cert = loaded
    assert out_key == key_pem
    assert out_cert == cert_pem

    # And read the raw row via the DB helper: ciphertext must NOT
    # contain the plaintext PEM body.
    from mcp_proxy.db import get_active_pki_key

    row = await get_active_pki_key("org_ca")
    assert row is not None
    assert marker not in row["ciphertext"]
    assert row["ciphertext"].startswith("enc:pki:v1:")
    # Cert PEM is duplicated unencrypted for verification-only path.
    assert row["cert_pem"] == cert_pem


async def test_local_kms_intermediate_routes_through_provider(monkeypatch):
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "intermediate-test-32-chars-minimum-passphrase",
    )
    _reset_cache_for_tests()

    from mcp_proxy.kms.local import LocalKMSProvider

    provider = LocalKMSProvider()
    int_key, int_cert, marker = _mint_fake_ca()
    await provider.store_intermediate_ca(int_key, int_cert)

    loaded = await provider.load_intermediate_ca()
    assert loaded == (int_key, int_cert)

    from mcp_proxy.db import get_active_pki_key

    row = await get_active_pki_key("intermediate_ca")
    assert row is not None
    assert marker not in row["ciphertext"]
    assert row["ciphertext"].startswith("enc:pki:v1:")
