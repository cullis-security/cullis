"""Tests for the embedded UserPrincipalKMS backend.

Pure unit coverage of ``app/kms/user_principal_embedded.py`` — does
not touch the broker app or the SQLAlchemy fixtures from conftest.
"""
from __future__ import annotations

import os
import sqlite3

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.kms.user_principal import (
    ALG_ES256,
    CertificateNotAttachedError,
    PrincipalAlreadyExistsError,
    PrincipalNotFoundError,
    PrincipalRevokedError,
    ProvisioningResult,
    UserPrincipalKMS,
)
from app.kms.user_principal_embedded import (
    ENV_MASTER_KEY,
    EmbeddedUserPrincipalKMS,
)


# 32 bytes of test entropy — fixed for determinism across runs.
TEST_MASTER_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff" "00112233445566778899aabbccddeeff"
)


# ── helpers ────────────────────────────────────────────────────────


def _make_kms(tmp_path) -> EmbeddedUserPrincipalKMS:
    return EmbeddedUserPrincipalKMS(
        db_path=tmp_path / "user_principals.db",
        master_key=TEST_MASTER_KEY,
    )


def _verify_es256(public_pem: str, payload: bytes, signature: bytes) -> None:
    """Verify an ES256 signature; raises if invalid."""
    pub = serialization.load_pem_public_key(public_pem.encode())
    pub.verify(signature, payload, ec.ECDSA(hashes.SHA256()))


# ── master key handling (3 tests) ─────────────────────────────────


def test_constructor_without_env_raises(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_MASTER_KEY, raising=False)
    with pytest.raises(RuntimeError, match=ENV_MASTER_KEY):
        EmbeddedUserPrincipalKMS(db_path=tmp_path / "x.db")


def test_constructor_master_key_wrong_length_raises(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_MASTER_KEY, "abcd")  # 2 bytes
    with pytest.raises(RuntimeError, match="32 bytes"):
        EmbeddedUserPrincipalKMS(db_path=tmp_path / "x.db")


def test_constructor_master_key_non_hex_raises(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_MASTER_KEY, "z" * 64)
    with pytest.raises(RuntimeError, match="hex"):
        EmbeddedUserPrincipalKMS(db_path=tmp_path / "x.db")


def test_explicit_master_key_bypasses_env(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_MASTER_KEY, raising=False)
    # No env var, but explicit master_key works fine.
    kms = EmbeddedUserPrincipalKMS(
        db_path=tmp_path / "x.db", master_key=TEST_MASTER_KEY,
    )
    assert kms is not None


def test_explicit_master_key_wrong_length_raises(tmp_path):
    with pytest.raises(ValueError, match="32 bytes"):
        EmbeddedUserPrincipalKMS(
            db_path=tmp_path / "x.db", master_key=b"\x00" * 16,
        )


# ── Protocol satisfaction (1 test) ─────────────────────────────────


def test_implements_protocol(tmp_path):
    kms = _make_kms(tmp_path)
    # runtime_checkable Protocol — isinstance check verifies the
    # concrete class exposes every method.
    assert isinstance(kms, UserPrincipalKMS)


# ── has_principal (2 tests) ────────────────────────────────────────


@pytest.mark.asyncio
async def test_has_principal_false_for_unknown(tmp_path):
    kms = _make_kms(tmp_path)
    assert await kms.has_principal("acme.test/acme/user/mario") is False


@pytest.mark.asyncio
async def test_has_principal_true_after_create(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    assert await kms.has_principal("acme.test/acme/user/mario") is True


# ── create_keypair (4 tests) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_create_keypair_returns_provisioning_result(tmp_path):
    kms = _make_kms(tmp_path)
    res = await kms.create_keypair("acme.test/acme/user/mario")
    assert isinstance(res, ProvisioningResult)
    assert res.alg == ALG_ES256
    assert res.key_handle == "embedded:acme.test/acme/user/mario"
    assert "BEGIN PUBLIC KEY" in res.public_key_pem


@pytest.mark.asyncio
async def test_create_keypair_twice_raises(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    with pytest.raises(PrincipalAlreadyExistsError):
        await kms.create_keypair("acme.test/acme/user/mario")


@pytest.mark.asyncio
async def test_create_keypair_unsupported_alg_raises(tmp_path):
    kms = _make_kms(tmp_path)
    with pytest.raises(ValueError, match="not supported"):
        await kms.create_keypair("acme.test/acme/user/mario", alg="HS256")


@pytest.mark.asyncio
async def test_create_keypair_after_revoke_still_blocked(tmp_path):
    """Re-provisioning a revoked principal still raises — caller must
    delete + recreate via a different principal_id, or implement
    explicit reset semantics in a higher layer.
    """
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    await kms.revoke_principal("acme.test/acme/user/mario")
    with pytest.raises(PrincipalAlreadyExistsError):
        await kms.create_keypair("acme.test/acme/user/mario")


# ── attach_certificate (4 tests) ───────────────────────────────────


@pytest.mark.asyncio
async def test_attach_certificate_happy_path(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    pem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
    await kms.attach_certificate("acme.test/acme/user/mario", pem)
    assert await kms.get_certificate("acme.test/acme/user/mario") == pem


@pytest.mark.asyncio
async def test_attach_certificate_unknown_principal_raises(tmp_path):
    kms = _make_kms(tmp_path)
    with pytest.raises(PrincipalNotFoundError):
        await kms.attach_certificate(
            "acme.test/acme/user/ghost",
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        )


@pytest.mark.asyncio
async def test_attach_certificate_replaces_old(tmp_path):
    """Cert rotation is a normal operation; reattach overwrites."""
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    old = "-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n"
    new = "-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n"
    await kms.attach_certificate("acme.test/acme/user/mario", old)
    await kms.attach_certificate("acme.test/acme/user/mario", new)
    assert await kms.get_certificate("acme.test/acme/user/mario") == new


@pytest.mark.asyncio
async def test_attach_certificate_empty_raises(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    with pytest.raises(ValueError, match="non-empty"):
        await kms.attach_certificate("acme.test/acme/user/mario", "   ")


# ── get_certificate (3 tests) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_get_certificate_unknown_principal_raises(tmp_path):
    kms = _make_kms(tmp_path)
    with pytest.raises(PrincipalNotFoundError):
        await kms.get_certificate("acme.test/acme/user/ghost")


@pytest.mark.asyncio
async def test_get_certificate_before_attach_raises(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    with pytest.raises(CertificateNotAttachedError):
        await kms.get_certificate("acme.test/acme/user/mario")


@pytest.mark.asyncio
async def test_get_certificate_after_attach(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    pem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
    await kms.attach_certificate("acme.test/acme/user/mario", pem)
    assert await kms.get_certificate("acme.test/acme/user/mario") == pem


# ── sign (5 tests) ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sign_produces_verifiable_signature(tmp_path):
    kms = _make_kms(tmp_path)
    res = await kms.create_keypair("acme.test/acme/user/mario")
    payload = b"the quick brown fox"
    sig = await kms.sign("acme.test/acme/user/mario", payload)
    assert isinstance(sig, bytes)
    # ECDSA DER signatures are 70-72 bytes typically; just sanity-check.
    assert 64 <= len(sig) <= 80
    # Decoding the DER does not raise → it's a well-formed signature.
    decode_dss_signature(sig)
    # And the signature verifies under the returned public key.
    _verify_es256(res.public_key_pem, payload, sig)


@pytest.mark.asyncio
async def test_sign_unknown_principal_raises(tmp_path):
    kms = _make_kms(tmp_path)
    with pytest.raises(PrincipalNotFoundError):
        await kms.sign("acme.test/acme/user/ghost", b"payload")


@pytest.mark.asyncio
async def test_sign_after_revoke_raises(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    await kms.revoke_principal("acme.test/acme/user/mario")
    with pytest.raises(PrincipalRevokedError):
        await kms.sign("acme.test/acme/user/mario", b"payload")


@pytest.mark.asyncio
async def test_sign_str_payload_raises(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    with pytest.raises(TypeError):
        await kms.sign("acme.test/acme/user/mario", "string-not-bytes")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_sign_two_principals_independent(tmp_path):
    kms = _make_kms(tmp_path)
    res_m = await kms.create_keypair("acme.test/acme/user/mario")
    res_a = await kms.create_keypair("acme.test/acme/user/anna")
    payload = b"shared payload"
    sig_m = await kms.sign("acme.test/acme/user/mario", payload)
    sig_a = await kms.sign("acme.test/acme/user/anna", payload)
    # Each signature verifies only under its own public key.
    _verify_es256(res_m.public_key_pem, payload, sig_m)
    _verify_es256(res_a.public_key_pem, payload, sig_a)
    with pytest.raises(Exception):  # InvalidSignature
        _verify_es256(res_m.public_key_pem, payload, sig_a)


# ── revoke_principal (3 tests) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_revoke_unknown_principal_raises(tmp_path):
    kms = _make_kms(tmp_path)
    with pytest.raises(PrincipalNotFoundError):
        await kms.revoke_principal("acme.test/acme/user/ghost")


@pytest.mark.asyncio
async def test_revoke_idempotent(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    await kms.revoke_principal("acme.test/acme/user/mario")
    # Second call must not raise.
    await kms.revoke_principal("acme.test/acme/user/mario")


@pytest.mark.asyncio
async def test_revoke_one_does_not_affect_other(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    await kms.create_keypair("acme.test/acme/user/anna")
    await kms.revoke_principal("acme.test/acme/user/mario")
    # Anna can still sign.
    sig = await kms.sign("acme.test/acme/user/anna", b"payload")
    assert isinstance(sig, bytes)
    # Mario cannot.
    with pytest.raises(PrincipalRevokedError):
        await kms.sign("acme.test/acme/user/mario", b"payload")


# ── principal_id validation (3 tests) ──────────────────────────────


@pytest.mark.asyncio
async def test_principal_id_empty_raises(tmp_path):
    kms = _make_kms(tmp_path)
    with pytest.raises(ValueError, match="non-empty"):
        await kms.has_principal("")


@pytest.mark.asyncio
async def test_principal_id_too_long_raises(tmp_path):
    kms = _make_kms(tmp_path)
    too_long = "a" * 256
    with pytest.raises(ValueError, match="exceeds"):
        await kms.has_principal(too_long)


@pytest.mark.asyncio
async def test_principal_id_non_ascii_raises(tmp_path):
    kms = _make_kms(tmp_path)
    with pytest.raises(ValueError, match="ASCII"):
        await kms.has_principal("acme.test/acme/user/mariò")


# ── encryption properties (3 tests) ────────────────────────────────


@pytest.mark.asyncio
async def test_stored_blob_is_not_plaintext(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    # Open the SQLite directly and check the stored blob does not
    # contain the unencrypted PKCS8 marker.
    with sqlite3.connect(tmp_path / "user_principals.db") as conn:
        row = conn.execute(
            "SELECT encrypted_private_key FROM user_principals_keys "
            "WHERE principal_id = ?",
            ("acme.test/acme/user/mario",),
        ).fetchone()
    blob = row[0]
    assert b"BEGIN PRIVATE KEY" not in blob
    assert b"PRIVATE KEY" not in blob


@pytest.mark.asyncio
async def test_two_principals_have_different_nonces(tmp_path):
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    await kms.create_keypair("acme.test/acme/user/anna")
    with sqlite3.connect(tmp_path / "user_principals.db") as conn:
        rows = conn.execute(
            "SELECT principal_id, encrypted_private_key "
            "FROM user_principals_keys",
        ).fetchall()
    assert len(rows) == 2
    nonces = [blob[:12] for _, blob in rows]
    assert nonces[0] != nonces[1]


@pytest.mark.asyncio
async def test_aad_binding_prevents_cross_principal_replay(tmp_path):
    """AAD binds the ciphertext to its principal_id. Swapping the
    blob between two principals must fail to decrypt.
    """
    kms = _make_kms(tmp_path)
    await kms.create_keypair("acme.test/acme/user/mario")
    await kms.create_keypair("acme.test/acme/user/anna")
    # Swap the encrypted_private_key blobs.
    db = tmp_path / "user_principals.db"
    with sqlite3.connect(db) as conn:
        m_row = conn.execute(
            "SELECT encrypted_private_key FROM user_principals_keys "
            "WHERE principal_id = ?",
            ("acme.test/acme/user/mario",),
        ).fetchone()
        a_row = conn.execute(
            "SELECT encrypted_private_key FROM user_principals_keys "
            "WHERE principal_id = ?",
            ("acme.test/acme/user/anna",),
        ).fetchone()
        conn.execute(
            "UPDATE user_principals_keys SET encrypted_private_key = ? "
            "WHERE principal_id = ?",
            (a_row[0], "acme.test/acme/user/mario"),
        )
        conn.execute(
            "UPDATE user_principals_keys SET encrypted_private_key = ? "
            "WHERE principal_id = ?",
            (m_row[0], "acme.test/acme/user/anna"),
        )
    # Sign attempts must now raise InvalidTag (or its parent
    # cryptography.exceptions.InvalidTag) — surfaces as Exception
    # because we don't translate it.
    with pytest.raises(Exception):
        await kms.sign("acme.test/acme/user/mario", b"x")


# ── persistence + perms (2 tests) ──────────────────────────────────


@pytest.mark.asyncio
async def test_persistence_across_instances(tmp_path):
    """A second EmbeddedKMS instance pointed at the same DB sees prior
    state and can sign with the existing keypair."""
    kms1 = _make_kms(tmp_path)
    res = await kms1.create_keypair("acme.test/acme/user/mario")
    payload = b"persisted"
    # Drop the first instance, open a new one.
    del kms1
    kms2 = _make_kms(tmp_path)
    assert await kms2.has_principal("acme.test/acme/user/mario") is True
    sig = await kms2.sign("acme.test/acme/user/mario", payload)
    _verify_es256(res.public_key_pem, payload, sig)


def test_db_file_has_tight_perms(tmp_path):
    db_path = tmp_path / "user_principals.db"
    EmbeddedUserPrincipalKMS(db_path=db_path, master_key=TEST_MASTER_KEY)
    mode = os.stat(db_path).st_mode & 0o777
    # Owner-only by default.
    assert mode == 0o600


# ── schema idempotency (1 test) ────────────────────────────────────


def test_schema_idempotent_on_reinit(tmp_path):
    db_path = tmp_path / "user_principals.db"
    # Two instances pointing at the same DB must coexist without
    # raising "table already exists".
    EmbeddedUserPrincipalKMS(db_path=db_path, master_key=TEST_MASTER_KEY)
    EmbeddedUserPrincipalKMS(db_path=db_path, master_key=TEST_MASTER_KEY)
