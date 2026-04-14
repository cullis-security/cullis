"""Tests for cullis_connector.identity.store — on-disk identity lifecycle."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cullis_connector.identity import (
    IdentityNotFound,
    generate_keypair,
    has_identity,
    load_identity,
    save_identity,
)
from cullis_connector.identity.store import (
    CA_CHAIN_FILENAME,
    CERT_FILENAME,
    KEY_FILENAME,
    METADATA_FILENAME,
    IdentityMetadata,
)


# ── Helpers ────────────────────────────────────────────────────────


def _self_signed_cert_pem(private_key) -> str:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "acme::agent-mrossi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "acme"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ── Tests ─────────────────────────────────────────────────────────


def test_has_identity_false_on_empty_dir(tmp_path: Path):
    assert has_identity(tmp_path) is False


def test_save_and_load_round_trip(tmp_path: Path):
    key = generate_keypair()
    cert_pem = _self_signed_cert_pem(key)
    metadata = IdentityMetadata(
        agent_id="acme::agent-mrossi",
        capabilities=["procurement.read"],
        site_url="https://site.test",
        issued_at="2026-04-14T12:00:00+00:00",
    )

    save_identity(
        config_dir=tmp_path,
        cert_pem=cert_pem,
        private_key=key,
        ca_chain_pem="-----CA CHAIN-----",
        metadata=metadata,
    )

    assert has_identity(tmp_path) is True
    bundle = load_identity(tmp_path)
    assert bundle.cert_pem == cert_pem
    assert bundle.ca_chain_pem == "-----CA CHAIN-----"
    assert bundle.metadata.agent_id == "acme::agent-mrossi"
    assert bundle.metadata.capabilities == ["procurement.read"]
    # Keypair round-trip: loaded key should match the saved one.
    assert bundle.private_key.public_key().public_numbers() == (
        key.public_key().public_numbers()
    )


def test_save_sets_private_key_mode_to_600(tmp_path: Path):
    if os.name != "posix":
        pytest.skip("POSIX-only permission check")
    key = generate_keypair()
    save_identity(
        config_dir=tmp_path,
        cert_pem=_self_signed_cert_pem(key),
        private_key=key,
        ca_chain_pem=None,
        metadata=IdentityMetadata(
            agent_id="x", capabilities=[], site_url="", issued_at=""
        ),
    )
    key_path = tmp_path / "identity" / KEY_FILENAME
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


def test_load_missing_identity_raises(tmp_path: Path):
    with pytest.raises(IdentityNotFound):
        load_identity(tmp_path)


def test_save_overwrites_stale_ca_chain(tmp_path: Path):
    key = generate_keypair()
    cert_pem = _self_signed_cert_pem(key)
    metadata = IdentityMetadata(
        agent_id="x", capabilities=[], site_url="", issued_at=""
    )

    save_identity(
        config_dir=tmp_path,
        cert_pem=cert_pem,
        private_key=key,
        ca_chain_pem="chain-v1",
        metadata=metadata,
    )
    assert (tmp_path / "identity" / CA_CHAIN_FILENAME).exists()

    # Second save without chain must delete the stale file.
    save_identity(
        config_dir=tmp_path,
        cert_pem=cert_pem,
        private_key=key,
        ca_chain_pem=None,
        metadata=metadata,
    )
    assert not (tmp_path / "identity" / CA_CHAIN_FILENAME).exists()


def test_load_fixes_loose_key_permissions(tmp_path: Path):
    if os.name != "posix":
        pytest.skip("POSIX-only permission check")
    key = generate_keypair()
    save_identity(
        config_dir=tmp_path,
        cert_pem=_self_signed_cert_pem(key),
        private_key=key,
        ca_chain_pem=None,
        metadata=IdentityMetadata(
            agent_id="x", capabilities=[], site_url="", issued_at=""
        ),
    )
    key_path = tmp_path / "identity" / KEY_FILENAME
    os.chmod(key_path, 0o644)  # simulate accidental permission loosening

    load_identity(tmp_path)
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_metadata_json_is_pretty_printed(tmp_path: Path):
    key = generate_keypair()
    metadata = IdentityMetadata(
        agent_id="acme::bot",
        capabilities=["a", "b"],
        site_url="https://s",
        issued_at="now",
    )
    save_identity(
        config_dir=tmp_path,
        cert_pem=_self_signed_cert_pem(key),
        private_key=key,
        ca_chain_pem=None,
        metadata=metadata,
    )
    raw = (tmp_path / "identity" / METADATA_FILENAME).read_text()
    parsed = json.loads(raw)
    assert parsed["agent_id"] == "acme::bot"
    assert parsed["capabilities"] == ["a", "b"]
    # Pretty printed → newlines present.
    assert "\n" in raw


def test_load_without_metadata_falls_back_to_cert_cn(tmp_path: Path):
    key = generate_keypair()
    (tmp_path / "identity").mkdir(parents=True)
    (tmp_path / "identity" / CERT_FILENAME).write_text(_self_signed_cert_pem(key))
    key_path = tmp_path / "identity" / KEY_FILENAME
    from cryptography.hazmat.primitives import serialization

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    if os.name == "posix":
        os.chmod(key_path, 0o600)

    bundle = load_identity(tmp_path)
    assert bundle.metadata.agent_id == "acme::agent-mrossi"
