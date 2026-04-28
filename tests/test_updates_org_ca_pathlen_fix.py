"""Tests for the first concrete federation update migration.

Covers :class:`OrgCAPathLenFix` end-to-end:

- ``check()`` returns True/False for every interesting state (pathLen,
  intermediate presence, Org CA key presence).
- ``up()`` preserves agent pubkeys, preserves validity, produces a
  chain that ``Certificate.verify_directly_issued_by`` accepts (the
  exact verifier that failed on the #280 legacy chain).
- ``up()`` is idempotent on a no-op state, refuses to rotate an
  expired CA, and writes a backup row.
- ``rollback()`` restores the pre-rotation state and raises when no
  backup exists.

Each test builds its own legacy / current state via fixtures, so the
entire Alembic chain runs (0001 → 0020) against a throwaway SQLite file.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import text

from mcp_proxy.db import (
    dispose_db,
    get_config,
    get_db,
    get_migration_backup,
    init_db,
    set_config,
)
from mcp_proxy.updates.migrations.org_ca_pathlen_1_20260423 import (
    OrgCAPathLenFix,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def fresh_db(tmp_path, monkeypatch):
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    await init_db(url)
    try:
        yield url
    finally:
        await dispose_db()


def _build_legacy_org_ca(
    *,
    path_length: int = 0,
    not_after_delta_days: int = 3650,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Build an Org CA matching the pre-#284 broken shape.

    Default ``path_length=0`` reproduces the bug. ``not_after_delta_days``
    is the offset from now; negative values produce an already-expired
    CA for the expiry-guard test (``not_valid_before`` is adjusted
    backwards so the builder's
    ``not_valid_before <= not_valid_after`` invariant holds).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-org CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "test-org"),
    ])
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=not_after_delta_days)
    # Place ``not_valid_before`` a year before ``not_valid_after`` so the
    # builder accepts even expired fixtures (expired-CA test case).
    not_before = not_after - timedelta(days=365)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_length),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _build_intermediate_ca(
    *, org_ca_cert: x509.Certificate, org_ca_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    """Build a Mastio-style intermediate CA under the Org CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mastio intermediate"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "test-org"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(org_ca_key, hashes.SHA256())
    )
    return cert


def _build_leaf(
    *,
    org_ca_cert: x509.Certificate,
    org_ca_key: rsa.RSAPrivateKey,
    agent_id: str,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "test-org"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(
                    f"spiffe://test-org/{agent_id}"
                ),
            ]),
            critical=False,
        )
        .sign(org_ca_key, hashes.SHA256())
    )
    return cert, key


async def _seed_legacy_state(
    *,
    path_length: int = 0,
    with_intermediate: bool = True,
    with_ca_key: bool = True,
    not_after_delta_days: int = 3650,
    agent_ids: tuple[str, ...] = ("alpha", "beta"),
) -> dict:
    """Populate proxy_config + internal_agents to mimic a pre-#284 proxy.

    Returns a dict with the cryptographic material the test may want to
    compare against after ``up()``.
    """
    ca_cert, ca_key = _build_legacy_org_ca(
        path_length=path_length,
        not_after_delta_days=not_after_delta_days,
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    ca_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    await set_config("org_ca_cert", ca_cert_pem)
    if with_ca_key:
        await set_config("org_ca_key", ca_key_pem)

    if with_intermediate:
        intermediate = _build_intermediate_ca(
            org_ca_cert=ca_cert, org_ca_key=ca_key,
        )
        await set_config(
            "mastio_ca_cert",
            intermediate.public_bytes(serialization.Encoding.PEM).decode(),
        )

    leaves: dict[str, x509.Certificate] = {}
    async with get_db() as conn:
        for aid in agent_ids:
            leaf_cert, _ = _build_leaf(
                org_ca_cert=ca_cert, org_ca_key=ca_key, agent_id=aid,
            )
            leaf_pem = leaf_cert.public_bytes(
                serialization.Encoding.PEM,
            ).decode()
            leaves[aid] = leaf_cert
            await conn.execute(
                text(
                    "INSERT INTO internal_agents "
                    "(agent_id, display_name, capabilities, "
                    " cert_pem, created_at, is_active, enrollment_method) "
                    "VALUES "
                    "(:aid, :name, '[]', :cert, "
                    " '2026-04-23T00:00:00+00:00', 1, 'connector')"
                ),
                {
                    "aid": aid,
                    "name": f"agent {aid}",
                    "cert": leaf_pem,
                },
            )

    return {
        "ca_cert": ca_cert,
        "ca_key": ca_key,
        "leaves": leaves,
    }


# ── check() branches ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_check_true_when_pathlen_zero_with_intermediate(fresh_db):
    await _seed_legacy_state(path_length=0, with_intermediate=True)
    assert await OrgCAPathLenFix().check() is True


@pytest.mark.asyncio
async def test_check_false_when_pathlen_one(fresh_db):
    # Post-#284 fresh install — CA has pathLen=1, no auto-migration.
    await _seed_legacy_state(path_length=1, with_intermediate=True)
    assert await OrgCAPathLenFix().check() is False


@pytest.mark.asyncio
async def test_check_false_when_no_intermediate(fresh_db):
    # pathLen=0 without an intermediate is a valid 2-tier deploy,
    # no chain violation to repair.
    await _seed_legacy_state(path_length=0, with_intermediate=False)
    assert await OrgCAPathLenFix().check() is False


@pytest.mark.asyncio
async def test_check_false_when_no_org_ca_loaded(fresh_db):
    # Fresh proxy (or attached-CA-pre-consume) — no Org CA cert yet.
    assert await OrgCAPathLenFix().check() is False


@pytest.mark.asyncio
async def test_check_false_when_org_ca_key_missing(fresh_db):
    # BYOCA with secret-manager-held privkey — not auto-migrable.
    await _seed_legacy_state(
        path_length=0, with_intermediate=True, with_ca_key=False,
    )
    assert await OrgCAPathLenFix().check() is False


# ── up() ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_up_rotates_ca_to_pathlen_one(fresh_db):
    await _seed_legacy_state(path_length=0, with_intermediate=True)
    await OrgCAPathLenFix().up()

    new_ca_pem = await get_config("org_ca_cert")
    new_ca = x509.load_pem_x509_certificate(new_ca_pem.encode())
    bc = new_ca.extensions.get_extension_for_class(
        x509.BasicConstraints,
    ).value
    assert bc.ca is True
    assert bc.path_length == 1


@pytest.mark.asyncio
async def test_up_preserves_agent_pubkeys(fresh_db):
    seeded = await _seed_legacy_state(
        path_length=0, with_intermediate=True,
        agent_ids=("alpha", "beta", "gamma"),
    )
    old_pubkeys = {
        aid: leaf.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        for aid, leaf in seeded["leaves"].items()
    }

    await OrgCAPathLenFix().up()

    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT agent_id, cert_pem FROM internal_agents "
                "WHERE is_active = 1"
            )
        )
        rows = {row["agent_id"]: row["cert_pem"] for row in result.mappings()}

    assert set(rows) == set(old_pubkeys)
    for aid, new_pem in rows.items():
        new_leaf = x509.load_pem_x509_certificate(new_pem.encode())
        new_pub_der = new_leaf.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert new_pub_der == old_pubkeys[aid], (
            f"pubkey changed for {aid} — migration broke preservation"
        )


@pytest.mark.asyncio
async def test_up_preserves_agent_validity(fresh_db):
    seeded = await _seed_legacy_state(path_length=0, with_intermediate=True)
    old_validity = {
        aid: (leaf.not_valid_before_utc, leaf.not_valid_after_utc)
        for aid, leaf in seeded["leaves"].items()
    }

    await OrgCAPathLenFix().up()

    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT agent_id, cert_pem FROM internal_agents")
        )
        rows = {row["agent_id"]: row["cert_pem"] for row in result.mappings()}

    for aid, new_pem in rows.items():
        new_leaf = x509.load_pem_x509_certificate(new_pem.encode())
        assert new_leaf.not_valid_before_utc == old_validity[aid][0]
        assert new_leaf.not_valid_after_utc == old_validity[aid][1]


@pytest.mark.asyncio
async def test_up_chain_verifies_with_stdlib(fresh_db):
    """Post-migration, each leaf is directly issued by the new Org CA.

    Uses ``Certificate.verify_directly_issued_by`` — the exact
    cryptography-lib verifier that rejected the pre-#284 chain in the
    original bug #280 reproducer.
    """
    await _seed_legacy_state(path_length=0, with_intermediate=True)
    await OrgCAPathLenFix().up()

    new_ca = x509.load_pem_x509_certificate(
        (await get_config("org_ca_cert")).encode(),
    )

    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT cert_pem FROM internal_agents")
        )
        leaves = [
            x509.load_pem_x509_certificate(row["cert_pem"].encode())
            for row in result.mappings()
        ]

    for leaf in leaves:
        # Raises on verification failure; stateless assertion.
        leaf.verify_directly_issued_by(new_ca)


@pytest.mark.asyncio
async def test_up_idempotent_on_already_fixed_state(fresh_db):
    # First apply: rotates.
    await _seed_legacy_state(path_length=0, with_intermediate=True)
    await OrgCAPathLenFix().up()

    after_first = await get_config("org_ca_cert")

    # Second apply: check() returns False (pathLen=1 now), up() no-ops.
    await OrgCAPathLenFix().up()

    after_second = await get_config("org_ca_cert")
    assert after_first == after_second


@pytest.mark.asyncio
async def test_up_refuses_expired_ca(fresh_db):
    # notAfter in the past by a minute → guard must fire.
    await _seed_legacy_state(
        path_length=0, with_intermediate=True,
        not_after_delta_days=-1,  # 1 day in the past — comfortably expired
    )
    # ``check()`` might still return True (pathLen==0 doesn't know about
    # expiry), but ``up()`` must refuse.
    with pytest.raises(RuntimeError, match="expired Org CA"):
        await OrgCAPathLenFix().up()


@pytest.mark.asyncio
async def test_up_accepts_near_expiry_ca(fresh_db):
    # notAfter in the future — no guard, rotation proceeds.
    await _seed_legacy_state(
        path_length=0, with_intermediate=True,
        not_after_delta_days=1,  # 1 day remaining
    )
    await OrgCAPathLenFix().up()
    new_ca_pem = await get_config("org_ca_cert")
    new_ca = x509.load_pem_x509_certificate(new_ca_pem.encode())
    assert new_ca.extensions.get_extension_for_class(
        x509.BasicConstraints,
    ).value.path_length == 1


@pytest.mark.asyncio
async def test_up_writes_snapshot_to_backup_table(fresh_db):
    seeded = await _seed_legacy_state(path_length=0, with_intermediate=True)
    await OrgCAPathLenFix().up()

    backup = await get_migration_backup("2026-04-23-org-ca-pathlen-1")
    assert backup is not None

    import json
    snap = json.loads(backup["snapshot_json"])
    assert "org_ca_cert_pem" in snap
    assert "org_ca_key_pem" in snap
    assert set(snap["internal_agents"]) == set(seeded["leaves"])


# ── rollback() ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rollback_restores_original_state(fresh_db):
    seeded = await _seed_legacy_state(path_length=0, with_intermediate=True)
    old_ca_pem = (
        seeded["ca_cert"].public_bytes(serialization.Encoding.PEM).decode()
    )

    await OrgCAPathLenFix().up()
    # Confirm we actually rotated (new cert differs from old).
    rotated_pem = await get_config("org_ca_cert")
    assert rotated_pem != old_ca_pem

    await OrgCAPathLenFix().rollback()

    restored_pem = await get_config("org_ca_cert")
    assert restored_pem == old_ca_pem

    async with get_db() as conn:
        result = await conn.execute(
            text("SELECT agent_id, cert_pem FROM internal_agents")
        )
        restored_leaves = {
            row["agent_id"]: row["cert_pem"] for row in result.mappings()
        }

    for aid, cert in seeded["leaves"].items():
        expected_pem = cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode()
        assert restored_leaves[aid] == expected_pem


@pytest.mark.asyncio
async def test_rollback_raises_when_no_backup(fresh_db):
    # No up() call → no backup row → rollback must raise.
    with pytest.raises(RuntimeError, match="no backup exists"):
        await OrgCAPathLenFix().rollback()


@pytest.mark.asyncio
async def test_rollback_second_call_raises(fresh_db):
    # First rollback succeeds; second must fail because the backup row
    # is gone.
    await _seed_legacy_state(path_length=0, with_intermediate=True)
    await OrgCAPathLenFix().up()
    await OrgCAPathLenFix().rollback()
    with pytest.raises(RuntimeError, match="no backup exists"):
        await OrgCAPathLenFix().rollback()
