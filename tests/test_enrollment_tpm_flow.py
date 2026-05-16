"""End-to-end enrollment with the TPM attestation half (F3 Phase 1).

Software-mocked: the test drives the real service.start_enrollment path
but signs the "quote" with an in-process EC P-256 key in place of the
TPM. This exercises the full server pipeline; nonce mint, quote verify,
pending_enrollments.device_attestation_json persistence, audit event; on
hosts without a TPM (which is the default in CI).

A separate test exercises the soft-fallback path: omitting the TPM
fields must keep the enrollment running without an attestation row.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from sqlalchemy import text

from mcp_proxy.attestation import nonce_store
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.enrollment import service
from mcp_proxy.enrollment.service import EnrollmentError


_QUOTE_MAGIC = b"CULLIS-Q1"


def _pack(quote: bytes, sig: bytes, nonce: bytes) -> bytes:
    out = bytearray()
    out += _QUOTE_MAGIC
    out += len(nonce).to_bytes(2, "big")
    out += nonce
    out += len(quote).to_bytes(4, "big")
    out += quote
    out += len(sig).to_bytes(4, "big")
    out += sig
    return bytes(out)


def _ec_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return key, pem


def _build_quote_b64(nonce: bytes, key: ec.EllipticCurvePrivateKey) -> str:
    body = b"mocked-TPMS_ATTEST||" + nonce
    digest = hashlib.sha256(body).digest()
    sig = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    blob = _pack(body, sig, nonce)
    return base64.urlsafe_b64encode(blob).rstrip(b"=").decode()


@pytest_asyncio.fixture
async def db_engine(tmp_path, monkeypatch):
    db_file = tmp_path / "tpm_flow.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    from mcp_proxy.config import get_settings

    get_settings.cache_clear()
    await init_db(url)
    nonce_store.reset_memory_store_for_tests()
    yield
    await dispose_db()
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_start_enrollment_with_valid_tpm_quote_persists_claim(db_engine):
    key, pem = _ec_keypair()
    issued = await nonce_store.issue_nonce()
    quote_b64 = _build_quote_b64(issued.nonce_bytes, key)

    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pem,
            requester_name="Hardware Hannah",
            requester_email="hh@acme.com",
            reason="tpm-pilot",
            device_info=None,
            attestation_nonce_id=issued.nonce_id,
            tpm_quote_b64=quote_b64,
            tpm_manufacturer="Infineon",
            tpm_ek_cert_present=True,
        )

    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT device_attestation_json FROM pending_enrollments "
                "WHERE session_id = :sid"
            ),
            {"sid": started.session_id},
        )
        row = result.first()
    assert row is not None
    claim_json = row[0]
    assert claim_json
    claim = json.loads(claim_json)
    assert claim["hardware"] == "tpm_2.0"
    assert claim["strength"] == "hw_attested"
    assert claim["manufacturer"] == "Infineon"
    assert "verified_at" in claim


@pytest.mark.asyncio
async def test_start_enrollment_audit_row_written_on_verified_quote(db_engine):
    key, pem = _ec_keypair()
    issued = await nonce_store.issue_nonce()
    quote_b64 = _build_quote_b64(issued.nonce_bytes, key)

    async with get_db() as conn:
        await service.start_enrollment(
            conn,
            pubkey_pem=pem,
            requester_name="Hannah",
            requester_email="h@acme.com",
            reason=None,
            device_info=None,
            attestation_nonce_id=issued.nonce_id,
            tpm_quote_b64=quote_b64,
            tpm_manufacturer="Infineon",
            tpm_ek_cert_present=True,
        )

    async with get_db() as conn:
        result = await conn.execute(
            text(
                "SELECT action FROM audit_log WHERE action = "
                "'device_attestation.verified'"
            )
        )
        actions = [r[0] for r in result.all()]
    assert actions == ["device_attestation.verified"]


@pytest.mark.asyncio
async def test_start_enrollment_without_tpm_fields_skips_attestation(db_engine):
    _, pem = _ec_keypair()
    async with get_db() as conn:
        started = await service.start_enrollment(
            conn,
            pubkey_pem=pem,
            requester_name="Soft Sam",
            requester_email="s@acme.com",
            reason=None,
            device_info=None,
        )
        result = await conn.execute(
            text(
                "SELECT device_attestation_json FROM pending_enrollments "
                "WHERE session_id = :sid"
            ),
            {"sid": started.session_id},
        )
        row = result.first()
    assert row is not None
    assert row[0] is None


@pytest.mark.asyncio
async def test_start_enrollment_rejects_quote_without_nonce_id(db_engine):
    key, pem = _ec_keypair()
    issued = await nonce_store.issue_nonce()
    quote_b64 = _build_quote_b64(issued.nonce_bytes, key)

    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.start_enrollment(
                conn,
                pubkey_pem=pem,
                requester_name="Half",
                requester_email="h@acme.com",
                reason=None,
                device_info=None,
                attestation_nonce_id=None,
                tpm_quote_b64=quote_b64,
            )
    assert exc.value.http_status == 400


@pytest.mark.asyncio
async def test_start_enrollment_rejects_expired_or_unknown_nonce(db_engine):
    key, pem = _ec_keypair()
    bogus_nonce = secrets.token_bytes(32)
    body = b"mocked-TPMS_ATTEST||" + bogus_nonce
    digest = hashlib.sha256(body).digest()
    sig = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    blob = _pack(body, sig, bogus_nonce)
    quote_b64 = base64.urlsafe_b64encode(blob).rstrip(b"=").decode()

    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.start_enrollment(
                conn,
                pubkey_pem=pem,
                requester_name="Stale",
                requester_email="x@acme.com",
                reason=None,
                device_info=None,
                attestation_nonce_id="never-issued",
                tpm_quote_b64=quote_b64,
            )
    assert exc.value.http_status == 400


@pytest.mark.asyncio
async def test_start_enrollment_rejects_tampered_quote(db_engine):
    key, pem = _ec_keypair()
    issued = await nonce_store.issue_nonce()
    quote_b64 = _build_quote_b64(issued.nonce_bytes, key)
    # Flip a byte deep inside the base64url payload; corrupts the
    # signature DER and must fail crypto verification.
    raw = bytearray(base64.urlsafe_b64decode(quote_b64 + "=" * (-len(quote_b64) % 4)))
    raw[-1] ^= 0x80
    tampered_b64 = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

    async with get_db() as conn:
        with pytest.raises(EnrollmentError) as exc:
            await service.start_enrollment(
                conn,
                pubkey_pem=pem,
                requester_name="Tampered",
                requester_email="t@acme.com",
                reason=None,
                device_info=None,
                attestation_nonce_id=issued.nonce_id,
                tpm_quote_b64=tampered_b64,
                tpm_manufacturer="Infineon",
                tpm_ek_cert_present=True,
            )
    assert exc.value.http_status == 400
