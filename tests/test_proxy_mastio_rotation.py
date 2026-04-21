"""ADR-012 Phase 2.1 — key-continuity proof + ``rotate_mastio_key``.

Two surfaces:

* ``mcp_proxy.auth.mastio_rotation`` — pure proof build/verify
  primitive. Tested against a fresh EC P-256 keypair, no DB or Court.
* ``AgentManager.rotate_mastio_key`` — exercised end-to-end against a
  real ``mastio_keys`` table. A stub propagator stands in for the
  Court; Commit 3 wires the real BrokerBridge call.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_proxy.auth.local_keystore import LocalKeyStore, compute_kid
from mcp_proxy.auth.mastio_rotation import (
    ContinuityProof,
    ContinuityProofError,
    build_proof,
    verify_proof,
)


def _fresh_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


# ── Proof primitive ─────────────────────────────────────────────────


def test_proof_roundtrip_valid_signature():
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    old_kid = compute_kid(old_pub)
    new_kid = compute_kid(new_pub)

    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=old_kid,
        new_kid=new_kid,
        new_pubkey_pem=new_pub,
    )
    assert proof.old_kid == old_kid
    assert proof.new_kid == new_kid
    assert proof.new_pubkey_pem == new_pub
    # ES256 raw r||s → 64 bytes → ~86 b64url chars, no padding
    assert 80 <= len(proof.signature_b64u) <= 90
    assert "=" not in proof.signature_b64u

    verify_proof(
        proof,
        expected_old_pubkey_pem=old_pub,
        expected_old_kid=old_kid,
    )


def test_verify_rejects_wrong_pubkey():
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    _, foreign_pub = _fresh_keypair()
    with pytest.raises(ContinuityProofError, match="signature"):
        verify_proof(proof, expected_old_pubkey_pem=foreign_pub)


def test_verify_rejects_kid_substitution():
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    with pytest.raises(ContinuityProofError, match="old_kid mismatch"):
        verify_proof(
            proof,
            expected_old_pubkey_pem=old_pub,
            expected_old_kid="mastio-deadbeefdeadbeef",
        )


def test_verify_rejects_stale_proof():
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    stale_when = datetime.now(timezone.utc) - timedelta(hours=2)
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
        issued_at=stale_when,
    )
    with pytest.raises(ContinuityProofError, match="freshness"):
        verify_proof(proof, expected_old_pubkey_pem=old_pub)


def test_verify_rejects_tampered_payload():
    """Payload tamper detection: any change to canonicalised fields
    invalidates the signature even if ``old_kid`` still matches."""
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    _, evil_pub = _fresh_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    tampered = ContinuityProof(
        old_kid=proof.old_kid,
        new_kid=compute_kid(evil_pub),
        new_pubkey_pem=evil_pub,
        issued_at=proof.issued_at,
        signature_b64u=proof.signature_b64u,
    )
    with pytest.raises(ContinuityProofError, match="signature"):
        verify_proof(tampered, expected_old_pubkey_pem=old_pub)


def test_proof_serialisation_roundtrip():
    old_priv, old_pub = _fresh_keypair()
    _, new_pub = _fresh_keypair()
    proof = build_proof(
        old_priv_key=old_priv,
        old_kid=compute_kid(old_pub),
        new_kid=compute_kid(new_pub),
        new_pubkey_pem=new_pub,
    )
    data = proof.to_dict()
    assert set(data) == {
        "old_kid", "new_kid", "new_pubkey_pem", "issued_at", "signature_b64u",
    }
    restored = ContinuityProof.from_dict(data)
    verify_proof(restored, expected_old_pubkey_pem=old_pub)


def test_proof_from_dict_rejects_missing_fields():
    with pytest.raises(ValueError, match="missing fields"):
        ContinuityProof.from_dict({"old_kid": "k"})


# ── AgentManager.rotate_mastio_key ──────────────────────────────────


@pytest_asyncio.fixture
async def agent_manager_with_identity(tmp_path, monkeypatch):
    """``AgentManager`` with a bootstrapped Org CA + Mastio identity,
    ready for rotation."""
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.db import dispose_db, init_db
    from mcp_proxy.egress.agent_manager import AgentManager

    await init_db(url)
    mgr = AgentManager(org_id="acme")
    await mgr.generate_org_ca(derive_org_id=False)
    await mgr.ensure_mastio_identity()
    try:
        yield mgr
    finally:
        await dispose_db()
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_rotate_mastio_key_swaps_active_row(agent_manager_with_identity):
    mgr = agent_manager_with_identity
    old_kid = mgr._active_key.kid  # pre-rotation signer

    new_active = await mgr.rotate_mastio_key(grace_days=3)

    assert new_active.kid != old_kid
    assert new_active.is_active is True
    # Cache refreshed on the manager
    assert mgr._active_key.kid == new_active.kid

    # Old row is now deprecated but still verification-valid.
    store = LocalKeyStore()
    old = await store.find_by_kid(old_kid)
    assert old is not None
    assert old.is_active is False
    assert old.deprecated_at is not None
    assert old.expires_at is not None
    assert old.is_valid_for_verification is True

    valid = await store.all_valid_keys()
    kids = {k.kid for k in valid}
    assert kids == {old_kid, new_active.kid}


@pytest.mark.asyncio
async def test_rotate_invokes_propagator_before_db_swap(agent_manager_with_identity):
    mgr = agent_manager_with_identity
    old_kid = mgr._active_key.kid

    captured: list[tuple[ContinuityProof, str]] = []

    async def propagator(proof: ContinuityProof, new_cert_pem: str) -> None:
        captured.append((proof, new_cert_pem))
        # Observer check: keystore has NOT swapped yet at this point.
        store = LocalKeyStore()
        current = await store.current_signer()
        assert current.kid == old_kid, "DB swap happened before propagator"

    await mgr.rotate_mastio_key(grace_days=3, propagator=propagator)

    assert len(captured) == 1
    proof, cert_pem = captured[0]
    assert proof.old_kid == old_kid
    # Proof carries the new cert's public key — verify chain
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")


@pytest.mark.asyncio
async def test_rotate_aborts_when_propagator_raises(agent_manager_with_identity):
    mgr = agent_manager_with_identity
    old_kid = mgr._active_key.kid

    async def failing(_proof, _cert):
        raise RuntimeError("court rejected the proof")

    with pytest.raises(RuntimeError, match="court rejected"):
        await mgr.rotate_mastio_key(grace_days=3, propagator=failing)

    # State unchanged — still exactly one active row, same kid.
    store = LocalKeyStore()
    current = await store.current_signer()
    assert current.kid == old_kid
    assert mgr._active_key.kid == old_kid


@pytest.mark.asyncio
async def test_rotate_rejects_non_positive_grace(agent_manager_with_identity):
    with pytest.raises(ValueError, match="grace_days"):
        await agent_manager_with_identity.rotate_mastio_key(grace_days=0)


@pytest.mark.asyncio
async def test_rotated_key_issues_verifiable_jwts(agent_manager_with_identity):
    """After rotation, the LocalIssuer built from the keystore signs
    JWTs under the new kid, and the validator resolves both kids
    (new and grace-period old)."""
    from mcp_proxy.auth.local_issuer import build_from_keystore
    from mcp_proxy.auth.local_validator import validate_local_token

    mgr = agent_manager_with_identity
    store = LocalKeyStore()

    old_issuer = await build_from_keystore("acme", store)
    old_token = old_issuer.issue("acme::alice", ttl_seconds=60).token

    await mgr.rotate_mastio_key(grace_days=3)

    new_issuer = await build_from_keystore("acme", store)
    assert new_issuer.kid != old_issuer.kid
    new_token = new_issuer.issue("acme::alice", ttl_seconds=60).token

    # Both tokens validate during the grace period — the verifier picks
    # the right key out of the keystore via ``kid`` lookup.
    payload_old = await validate_local_token(
        old_token, store, expected_issuer=new_issuer.issuer,
    )
    payload_new = await validate_local_token(
        new_token, store, expected_issuer=new_issuer.issuer,
    )
    assert payload_old.agent_id == "acme::alice"
    assert payload_new.agent_id == "acme::alice"


@pytest.mark.asyncio
async def test_rotate_counter_signs_with_new_key(agent_manager_with_identity):
    """ADR-009 counter-sign path follows the active key swap."""
    mgr = agent_manager_with_identity
    old_pub = mgr.get_mastio_pubkey_pem()

    await mgr.rotate_mastio_key(grace_days=3)

    new_pub = mgr.get_mastio_pubkey_pem()
    assert new_pub != old_pub

    # countersign() now signs under the new key; the signature must be
    # verifiable by the new pubkey, not the old.
    sig_b64 = mgr.countersign(b"payload-under-test")
    assert sig_b64
    import base64
    import cryptography.hazmat.primitives.asymmetric.ec as _ec
    from cryptography.hazmat.primitives import hashes, serialization

    sig_raw = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    # countersign() emits a DER-encoded signature (``priv.sign`` default).
    pub = serialization.load_pem_public_key(new_pub.encode())
    assert isinstance(pub, _ec.EllipticCurvePublicKey)
    pub.verify(sig_raw, b"payload-under-test", _ec.ECDSA(hashes.SHA256()))
