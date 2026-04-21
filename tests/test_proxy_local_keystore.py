"""ADR-012 Phase 2.0 — unit tests for ``LocalKeyStore``.

Covers the four public surface points of the keystore: ``current_signer``
(with both invariant-violation branches), ``find_by_kid``,
``all_valid_keys`` (including grace-period filtering), and the
``MastioKey.is_valid_for_verification`` computed property.

The migration itself (0018) has coverage in ``test_proxy_migrations_*``
by virtue of running on every proxy fixture boot; this file focuses on
the Python primitive once the table exists.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_proxy.auth.local_keystore import (
    LocalKeyStore,
    MastioKey,
    compute_kid,
)
from mcp_proxy.db import insert_mastio_key


def _fresh_keypair() -> tuple[str, str, str]:
    """Return ``(kid, pubkey_pem, privkey_pem)`` for a fresh EC P-256 key."""
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return compute_kid(pub_pem), pub_pem, priv_pem


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    """Fresh proxy SQLite DB with the ``mastio_keys`` migration applied."""
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.db import dispose_db, init_db
    await init_db(url)
    yield
    await dispose_db()
    get_settings.cache_clear()


def test_compute_kid_matches_legacy_algorithm():
    """``compute_kid`` reproduces the pre-2.0 ``LocalIssuer._compute_kid``
    so rows migrated from ``proxy_config`` keep the kid any already-issued
    JWT references in its header."""
    _, pub_pem, _ = _fresh_keypair()
    expected = "mastio-" + hashlib.sha256(pub_pem.encode()).hexdigest()[:16]
    assert compute_kid(pub_pem) == expected


def test_mastio_key_is_active_only_when_activated_and_not_deprecated():
    now = datetime.now(timezone.utc)
    activated = MastioKey(
        kid="k", pubkey_pem="", privkey_pem="", cert_pem=None,
        created_at=now, activated_at=now, deprecated_at=None, expires_at=None,
    )
    assert activated.is_active is True

    never_activated = MastioKey(
        kid="k", pubkey_pem="", privkey_pem="", cert_pem=None,
        created_at=now, activated_at=None, deprecated_at=None, expires_at=None,
    )
    assert never_activated.is_active is False

    deprecated = MastioKey(
        kid="k", pubkey_pem="", privkey_pem="", cert_pem=None,
        created_at=now, activated_at=now, deprecated_at=now, expires_at=None,
    )
    assert deprecated.is_active is False


def test_mastio_key_valid_for_verification_honours_expires_at():
    now = datetime.now(timezone.utc)
    past = now - timedelta(hours=1)
    future = now + timedelta(hours=1)

    never_activated = MastioKey(
        kid="k", pubkey_pem="", privkey_pem="", cert_pem=None,
        created_at=now, activated_at=None, deprecated_at=None, expires_at=None,
    )
    assert never_activated.is_valid_for_verification is False

    no_expiry = MastioKey(
        kid="k", pubkey_pem="", privkey_pem="", cert_pem=None,
        created_at=now, activated_at=past, deprecated_at=None, expires_at=None,
    )
    assert no_expiry.is_valid_for_verification is True

    within_grace = MastioKey(
        kid="k", pubkey_pem="", privkey_pem="", cert_pem=None,
        created_at=now, activated_at=past, deprecated_at=past,
        expires_at=future,
    )
    assert within_grace.is_valid_for_verification is True

    grace_elapsed = MastioKey(
        kid="k", pubkey_pem="", privkey_pem="", cert_pem=None,
        created_at=now, activated_at=past, deprecated_at=past,
        expires_at=past,
    )
    assert grace_elapsed.is_valid_for_verification is False


@pytest.mark.asyncio
async def test_current_signer_raises_when_no_active_key(proxy_db):
    store = LocalKeyStore()
    with pytest.raises(RuntimeError, match="no active mastio key"):
        await store.current_signer()


@pytest.mark.asyncio
async def test_current_signer_returns_the_single_active_row(proxy_db):
    kid, pub, priv = _fresh_keypair()
    now = datetime.now(timezone.utc)
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_iso(now), activated_at=_iso(now),
    )
    store = LocalKeyStore()
    current = await store.current_signer()
    assert current.kid == kid
    assert current.is_active is True


@pytest.mark.asyncio
async def test_current_signer_raises_when_multiple_active(proxy_db):
    now = datetime.now(timezone.utc)
    for _ in range(2):
        kid, pub, priv = _fresh_keypair()
        await insert_mastio_key(
            kid=kid, pubkey_pem=pub, privkey_pem=priv,
            created_at=_iso(now), activated_at=_iso(now),
        )
    store = LocalKeyStore()
    with pytest.raises(RuntimeError, match="rotation invariant violated"):
        await store.current_signer()


@pytest.mark.asyncio
async def test_find_by_kid_returns_none_for_unknown_kid(proxy_db):
    store = LocalKeyStore()
    assert await store.find_by_kid("mastio-deadbeefdeadbeef") is None


@pytest.mark.asyncio
async def test_find_by_kid_returns_row_even_when_deprecated(proxy_db):
    """The verifier must still see deprecated keys to accept grace-period
    tokens — ``find_by_kid`` does not filter on ``deprecated_at``."""
    kid, pub, priv = _fresh_keypair()
    now = datetime.now(timezone.utc)
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_iso(now - timedelta(days=30)),
        activated_at=_iso(now - timedelta(days=30)),
        deprecated_at=_iso(now - timedelta(days=1)),
        expires_at=_iso(now + timedelta(days=6)),
    )
    store = LocalKeyStore()
    found = await store.find_by_kid(kid)
    assert found is not None
    assert found.kid == kid
    assert found.is_active is False
    assert found.is_valid_for_verification is True


@pytest.mark.asyncio
async def test_all_valid_keys_excludes_expired_rows(proxy_db):
    now = datetime.now(timezone.utc)
    # Active
    kid_active, pub_a, priv_a = _fresh_keypair()
    await insert_mastio_key(
        kid=kid_active, pubkey_pem=pub_a, privkey_pem=priv_a,
        created_at=_iso(now), activated_at=_iso(now),
    )
    # Deprecated but in grace window → still valid
    kid_grace, pub_g, priv_g = _fresh_keypair()
    await insert_mastio_key(
        kid=kid_grace, pubkey_pem=pub_g, privkey_pem=priv_g,
        created_at=_iso(now - timedelta(days=10)),
        activated_at=_iso(now - timedelta(days=10)),
        deprecated_at=_iso(now - timedelta(hours=1)),
        expires_at=_iso(now + timedelta(days=5)),
    )
    # Deprecated and expired → filtered out
    kid_expired, pub_e, priv_e = _fresh_keypair()
    await insert_mastio_key(
        kid=kid_expired, pubkey_pem=pub_e, privkey_pem=priv_e,
        created_at=_iso(now - timedelta(days=400)),
        activated_at=_iso(now - timedelta(days=400)),
        deprecated_at=_iso(now - timedelta(days=30)),
        expires_at=_iso(now - timedelta(days=1)),
    )

    store = LocalKeyStore()
    valid = await store.all_valid_keys()
    kids = {k.kid for k in valid}
    assert kid_active in kids
    assert kid_grace in kids
    assert kid_expired not in kids


@pytest.mark.asyncio
async def test_mastio_key_load_private_key_roundtrip(proxy_db):
    kid, pub, priv = _fresh_keypair()
    now = datetime.now(timezone.utc)
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_iso(now), activated_at=_iso(now),
    )
    store = LocalKeyStore()
    found = await store.find_by_kid(kid)
    assert found is not None
    loaded = found.load_private_key()
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)


@pytest.mark.asyncio
async def test_mastio_key_jwk_shape_matches_rfc7517(proxy_db):
    kid, pub, priv = _fresh_keypair()
    now = datetime.now(timezone.utc)
    await insert_mastio_key(
        kid=kid, pubkey_pem=pub, privkey_pem=priv,
        created_at=_iso(now), activated_at=_iso(now),
    )
    store = LocalKeyStore()
    found = await store.find_by_kid(kid)
    assert found is not None
    jwk = found.jwk()
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert jwk["alg"] == "ES256"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == kid
    assert set(jwk) == {"kty", "crv", "alg", "use", "kid", "x", "y"}
