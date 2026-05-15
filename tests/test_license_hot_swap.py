"""H3 P0.2 — license hot-swap without restart.

The cached license must be replaceable in-process so a paid-tier
customer can rotate their JWT every ~90 days without bouncing the
bundle. The new function :func:`mcp_proxy.license.swap_token`:

- atomically replaces ``_cached`` when the candidate verifies
- leaves the cache unchanged when verification fails (so a paste
  error or hostile JWT cannot accidentally downgrade a running
  deployment to community)
- resets the plugin registry so the feature gate re-applies on the
  next call (paid plugins come online, downgrades hide them)

The dashboard wraps this with a CSRF + login-gated POST and runs the
4-eyes plugin hook when the enterprise rbac_multi_admin plugin
publishes a quorum policy for ``ACTION_LICENSE_IMPORT``.
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt as jose_jwt

from mcp_proxy import license as mp_license
from mcp_proxy import plugins as mp_plugins


def _gen_keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub


def _mint_license(
    priv_pem: bytes,
    *,
    features: list[str],
    tier: str = "enterprise",
    org: str = "rotation-test",
    exp_offset: int = 3600,
) -> str:
    now = int(time.time())
    return jose_jwt.encode(
        {"tier": tier, "org": org, "features": features, "exp": now + exp_offset},
        priv_pem,
        algorithm="RS256",
    )


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch: pytest.MonkeyPatch):
    mp_license.reset_cache()
    mp_plugins.reset_registry()
    monkeypatch.delenv("CULLIS_LICENSE_KEY", raising=False)
    monkeypatch.delenv("CULLIS_LICENSE_PATH", raising=False)
    monkeypatch.delenv("CULLIS_LICENSE_PUBKEY_PATH", raising=False)
    yield
    mp_license.reset_cache()
    mp_plugins.reset_registry()


# ── happy path ───────────────────────────────────────────────────────────


def test_swap_valid_token_replaces_cache(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Verified token → ``_cached`` is replaced with the new claims."""
    priv, pub = _gen_keypair()
    pub_path = tmp_path / "rotation.pub"
    pub_path.write_bytes(pub)
    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))

    # First, prime the cache with one license.
    first = _mint_license(priv, features=["saml_sso"])
    monkeypatch.setenv("CULLIS_LICENSE_KEY", first)
    initial = mp_license.load_license()
    assert initial.features == frozenset({"saml_sso"})

    # Mint a second one with different features and swap.
    second = _mint_license(priv, features=["saml_sso", "audit_export_s3"])
    new_claims = mp_license.swap_token(second)

    assert new_claims.features == frozenset({"saml_sso", "audit_export_s3"})
    # And the cache reflects the swap: a fresh has_feature call sees it.
    assert mp_license.has_feature("audit_export_s3") is True


def test_swap_invalidates_plugin_registry(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Plugin registry is reset so paid plugins re-filter on the next call."""
    priv, pub = _gen_keypair()
    pub_path = tmp_path / "rotation.pub"
    pub_path.write_bytes(pub)
    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))

    first = _mint_license(priv, features=[])
    monkeypatch.setenv("CULLIS_LICENSE_KEY", first)
    # Force the registry to populate.
    mp_plugins.get_registry()
    assert mp_plugins._registry is not None

    second = _mint_license(priv, features=["saml_sso"])
    mp_license.swap_token(second)

    # swap_token must have cleared the cached registry.
    assert mp_plugins._registry is None


# ── failure paths: cache stays unchanged ─────────────────────────────────


def test_swap_empty_token_raises_and_leaves_cache_unchanged(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
):
    priv, pub = _gen_keypair()
    pub_path = tmp_path / "rotation.pub"
    pub_path.write_bytes(pub)
    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))

    first = _mint_license(priv, features=["saml_sso"])
    monkeypatch.setenv("CULLIS_LICENSE_KEY", first)
    mp_license.load_license()

    with pytest.raises(mp_license.LicenseSwapError, match="empty"):
        mp_license.swap_token("")
    # Cache untouched.
    assert mp_license.has_feature("saml_sso") is True


def test_swap_expired_token_raises_and_leaves_cache_unchanged(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
):
    priv, pub = _gen_keypair()
    pub_path = tmp_path / "rotation.pub"
    pub_path.write_bytes(pub)
    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))

    first = _mint_license(priv, features=["saml_sso"])
    monkeypatch.setenv("CULLIS_LICENSE_KEY", first)
    mp_license.load_license()

    expired = _mint_license(priv, features=["audit_export_s3"], exp_offset=-60)
    with pytest.raises(mp_license.LicenseSwapError, match="failed verification"):
        mp_license.swap_token(expired)
    # Cache still holds the valid first license.
    assert mp_license.has_feature("saml_sso") is True
    assert mp_license.has_feature("audit_export_s3") is False


def test_swap_token_signed_with_wrong_key_raises(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
):
    """Swap must reject a token signed by anyone other than the configured
    issuer — i.e. an attacker mints their own JWT but the verifier rejects
    it because the public key does not match."""
    issuer_priv, issuer_pub = _gen_keypair()
    pub_path = tmp_path / "issuer.pub"
    pub_path.write_bytes(issuer_pub)
    monkeypatch.setenv("CULLIS_LICENSE_PUBKEY_PATH", str(pub_path))

    legit = _mint_license(issuer_priv, features=["saml_sso"])
    monkeypatch.setenv("CULLIS_LICENSE_KEY", legit)
    mp_license.load_license()

    attacker_priv, _ = _gen_keypair()
    hostile = _mint_license(attacker_priv, features=["saml_sso", "audit_export_s3"])
    with pytest.raises(mp_license.LicenseSwapError):
        mp_license.swap_token(hostile)
    # The hostile token's extra feature must not have been activated.
    assert mp_license.has_feature("audit_export_s3") is False


def test_swap_refuses_when_pubkey_override_unreadable(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
):
    """When ``CULLIS_LICENSE_PUBKEY_PATH`` is set but unreadable (typo /
    missing file), ``_load_pubkey`` returns None and the swap must
    refuse rather than silently fall back to the baked key — the
    operator's intent was to use the override."""
    monkeypatch.setenv(
        "CULLIS_LICENSE_PUBKEY_PATH", str(tmp_path / "does-not-exist.pub"),
    )
    priv, _ = _gen_keypair()
    candidate = _mint_license(priv, features=["saml_sso"])
    with pytest.raises(mp_license.LicenseSwapError, match="pubkey"):
        mp_license.swap_token(candidate)
