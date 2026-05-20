"""Audit F-E-03 + F-E-04 — startup refuses insecure secret backends in prod.

These tests lock in the post-fix behaviour:

1. Broker ``validate_config`` refuses ``environment=production`` when
   ``KMS_BACKEND`` is not ``vault`` (F-E-03) or when ``REDIS_URL`` is
   empty (F-E-04). Development mode keeps tolerating both for local
   workflows.
2. Proxy ``validate_config`` refuses ``environment=production`` when
   ``secret_backend`` is not ``vault`` (F-E-03 proxy analogue).
3. The DPoP JTI store runtime fallback raises in production when Redis
   is unavailable instead of silently dropping to the per-process
   in-memory store (F-E-04 defense in depth).
"""
from __future__ import annotations

import pytest

from app.config import Settings, validate_config
from mcp_proxy.config import ProxySettings, validate_config as proxy_validate_config


# ── Broker: F-E-03 KMS_BACKEND ──────────────────────────────────────

def _prod_broker_settings(**overrides) -> Settings:
    """Build broker Settings that would otherwise pass production validation.

    Uses bind-mount-style paths that exist in the test checkout (certs/ is
    created by generate_certs.py / tests fixtures). We only care about the
    production branch raising SystemExit for the specific knob under test,
    so callers flip the knob they want.
    """
    base = dict(
        environment="production",
        admin_secret="strong-random-admin-secret",
        database_url="postgresql+asyncpg://u:p@db/cullis",
        broker_ca_key_path="certs/broker-ca-key.pem",
        dashboard_signing_key="strong-random-dashboard-key",
        redis_url="redis://redis:6379/0",
        kms_backend="vault",
        # Audit Ultra U2 — production validate_config now requires an
        # explicit policy_default_decision. Every prod-shaped helper
        # therefore declares one (we don't care which value: tests that
        # need "allow" override locally).
        policy_default_decision="deny",
        # PR #1 audit 2026-05-20 — H4 sweep refuse-to-start gates.
        mastio_mtls_trusted_proxy_cidrs="172.18.0.0/16",  # F-A-101
        policy_webhook_hmac_secret="strong-policy-webhook-hmac",  # F-A-513
    )
    base.update(overrides)
    return Settings(**base)


def test_validate_config_rejects_prod_with_kms_backend_local(tmp_path, monkeypatch):
    # Create a placeholder CA key file so the pre-existing CA-path check
    # does not preempt the KMS check.
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n")
    settings = _prod_broker_settings(
        kms_backend="local",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_rejects_prod_with_unknown_kms_backend(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_broker_settings(
        kms_backend="aws-kms",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_dev_tolerates_kms_backend_local():
    """Development mode keeps KMS_BACKEND=local working for fixtures / CI."""
    settings = Settings(
        environment="development",
        admin_secret="strong-random-admin-secret",
        kms_backend="local",
        redis_url="",
    )
    # Must not raise.
    validate_config(settings)


# ── Broker: F-E-04 REDIS_URL ────────────────────────────────────────

def test_validate_config_rejects_prod_with_empty_redis_url(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_broker_settings(
        redis_url="",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_prod_passes_with_vault_and_redis(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_broker_settings(broker_ca_key_path=str(ca_key))
    # Must not raise.
    validate_config(settings)


# ── Proxy: F-E-03 secret_backend ────────────────────────────────────

def _prod_proxy_settings(**overrides) -> ProxySettings:
    base = dict(
        environment="production",
        admin_secret="strong-random-admin-secret",
        broker_jwks_url="https://broker.example.com/.well-known/jwks.json",
        standalone=False,
        broker_verify_tls=True,
        secret_backend="vault",
        # H3 P0.1 — production refuses kms_backend=local; the
        # prod-shaped helper therefore declares vault by default. Tests
        # that need to exercise the local-rejection branch override it.
        kms_backend="vault",
        vault_verify_tls=True,
        # Audit F-B-10 — prod now refuses empty signing key, so every
        # prod-shaped helper has to provide one.
        dashboard_signing_key="strong-signing-key",
        # Three-tier PKI hardening (audit 2026-05-18) — prod now
        # refuses empty MCP_PROXY_DB_ENCRYPTION_KEY too.
        db_encryption_key="x" * 48,
        # PR #1 audit 2026-05-20 — H4 sweep refuse-to-start gates.
        pdp_webhook_hmac_secret="strong-pdp-hmac-secret",  # F-A-202
        webauthn_enforcement="required",  # F-A-205
        webauthn_rp_id="mastio.example.com",
    )
    base.update(overrides)
    return ProxySettings(**base)


def test_proxy_validate_config_rejects_prod_with_secret_backend_env():
    settings = _prod_proxy_settings(secret_backend="env")
    with pytest.raises(SystemExit):
        proxy_validate_config(settings)


def test_proxy_validate_config_dev_tolerates_secret_backend_env():
    settings = ProxySettings(
        environment="development",
        secret_backend="env",
    )
    # Must not raise.
    proxy_validate_config(settings)


def test_proxy_validate_config_prod_allows_vault_backend():
    settings = _prod_proxy_settings()
    # Must not raise.
    proxy_validate_config(settings)


def test_proxy_validate_config_rejects_standalone_prod_with_env_backend():
    """Standalone mode skips broker checks but the secret backend refusal
    still applies, agent keys live in the proxy regardless of uplink."""
    settings = ProxySettings(
        environment="production",
        admin_secret="strong-random-admin-secret",
        standalone=True,
        secret_backend="env",
        kms_backend="vault",  # H3 P0.1: pin so the SystemExit is from secret_backend only
        vault_verify_tls=True,
        dashboard_signing_key="strong-signing-key",  # F-B-10
        db_encryption_key="x" * 48,  # 2026-05-18 three-tier hardening
    )
    with pytest.raises(SystemExit):
        proxy_validate_config(settings)


# ── Proxy: H3 P0.1 kms_backend ──────────────────────────────────────

def test_proxy_validate_config_rejects_prod_with_kms_backend_local():
    """Production refuses kms_backend=local because the Org CA private
    key would live in the Mastio database with no HSM-grade protection.
    Closes the gap surfaced by the 2026-05-15 threat-model verification
    pass."""
    settings = _prod_proxy_settings(kms_backend="local")
    with pytest.raises(SystemExit):
        proxy_validate_config(settings)


def test_proxy_validate_config_dev_tolerates_kms_backend_local():
    """Development keeps kms_backend=local working for sandbox / first-
    boot dogfood scenarios."""
    settings = ProxySettings(
        environment="development",
        secret_backend="env",
        kms_backend="local",
    )
    # Must not raise.
    proxy_validate_config(settings)


def test_proxy_validate_config_prod_allows_vault_kms():
    """The shipping production posture (kms_backend=vault) must continue
    to pass after the local-rejection branch lands."""
    settings = _prod_proxy_settings(kms_backend="vault")
    # Must not raise.
    proxy_validate_config(settings)


def test_proxy_validate_config_rejects_standalone_prod_with_kms_local():
    """Standalone mode does not exempt the Org CA: standalone Mastios
    sign agent certs with the same key, so kms_backend=local still
    leaks the key on host compromise."""
    settings = ProxySettings(
        environment="production",
        admin_secret="strong-random-admin-secret",
        standalone=True,
        secret_backend="vault",  # pin so the SystemExit is from kms_backend only
        kms_backend="local",
        vault_verify_tls=True,
        dashboard_signing_key="strong-signing-key",  # F-B-10
        db_encryption_key="x" * 48,  # 2026-05-18 three-tier hardening
    )
    with pytest.raises(SystemExit):
        proxy_validate_config(settings)


# ── F-E-04 runtime: DPoP JTI store refuses in-memory in prod ────────

def test_dpop_jti_init_refuses_in_memory_in_production(monkeypatch):
    """``_init_store`` must not silently return InMemoryDpopJtiStore in
    production when Redis is unreachable — the replay window across
    workers is unacceptable."""
    from app.auth import dpop_jti_store as jti_mod
    from app.redis import pool as redis_pool

    # Force "no redis available".
    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)

    # Force production env via the cached settings.
    from app.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("ENVIRONMENT", "production")
    # Other prod-required knobs not relevant here: _init_store only reads
    # settings.environment.

    jti_mod.reset_dpop_jti_store()
    try:
        with pytest.raises(RuntimeError):
            jti_mod._init_store()
    finally:
        # Leave the cache and state clean for sibling tests.
        get_settings.cache_clear()
        jti_mod.reset_dpop_jti_store()


def test_dpop_jti_init_uses_in_memory_in_development(monkeypatch):
    from app.auth import dpop_jti_store as jti_mod
    from app.redis import pool as redis_pool

    monkeypatch.setattr(redis_pool, "get_redis", lambda: None)

    from app.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("ENVIRONMENT", "development")

    jti_mod.reset_dpop_jti_store()
    try:
        store = jti_mod._init_store()
        assert isinstance(store, jti_mod.InMemoryDpopJtiStore)
    finally:
        get_settings.cache_clear()
        jti_mod.reset_dpop_jti_store()


# ── F-B-12: Mastio Redis warning (not a hard refusal) ──────────────
#
# Unlike the broker, Mastio has a legitimate single-instance production
# mode (single-tenant intra-org). validate_config warns rather than
# refusing when REDIS_URL is empty in production — operators deploying
# multi-worker/HA must set it to avoid the cross-worker DPoP replay +
# rate-limit budget multiplication.
#
# pytest's caplog and even a manually-attached handler on the
# ``mcp_proxy`` logger miss the records on some CI runners (the
# structured JSON logger in ``mcp_proxy/logging_setup.py`` sets
# ``propagate=False``; downstream hierarchy + handler timing is
# environment-sensitive). Intercept ``_log.warning`` directly on the
# module under test — this is the tightest possible coupling and has no
# dependency on logging framework behaviour.


def _patch_startup_warning(monkeypatch):
    """Capture warnings emitted by ``mcp_proxy.config._log.warning``."""
    import mcp_proxy.config as _config_mod
    calls: list[str] = []

    def _record(msg, *args, **kwargs):
        calls.append(str(msg) % args if args else str(msg))

    monkeypatch.setattr(_config_mod._log, "warning", _record)
    return calls


def test_proxy_validate_config_warns_on_prod_without_redis(monkeypatch):
    settings = _prod_proxy_settings(redis_url="")
    warnings = _patch_startup_warning(monkeypatch)
    # Must NOT raise — single-instance Mastio prod is supported.
    proxy_validate_config(settings)
    messages = " ".join(warnings)
    assert "MCP_PROXY_REDIS_URL" in messages
    assert "single-instance" in messages or "multi-worker" in messages
    assert "F-B-12" in messages


def test_proxy_validate_config_prod_with_redis_no_warning(monkeypatch):
    settings = _prod_proxy_settings(redis_url="redis://redis:6379/0")
    warnings = _patch_startup_warning(monkeypatch)
    proxy_validate_config(settings)
    messages = " ".join(warnings)
    assert "F-B-12" not in messages


def test_proxy_validate_config_dev_without_redis_no_warning(monkeypatch):
    settings = ProxySettings(environment="development", redis_url="")
    warnings = _patch_startup_warning(monkeypatch)
    proxy_validate_config(settings)
    messages = " ".join(warnings)
    assert "F-B-12" not in messages


# ── F-B-5: reject ADMIN_SECRET default at Settings construction ────
#
# Previously the rejection lived only in validate_config, so a caller
# that built ``Settings()`` without running validate_config (subprocess
# tests, scripts, custom entrypoints) got happy settings carrying the
# well-known insecure default — which ``_require_admin`` then accepted
# via ``hmac.compare_digest``. Moving the refusal to a model_validator
# makes every ``Settings()`` instance fail fast.

def test_settings_rejects_insecure_default_admin_secret(monkeypatch):
    """The default literal ``change-me-in-production`` must not be
    accepted — ``Settings()`` raises at construction time, before
    any lifespan hook (``validate_config``) is ever invoked."""
    from app.config import _INSECURE_DEFAULT_SECRET
    from pydantic import ValidationError

    monkeypatch.setenv("ADMIN_SECRET", _INSECURE_DEFAULT_SECRET)
    with pytest.raises(ValidationError) as excinfo:
        Settings()
    # Error message names the env var so operators know how to fix it.
    assert "ADMIN_SECRET" in str(excinfo.value)
    assert "F-B-5" in str(excinfo.value)


def test_settings_rejects_default_even_when_kwarg_forced():
    """Explicit kwarg override must also raise — not just .env reads.
    Guards against a test harness that passes the default through
    unintentionally."""
    from app.config import _INSECURE_DEFAULT_SECRET
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(admin_secret=_INSECURE_DEFAULT_SECRET)


def test_settings_accepts_any_non_default_admin_secret():
    """Sanity: any string other than the sentinel is fine."""
    settings = Settings(admin_secret="some-other-admin-secret-value")
    assert settings.admin_secret == "some-other-admin-secret-value"


def test_settings_rejects_default_regardless_of_environment(monkeypatch):
    """The refusal is environment-independent. Dev mode does not unlock
    the default — tests that genuinely need it must supply a
    non-default value (the conftest autouses
    ``ADMIN_SECRET=test-secret-not-default``)."""
    from app.config import _INSECURE_DEFAULT_SECRET
    from pydantic import ValidationError

    monkeypatch.setenv("ADMIN_SECRET", _INSECURE_DEFAULT_SECRET)
    for env in ("development", "production"):
        monkeypatch.setenv("ENVIRONMENT", env)
        with pytest.raises(ValidationError):
            Settings()
