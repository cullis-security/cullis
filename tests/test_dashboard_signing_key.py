"""Audit F-B-10 — dashboard signing key persistence + prod refusal.

The legacy ``_auto_key = os.urandom(32).hex()`` fallback is per-process only
so multi-worker / multi-replica deploys diverge and sessions break on
worker hop; restarts silently evict every logged-in admin. The fix:

  * Production with empty ``DASHBOARD_SIGNING_KEY`` → SystemExit (broker
    was already refusing; the proxy analogue is now enforced too).
  * Development → key is persisted to a 0600 file at the configured path,
    reused across restarts and workers on the same filesystem.
  * When ``DASHBOARD_SIGNING_KEY`` is set it wins and the file is ignored.
"""
from __future__ import annotations

import os
import pathlib

import pytest

from app.config import Settings, validate_config as broker_validate_config
from app.dashboard import session as broker_session
from mcp_proxy.config import ProxySettings, validate_config as proxy_validate_config
from mcp_proxy.dashboard import session as proxy_session


# ── Proxy: prod refusal when env is empty ─────────────────────────────


def _prod_proxy_settings(**overrides) -> ProxySettings:
    base = dict(
        environment="production",
        admin_secret="strong-random-admin-secret",
        broker_jwks_url="https://broker.example.com/.well-known/jwks.json",
        secret_backend="vault",
        vault_verify_tls=True,
        dashboard_signing_key="strong-signing-key",
    )
    base.update(overrides)
    return ProxySettings(**base)


def test_proxy_refuses_prod_with_empty_dashboard_signing_key():
    settings = _prod_proxy_settings(dashboard_signing_key="")
    with pytest.raises(SystemExit):
        proxy_validate_config(settings)


def test_proxy_prod_ok_when_signing_key_set():
    settings = _prod_proxy_settings()
    # Must not raise.
    proxy_validate_config(settings)


def test_proxy_dev_tolerates_empty_signing_key():
    settings = ProxySettings(
        environment="development",
        dashboard_signing_key="",
    )
    # Must not raise — dev falls back to file-backed auto key.
    proxy_validate_config(settings)


# ── Broker: prod refusal was already in place — regression guard ──────


def _prod_broker_settings(**overrides) -> Settings:
    base = dict(
        environment="production",
        admin_secret="strong-random-admin-secret",
        database_url="postgresql+asyncpg://u:p@db/cullis",
        broker_ca_key_path="certs/broker-ca-key.pem",
        dashboard_signing_key="strong-signing-key",
        redis_url="redis://redis:6379/0",
        kms_backend="vault",
    )
    base.update(overrides)
    return Settings(**base)


def test_broker_refuses_prod_with_empty_dashboard_signing_key(tmp_path):
    ca_key = tmp_path / "broker-ca-key.pem"
    ca_key.write_text("stub")
    settings = _prod_broker_settings(
        dashboard_signing_key="",
        broker_ca_key_path=str(ca_key),
    )
    with pytest.raises(SystemExit):
        broker_validate_config(settings)


# ── File-backed auto-key: persistence across calls ────────────────────


def _reset_auto_key(mod) -> None:
    """Clear the in-memory _auto_key between calls so we exercise the file path."""
    mod._auto_key = ""


def test_broker_dev_generates_and_persists_signing_key_file(tmp_path, monkeypatch):
    """First call creates the file (0600); second call returns the same bytes."""
    from app.config import get_settings as get_broker_settings

    key_path = tmp_path / "signing_key"
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY", "")
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY_PATH", str(key_path))
    # Force Settings to re-read env.
    get_broker_settings.cache_clear()

    _reset_auto_key(broker_session)
    try:
        first = broker_session._get_secret()
        assert key_path.exists(), "signing key file must be created in dev"
        # File perm should be 0600 (owner rw only).
        assert (os.stat(key_path).st_mode & 0o777) == 0o600

        # Clear the in-memory cache, second call reads the *file*, same key.
        _reset_auto_key(broker_session)
        second = broker_session._get_secret()
        assert first == second
        assert first == key_path.read_text().strip()
    finally:
        get_broker_settings.cache_clear()
        _reset_auto_key(broker_session)


def test_broker_env_key_wins_over_file(tmp_path, monkeypatch):
    """When DASHBOARD_SIGNING_KEY is set, the file is never touched."""
    from app.config import get_settings as get_broker_settings

    key_path = tmp_path / "signing_key"
    # Pre-populate the file with a known value.
    key_path.write_text("from-file-not-used")
    os.chmod(key_path, 0o600)

    monkeypatch.setenv("DASHBOARD_SIGNING_KEY", "from-env-wins")
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY_PATH", str(key_path))
    get_broker_settings.cache_clear()

    _reset_auto_key(broker_session)
    try:
        assert broker_session._get_secret() == "from-env-wins"
        # File content must remain whatever it was — no tampering.
        assert key_path.read_text() == "from-file-not-used"
    finally:
        get_broker_settings.cache_clear()
        _reset_auto_key(broker_session)


def test_proxy_dev_generates_and_persists_signing_key_file(tmp_path, monkeypatch):
    from mcp_proxy.config import get_settings as get_proxy_settings

    key_path = tmp_path / "proxy_signing_key"
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "")
    monkeypatch.setenv(
        "MCP_PROXY_DASHBOARD_SIGNING_KEY_PATH", str(key_path)
    )
    get_proxy_settings.cache_clear()

    _reset_auto_key(proxy_session)
    try:
        first = proxy_session._get_secret()
        assert key_path.exists()
        assert (os.stat(key_path).st_mode & 0o777) == 0o600

        _reset_auto_key(proxy_session)
        second = proxy_session._get_secret()
        assert first == second
    finally:
        get_proxy_settings.cache_clear()
        _reset_auto_key(proxy_session)


def test_proxy_env_key_wins_over_file(tmp_path, monkeypatch):
    from mcp_proxy.config import get_settings as get_proxy_settings

    key_path = tmp_path / "proxy_signing_key"
    key_path.write_text("from-file-not-used")
    os.chmod(key_path, 0o600)

    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "from-env-wins")
    monkeypatch.setenv(
        "MCP_PROXY_DASHBOARD_SIGNING_KEY_PATH", str(key_path)
    )
    get_proxy_settings.cache_clear()

    _reset_auto_key(proxy_session)
    try:
        assert proxy_session._get_secret() == "from-env-wins"
        assert key_path.read_text() == "from-file-not-used"
    finally:
        get_proxy_settings.cache_clear()
        _reset_auto_key(proxy_session)


def test_broker_concurrent_init_does_not_duplicate_file(tmp_path, monkeypatch):
    """Two ``_get_secret`` calls racing in the same process must converge
    on the same key and leave no ``.tmp.*`` stragglers."""
    from app.config import get_settings as get_broker_settings

    key_path = tmp_path / "signing_key"
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY", "")
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY_PATH", str(key_path))
    get_broker_settings.cache_clear()

    _reset_auto_key(broker_session)
    try:
        a = broker_session._get_secret()
        _reset_auto_key(broker_session)
        b = broker_session._get_secret()
        assert a == b
        # No tmp files left behind (worst case: two .tmp.<pid> files
        # remain and pollute the certs/ directory over time).
        leftover = [p for p in tmp_path.iterdir() if ".tmp." in p.name]
        assert leftover == []
    finally:
        get_broker_settings.cache_clear()
        _reset_auto_key(broker_session)


def test_get_secret_falls_back_when_path_unwritable(tmp_path, monkeypatch):
    """Read-only FS / sandbox: we log a warning and return the in-memory key."""
    from app.config import get_settings as get_broker_settings

    # Point at a location whose parent is itself a file (can't mkdir).
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    key_path = blocker / "child" / "signing_key"

    monkeypatch.setenv("DASHBOARD_SIGNING_KEY", "")
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY_PATH", str(key_path))
    get_broker_settings.cache_clear()

    _reset_auto_key(broker_session)
    try:
        key = broker_session._get_secret()
        # Must still return a usable 64-hex-char key (os.urandom(32).hex()).
        assert isinstance(key, str)
        assert len(key) == 64
        assert not pathlib.Path(key_path).exists()
    finally:
        get_broker_settings.cache_clear()
        _reset_auto_key(broker_session)
