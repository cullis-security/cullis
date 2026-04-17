"""Audit F-E-01 + F-E-02 — proxy must verify TLS for broker and Vault.

These tests lock in the post-fix behaviour:

1. ``validate_config`` refuses to start in ``environment=production`` when
   either ``MCP_PROXY_BROKER_VERIFY_TLS`` or ``MCP_PROXY_VAULT_VERIFY_TLS``
   is disabled. Development mode keeps allowing the opt-out (self-signed
   sandboxes still need it).
2. The Vault helpers in the dashboard router and the agent manager pass
   the configured ``verify=`` kwarg into ``httpx.AsyncClient`` instead of
   the previously hardcoded ``verify=False``.
3. ``broker_tls_verify`` / ``vault_tls_verify`` honour the CA-cert-path
   override when set, falling back to the boolean flag otherwise.

The broker-facing call sites (dashboard setup wizard, AgentManager
deactivate / register) reuse the same helper, so the unit coverage
around the helper plus the assertion in ``validate_config`` is what the
audit actually requires — no need to instantiate the full lifespan.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mcp_proxy.config import (
    ProxySettings,
    broker_tls_verify,
    validate_config,
    vault_tls_verify,
)


# ── validate_config production guards ───────────────────────────────

def _prod_settings(**overrides) -> ProxySettings:
    """Build a ProxySettings that passes every other production check."""
    base = dict(
        environment="production",
        admin_secret="strong-random-admin-secret",
        broker_jwks_url="https://broker.example.com/.well-known/jwks.json",
        standalone=False,
    )
    base.update(overrides)
    return ProxySettings(**base)


def test_validate_config_rejects_prod_with_broker_verify_disabled():
    settings = _prod_settings(broker_verify_tls=False)
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_rejects_prod_with_vault_verify_disabled():
    settings = _prod_settings(secret_backend="vault", vault_verify_tls=False)
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_allows_prod_with_verify_enabled():
    settings = _prod_settings(
        secret_backend="vault",
        broker_verify_tls=True,
        vault_verify_tls=True,
    )
    # Must not raise.
    validate_config(settings)


def test_validate_config_ignores_vault_flag_when_backend_is_env():
    """If secret_backend=env we never talk to Vault, so the vault flag is
    advisory — in development the configuration must boot. In production
    the env backend itself is refused by audit F-E-03 (keeps private keys
    at rest in the process environment), which is covered by
    ``test_validate_config_refuses_env_backend_in_prod`` below."""
    settings = ProxySettings(
        environment="development",
        secret_backend="env",
        vault_verify_tls=False,
    )
    # Must not raise: dev-mode opt-out path.
    validate_config(settings)


def test_validate_config_refuses_env_backend_in_prod():
    """Audit F-E-03: ``env`` stores agent private keys at rest in the
    process environment — production must reject it and point the
    operator at Vault."""
    settings = _prod_settings(secret_backend="env", vault_verify_tls=True)
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_dev_tolerates_disabled_verify():
    """Development keeps the existing opt-out for self-signed sandboxes."""
    settings = ProxySettings(
        environment="development",
        broker_verify_tls=False,
        vault_verify_tls=False,
        secret_backend="vault",
    )
    validate_config(settings)


def test_validate_config_standalone_still_enforces_vault_tls():
    """Standalone mode skips broker checks but a Vault backend is still
    reachable — keep enforcing its TLS in production."""
    settings = ProxySettings(
        environment="production",
        admin_secret="strong-random-admin-secret",
        standalone=True,
        secret_backend="vault",
        vault_verify_tls=False,
    )
    with pytest.raises(SystemExit):
        validate_config(settings)


# ── verify kwarg helpers ────────────────────────────────────────────

def test_broker_tls_verify_defaults_to_true():
    settings = ProxySettings()
    assert broker_tls_verify(settings) is True


def test_broker_tls_verify_honours_false_flag():
    settings = ProxySettings(broker_verify_tls=False)
    assert broker_tls_verify(settings) is False


def test_vault_tls_verify_defaults_to_true():
    settings = ProxySettings()
    assert vault_tls_verify(settings) is True


def test_vault_tls_verify_returns_ca_path_when_set():
    settings = ProxySettings(vault_ca_cert_path="/etc/ssl/vault-ca.pem")
    assert vault_tls_verify(settings) == "/etc/ssl/vault-ca.pem"


def test_vault_tls_verify_ca_path_wins_over_false_flag():
    """CA path pinning must take precedence over the boolean flag so a
    sandbox with a private CA never falls back to ``verify=False``."""
    settings = ProxySettings(
        vault_ca_cert_path="/etc/ssl/vault-ca.pem",
        vault_verify_tls=False,
    )
    assert vault_tls_verify(settings) == "/etc/ssl/vault-ca.pem"


# ── call sites forward the verify kwarg ─────────────────────────────

class _AsyncClientRecorder:
    """Stand-in for ``httpx.AsyncClient`` that captures constructor kwargs
    and returns a minimal context manager with stub get/post/delete."""

    captured_kwargs: dict = {}

    def __init__(self, *args, **kwargs):
        _AsyncClientRecorder.captured_kwargs = kwargs
        self._resp = MagicMock()
        self._resp.status_code = 200
        self._resp.json = MagicMock(return_value={
            "data": {"data": {"key_pem": "PEM"}}
        })
        self._resp.raise_for_status = MagicMock(return_value=None)
        self._resp.is_success = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        return self._resp

    async def post(self, *args, **kwargs):
        return self._resp

    async def delete(self, *args, **kwargs):
        return self._resp


@pytest.mark.asyncio
async def test_store_key_vault_passes_verify_kwarg(monkeypatch):
    """``AgentManager._store_key_vault`` must pass ``verify=`` from settings
    to httpx instead of the hardcoded ``verify=False``."""
    from mcp_proxy import config as proxy_config
    from mcp_proxy.egress import agent_manager as am_mod

    monkeypatch.setattr(am_mod, "httpx", MagicMock(AsyncClient=_AsyncClientRecorder))

    fake_settings = ProxySettings(
        secret_backend="vault",
        vault_addr="https://vault.example.com",
        vault_token="t",
        vault_ca_cert_path="/etc/ssl/vault-ca.pem",
    )
    monkeypatch.setattr(am_mod, "get_settings", lambda: fake_settings)
    monkeypatch.setattr(proxy_config, "get_settings", lambda: fake_settings)

    mgr = am_mod.AgentManager.__new__(am_mod.AgentManager)
    mgr._org_id = "acme"
    await mgr._store_key_vault("agent-1", "KEY_PEM")

    assert _AsyncClientRecorder.captured_kwargs.get("verify") == (
        "/etc/ssl/vault-ca.pem"
    ), (
        "Expected vault_ca_cert_path to be forwarded as verify=, got "
        f"{_AsyncClientRecorder.captured_kwargs!r}"
    )


@pytest.mark.asyncio
async def test_fetch_key_vault_passes_verify_kwarg(monkeypatch):
    """``AgentManager._fetch_key_vault`` must forward ``verify=`` too."""
    from mcp_proxy.egress import agent_manager as am_mod

    monkeypatch.setattr(am_mod, "httpx", MagicMock(AsyncClient=_AsyncClientRecorder))

    fake_settings = ProxySettings(
        secret_backend="vault",
        vault_addr="https://vault.example.com",
        vault_token="t",
        vault_verify_tls=True,
    )
    monkeypatch.setattr(am_mod, "get_settings", lambda: fake_settings)

    mgr = am_mod.AgentManager.__new__(am_mod.AgentManager)
    mgr._org_id = "acme"
    _AsyncClientRecorder.captured_kwargs = {}
    await mgr._fetch_key_vault("agent-1")

    assert _AsyncClientRecorder.captured_kwargs.get("verify") is True


def test_no_hardcoded_verify_false_in_mcp_proxy():
    """Regression guard for F-E-01 / F-E-02: scrub the tree for any
    accidental re-introduction of ``verify=False`` or ``verify_tls=False``
    in shipping proxy code. Tests may legitimately use them on fixtures."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / "mcp_proxy"
    hits: list[str] = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in ("verify=False", "verify_tls=False"):
            if needle in text:
                hits.append(f"{path}: {needle}")
    assert not hits, (
        "TLS verification must stay enforced in mcp_proxy/. Offending "
        f"lines: {hits}"
    )
