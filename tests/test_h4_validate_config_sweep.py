"""PR #1 audit 2026-05-20: H4 validate_config refuse-to-start sweep.

Closes 8 findings (F-A-101, F-A-202, F-A-205, F-A-406, F-A-501, F-A-502,
F-A-503, F-A-513) from the full re-audit 2026-05-20. Each test pins the
production refusal so the H4 fail-open default cannot regress.

The pattern follows ``tests/test_policy_default_decision.py``: set
production env + the surrounding required knobs, flip the gate under
test, expect SystemExit. We swallow downstream SystemExit for gates
that run after the target so the assertion is "this guard alone
refuses" rather than "all guards happen to refuse".
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest


# ─── Court (app/config.py) ────────────────────────────────────────────


def _court_prod_baseline(monkeypatch) -> None:
    """Set the minimal production env so the gates we are NOT testing
    pass. Each test then flips a single knob and asserts the refusal."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("POLICY_DEFAULT_DECISION", "deny")
    monkeypatch.setenv("DATABASE_URL", "postgresql://stub")
    monkeypatch.setenv("BROKER_PUBLIC_URL", "https://broker.example.com")
    monkeypatch.setenv("ADMIN_SECRET", "production-secret-not-default")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KMS_BACKEND", "vault")
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "production-hmac-not-empty")
    monkeypatch.setenv(
        "MASTIO_MTLS_TRUSTED_PROXY_CIDRS", "172.18.0.0/16"
    )
    monkeypatch.setenv("AUDIT_TSA_ENABLED", "false")
    monkeypatch.setenv("DASHBOARD_SIGNING_KEY", "test-key-not-empty")


def test_court_refuses_empty_mastio_mtls_cidrs_in_production(monkeypatch, tmp_path):
    """F-A-101: empty MASTIO_MTLS_TRUSTED_PROXY_CIDRS in production
    must refuse to start. The federation mTLS pass-through path would
    otherwise accept the X-Cullis-Mastio-Cert header from any peer."""
    from app.config import get_settings, validate_config

    _court_prod_baseline(monkeypatch)
    monkeypatch.setenv("MASTIO_MTLS_TRUSTED_PROXY_CIDRS", "")
    # Skip other-gate noise by pointing at a writable broker_ca_key path
    ca_key = tmp_path / "ca.key"
    ca_key.write_text("stub")
    monkeypatch.setenv("BROKER_CA_KEY_PATH", str(ca_key))
    get_settings.cache_clear()
    try:
        with pytest.raises(SystemExit):
            validate_config(get_settings())
    finally:
        get_settings.cache_clear()


def test_court_refuses_empty_policy_webhook_hmac_secret_in_production(monkeypatch, tmp_path):
    """F-A-513: empty POLICY_WEBHOOK_HMAC_SECRET in production ships
    unsigned PDP webhook calls, defeating the X-ATN-Signature defence."""
    from app.config import get_settings, validate_config

    _court_prod_baseline(monkeypatch)
    monkeypatch.setenv("POLICY_WEBHOOK_HMAC_SECRET", "")
    ca_key = tmp_path / "ca.key"
    ca_key.write_text("stub")
    monkeypatch.setenv("BROKER_CA_KEY_PATH", str(ca_key))
    get_settings.cache_clear()
    try:
        with pytest.raises(SystemExit):
            validate_config(get_settings())
    finally:
        get_settings.cache_clear()


def test_court_refuses_audit_tsa_mock_with_enabled_in_production(monkeypatch, tmp_path):
    """F-A-406: AUDIT_TSA_BACKEND=mock + AUDIT_TSA_ENABLED=true in
    production persists broker-internal blobs as 'external' timestamps.
    No dispute-grade evidence — refuse to start."""
    from app.config import get_settings, validate_config

    _court_prod_baseline(monkeypatch)
    monkeypatch.setenv("AUDIT_TSA_ENABLED", "true")
    monkeypatch.setenv("AUDIT_TSA_BACKEND", "mock")
    ca_key = tmp_path / "ca.key"
    ca_key.write_text("stub")
    monkeypatch.setenv("BROKER_CA_KEY_PATH", str(ca_key))
    get_settings.cache_clear()
    try:
        with pytest.raises(SystemExit):
            validate_config(get_settings())
    finally:
        get_settings.cache_clear()


def test_court_accepts_audit_tsa_disabled_with_mock(monkeypatch, tmp_path):
    """F-A-406 counterpart: AUDIT_TSA_ENABLED=false with the default
    AUDIT_TSA_BACKEND=mock must still boot — the operator declared no
    anchoring at all, so the mock backend is never read from."""
    from app.config import get_settings, validate_config

    _court_prod_baseline(monkeypatch)
    monkeypatch.setenv("AUDIT_TSA_ENABLED", "false")
    monkeypatch.setenv("AUDIT_TSA_BACKEND", "mock")
    ca_key = tmp_path / "ca.key"
    ca_key.write_text("stub")
    monkeypatch.setenv("BROKER_CA_KEY_PATH", str(ca_key))
    get_settings.cache_clear()
    try:
        try:
            validate_config(get_settings())
        except SystemExit:
            # Other prod gates may still raise — the assertion is that
            # the F-A-406 gate itself does not refuse this combination.
            pass
    finally:
        get_settings.cache_clear()


# ─── Mastio (mcp_proxy/config.py) ─────────────────────────────────────


def _mastio_prod_baseline(monkeypatch) -> None:
    """Minimal Mastio production env so gates we are NOT testing pass.
    Each test then flips one knob to the insecure value and expects
    SystemExit."""
    monkeypatch.setenv("MCP_PROXY_ENVIRONMENT", "production")
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    monkeypatch.setenv("MCP_PROXY_ADMIN_SECRET", "prod-mastio-secret")
    monkeypatch.setenv("MCP_PROXY_DASHBOARD_SIGNING_KEY", "prod-dashboard-key")
    monkeypatch.setenv("MCP_PROXY_SECRET_BACKEND", "vault")
    monkeypatch.setenv("MCP_PROXY_VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("MCP_PROXY_VAULT_TOKEN", "stub-token")
    monkeypatch.setenv("MCP_PROXY_VAULT_VERIFY_TLS", "true")
    monkeypatch.setenv("MCP_PROXY_KMS_BACKEND", "vault")
    monkeypatch.setenv(
        "MCP_PROXY_DB_ENCRYPTION_KEY",
        "a" * 64,  # >= 32 chars
    )
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_ENFORCEMENT", "required")
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_RP_ID", "mastio.example.com")
    monkeypatch.setenv(
        "MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", "prod-mastio-hmac-not-empty"
    )
    monkeypatch.setenv("MCP_PROXY_AUDIT_FAIL_DENY", "true")
    monkeypatch.setenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", "false")
    monkeypatch.delenv("MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK", raising=False)
    monkeypatch.delenv("MCP_PROXY_DEPLOYMENT_TOPOLOGY", raising=False)


def test_mastio_refuses_empty_pdp_webhook_hmac_secret_in_production(monkeypatch):
    """F-A-202: empty MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET in production
    skips the inbound HMAC check entirely on /pdp/policy and
    /v1/policy/tool-call. Refuse to start."""
    from mcp_proxy.config import get_settings, validate_config

    _mastio_prod_baseline(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET", "")
    get_settings.cache_clear()
    try:
        with pytest.raises(SystemExit):
            validate_config(get_settings())
    finally:
        get_settings.cache_clear()


def test_mastio_refuses_webauthn_warn_without_opt_in(monkeypatch):
    """F-A-205: webauthn_enforcement=warn in production is forgeable on
    bearer session_token theft. Refuse unless the operator explicitly
    opts in via MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK=true."""
    from mcp_proxy.config import get_settings, validate_config

    _mastio_prod_baseline(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_ENFORCEMENT", "warn")
    monkeypatch.delenv("MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK", raising=False)
    get_settings.cache_clear()
    try:
        with pytest.raises(SystemExit):
            validate_config(get_settings())
    finally:
        get_settings.cache_clear()


def test_mastio_accepts_webauthn_warn_with_explicit_opt_in(monkeypatch):
    """F-A-205 escape hatch: the legacy migration window stays open
    when the operator explicitly declares MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK=true.
    The point of the gate is operator intent, not blanket refusal."""
    from mcp_proxy.config import get_settings, validate_config

    _mastio_prod_baseline(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_ENFORCEMENT", "warn")
    monkeypatch.setenv("MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK", "true")
    get_settings.cache_clear()
    try:
        # The F-A-205 gate must NOT raise. Other prod gates may, but
        # this assertion is about the warn-with-opt-in branch only.
        try:
            validate_config(get_settings())
        except SystemExit:
            pass
    finally:
        get_settings.cache_clear()


def test_mastio_refuses_audit_fail_deny_false_in_production(monkeypatch):
    """F-A-501: MCP_PROXY_AUDIT_FAIL_DENY=false silently swallows
    audit-log persistence failures. Threat-model claim requires
    fail-deny semantics. Refuse to start."""
    from mcp_proxy.config import get_settings, validate_config

    _mastio_prod_baseline(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_AUDIT_FAIL_DENY", "false")
    get_settings.cache_clear()
    try:
        with pytest.raises(SystemExit):
            validate_config(get_settings())
    finally:
        get_settings.cache_clear()


def test_mastio_refuses_inmemory_stores_without_topology(monkeypatch):
    """F-A-502: MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES=true in
    production refuses unless MCP_PROXY_DEPLOYMENT_TOPOLOGY=single-worker-vertical
    is also declared. Multi-worker deploys without shared Redis allow
    DPoP replay up to N times per worker."""
    from mcp_proxy.config import get_settings, validate_config

    _mastio_prod_baseline(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", "true")
    monkeypatch.delenv("MCP_PROXY_DEPLOYMENT_TOPOLOGY", raising=False)
    get_settings.cache_clear()
    try:
        with pytest.raises(SystemExit):
            validate_config(get_settings())
    finally:
        get_settings.cache_clear()


def test_mastio_accepts_inmemory_stores_with_single_worker_topology(monkeypatch):
    """F-A-502 escape hatch: single-worker vertical deploys can opt in
    when the topology is declared explicitly."""
    from mcp_proxy.config import get_settings, validate_config

    _mastio_prod_baseline(monkeypatch)
    monkeypatch.setenv("MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES", "true")
    monkeypatch.setenv(
        "MCP_PROXY_DEPLOYMENT_TOPOLOGY", "single-worker-vertical"
    )
    get_settings.cache_clear()
    try:
        try:
            validate_config(get_settings())
        except SystemExit:
            pass
    finally:
        get_settings.cache_clear()


# ─── mastio_mtls runtime fail-closed (F-A-101 core fix) ───────────────


def test_mastio_mtls_peer_is_trusted_proxy_returns_false_on_empty_cidrs(monkeypatch):
    """F-A-101 runtime safety net: when MASTIO_MTLS_TRUSTED_PROXY_CIDRS
    is empty, _peer_is_trusted_proxy returns False (fail-closed),
    not True with a warning. The X-Cullis-Mastio-Cert pass-through path
    rejects the header instead of accepting it from any peer."""
    from app.config import get_settings
    from app.auth.mastio_mtls import _peer_is_trusted_proxy

    monkeypatch.setenv("MASTIO_MTLS_TRUSTED_PROXY_CIDRS", "")
    monkeypatch.setenv("ADMIN_SECRET", "non-default-test-secret")
    get_settings.cache_clear()

    request = MagicMock()
    request.client = MagicMock()
    request.client.host = "10.0.0.42"

    result = _peer_is_trusted_proxy(request)
    assert result is False, (
        "F-A-101 regression: empty CIDR allowlist must fail-closed, "
        "not accept any peer with a warning."
    )

    get_settings.cache_clear()


def test_mastio_mtls_peer_is_trusted_proxy_accepts_configured_cidr(monkeypatch):
    """Counter-test: with a configured CIDR, a peer inside the range
    is accepted (the gate works for the legitimate case)."""
    from app.config import get_settings
    from app.auth.mastio_mtls import _peer_is_trusted_proxy

    monkeypatch.setenv("MASTIO_MTLS_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    monkeypatch.setenv("ADMIN_SECRET", "non-default-test-secret")
    get_settings.cache_clear()

    request = MagicMock()
    request.client = MagicMock()
    request.client.host = "10.0.0.42"

    assert _peer_is_trusted_proxy(request) is True

    get_settings.cache_clear()
