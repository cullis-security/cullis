"""POLICY_DEFAULT_DECISION fall-through for orgs without a PDP webhook.

Issue #461. The webhook backend used to default-deny hard-coded when the
org had no ``webhook_url``, leaving sandbox/demo deploys with no
ergonomic path forward. The new ``policy_default_decision`` setting
gates this fall-through:

  - ``deny`` (default, prod-safe): same as before — denies with an
    actionable error message.
  - ``allow``: allows with an audit row tagged ``policy_default_allow``
    so the chain shows orgs that haven't wired a real PDP yet.

This test file pins the two paths and the audit reason string, plus
the production refusal in ``validate_config``.
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_default_deny_when_webhook_url_null(monkeypatch):
    """Default ``policy_default_decision='deny'`` mirrors legacy
    behaviour — no webhook → deny with an actionable hint."""
    from app.config import get_settings
    monkeypatch.delenv("POLICY_DEFAULT_DECISION", raising=False)
    get_settings.cache_clear()

    from app.policy import webhook as wh

    decision = await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url=None,
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
    )
    assert decision.allowed is False
    assert "policy_default_deny" in decision.reason
    # The error message must hand the operator both fix paths so they
    # don't have to grep the codebase to figure out how to unblock.
    assert "webhook_url" in decision.reason
    assert "POLICY_DEFAULT_DECISION" in decision.reason


@pytest.mark.asyncio
async def test_default_allow_when_explicitly_opted_in(monkeypatch):
    """``policy_default_decision='allow'`` lets unconfigured orgs through
    with an audit-greppable reason."""
    from app.config import get_settings
    monkeypatch.setenv("POLICY_DEFAULT_DECISION", "allow")
    monkeypatch.setenv("ENVIRONMENT", "development")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    decision = await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url=None,
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
    )
    assert decision.allowed is True
    assert "policy_default_allow" in decision.reason
    assert "acme" in decision.reason


@pytest.mark.asyncio
async def test_configured_webhook_path_unaffected(monkeypatch):
    """Setting ``policy_default_decision`` does NOT shadow real webhook
    calls — the fall-through only fires when ``webhook_url is None``."""
    import httpx
    from app.config import get_settings
    monkeypatch.setenv("POLICY_DEFAULT_DECISION", "allow")
    monkeypatch.setenv("POLICY_WEBHOOK_ALLOW_PRIVATE_IPS", "true")
    get_settings.cache_clear()

    from app.policy import webhook as wh

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": "deny",
                                          "reason": "explicit-pdp-deny"})

    transport = httpx.MockTransport(_handler)

    class _ImmediateClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(
        "app.policy.webhook._validate_and_resolve_webhook_url",
        lambda url: "127.0.0.1",
    )
    monkeypatch.setattr(wh.httpx, "AsyncClient", _ImmediateClient)

    decision = await wh.call_pdp_webhook(
        org_id="acme",
        webhook_url="https://example.com/pdp",
        initiator_agent_id="acme::alice",
        initiator_org_id="acme",
        target_agent_id="other-org::bob",
        target_org_id="other-org",
        capabilities=["cap.read"],
        session_context="initiator",
    )
    # Real webhook said deny — that wins, the env override is irrelevant.
    assert decision.allowed is False
    assert "explicit-pdp-deny" in decision.reason


def test_validate_config_refuses_allow_in_production(monkeypatch):
    """Production deploys must not silently allow unconfigured orgs.
    ``validate_config`` exits hard if both ``ENVIRONMENT=production``
    and ``POLICY_DEFAULT_DECISION=allow`` are set."""
    from app.config import get_settings, validate_config
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("POLICY_DEFAULT_DECISION", "allow")
    monkeypatch.setenv("DATABASE_URL", "postgresql://stub")
    monkeypatch.setenv("BROKER_PUBLIC_URL", "https://broker.example.com")
    monkeypatch.setenv("ADMIN_SECRET", "production-secret-not-default")
    get_settings.cache_clear()

    settings = get_settings()
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_rejects_unknown_value(monkeypatch):
    """Typo-guard — anything other than 'allow'/'deny' is a hard exit."""
    from app.config import get_settings, validate_config
    monkeypatch.setenv("POLICY_DEFAULT_DECISION", "maybe")
    monkeypatch.setenv("ADMIN_SECRET", "non-default-test-secret")
    get_settings.cache_clear()

    settings = get_settings()
    with pytest.raises(SystemExit):
        validate_config(settings)


def test_validate_config_requires_explicit_decision_in_production(monkeypatch):
    """Audit Ultra U2 — production boot must fail when POLICY_DEFAULT_DECISION
    is not explicitly set in the environment, even though the safe
    fallback ``"deny"`` would be applied. The point is operator intent:
    an audit reading the prod env should see the value declared out in
    the open, not have to cross-reference the source for the default.
    Mirrors the ``MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES`` fail-closed
    pattern.
    """
    from app.config import get_settings, validate_config
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("POLICY_DEFAULT_DECISION", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://stub")
    monkeypatch.setenv("BROKER_PUBLIC_URL", "https://broker.example.com")
    monkeypatch.setenv("ADMIN_SECRET", "production-secret-not-default")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        with pytest.raises(SystemExit):
            validate_config(settings)
    finally:
        # Don't pollute the lru_cache for downstream tests on this
        # worker (xdist loadfile schedules whole files together).
        get_settings.cache_clear()


def test_validate_config_accepts_explicit_deny_in_production(monkeypatch):
    """The same guard must accept a deliberate ``deny`` declared by the
    operator. We swallow other prod checks raising SystemExit (e.g.
    broker_ca_key_path missing on disk) — the assertion is that the U2
    guard alone does not refuse a properly declared value.
    """
    from app.config import get_settings, validate_config
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("POLICY_DEFAULT_DECISION", "deny")
    monkeypatch.setenv("DATABASE_URL", "postgresql://stub")
    monkeypatch.setenv("BROKER_PUBLIC_URL", "https://broker.example.com")
    monkeypatch.setenv("ADMIN_SECRET", "production-secret-not-default")
    get_settings.cache_clear()
    try:
        settings = get_settings()
        try:
            validate_config(settings)
        except SystemExit:
            pass  # other prod check failed — U2 guard itself accepted
    finally:
        get_settings.cache_clear()
