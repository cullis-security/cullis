"""Regression: pydantic must tolerate docker-compose's `${VAR:-}` empty string.

The Mastio bundle's ``docker-compose.yml`` exposes the customer-facing
bool flags via ``${MCP_PROXY_TOOL_PDP_ENABLED:-}`` etc., which compose
substitutes to the empty string when the operator hasn't set the var
in proxy.env. Pydantic v2's bool parser rejects ``""`` with
``bool_parsing`` ValidationError, which used to crash the container at
startup and surface in CI as ``mcp-proxy is unhealthy``.

The :class:`ProxySettings` field validator
``_empty_bool_str_to_false`` maps ``""`` → ``False`` for the three
bundle-exposed flags so the customer demo boots regardless of whether
the operator set the values. The ``_apply_routing_overrides``
model-validator re-reads via ``_env()`` (which also treats ``""`` as
None) so the standalone auto-flip for ``local_auth_enabled`` keeps
firing.

VM dogfood 2026-05-12: customer-path smoke turned red on PR #658
because empty-string env from the new mappings crashed pydantic
before the post-init logic could even run.
"""
from __future__ import annotations

import importlib

import pytest


def _reload_settings(monkeypatch, **env):
    """Force a fresh ProxySettings() against the requested env."""
    for k in (
        "MCP_PROXY_TOOL_PDP_ENABLED",
        "MCP_PROXY_FORCE_LOCAL_PASSWORD",
        "MCP_PROXY_LOCAL_AUTH_ENABLED",
        "MCP_PROXY_STANDALONE",
        "MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET",
        "PROXY_LOCAL_AUTH",
    ):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    config = importlib.import_module("mcp_proxy.config")
    return config.ProxySettings()


def test_empty_bool_env_falls_back_to_default(monkeypatch):
    """compose substitutes ${VAR:-} → "" when proxy.env omits the var.

    Before the fix this raised ValidationError and the container died.
    Now the validator collapses empty to False and pydantic accepts it.
    """
    settings = _reload_settings(
        monkeypatch,
        MCP_PROXY_TOOL_PDP_ENABLED="",
        MCP_PROXY_FORCE_LOCAL_PASSWORD="",
        MCP_PROXY_LOCAL_AUTH_ENABLED="",
    )
    assert settings.tool_pdp_enabled is False
    assert settings.force_local_password is False


def test_standalone_auto_flip_survives_empty_local_auth_env(monkeypatch):
    """The bundle customer-demo runs in standalone mode and relies on
    the post-init auto-flip to enable local auth. Empty string from
    compose must NOT block the auto-flip (the previous code path
    treated empty as "not set", and the new validator must not break
    that contract).
    """
    settings = _reload_settings(
        monkeypatch,
        MCP_PROXY_STANDALONE="true",
        MCP_PROXY_LOCAL_AUTH_ENABLED="",
        MCP_PROXY_TOOL_PDP_ENABLED="",
        MCP_PROXY_FORCE_LOCAL_PASSWORD="",
    )
    # Standalone mode set + operator did not opt out → auto-flip wins.
    assert settings.standalone is True
    assert settings.local_auth_enabled is True


def test_explicit_true_propagates(monkeypatch):
    settings = _reload_settings(
        monkeypatch,
        MCP_PROXY_TOOL_PDP_ENABLED="true",
        MCP_PROXY_FORCE_LOCAL_PASSWORD="true",
        MCP_PROXY_LOCAL_AUTH_ENABLED="true",
    )
    assert settings.tool_pdp_enabled is True
    assert settings.force_local_password is True
    assert settings.local_auth_enabled is True


def test_explicit_false_propagates(monkeypatch):
    """Regression: ``MCP_PROXY_LOCAL_AUTH_ENABLED=false`` set explicitly
    means "operator chose to disable local auth". Standalone mode must
    NOT auto-flip the value back to True — the operator's explicit
    opt-out wins. The ``_env()`` helper accomplishes this by returning
    the literal string ``"false"`` (not None) so the standalone branch
    is skipped.
    """
    settings = _reload_settings(
        monkeypatch,
        MCP_PROXY_STANDALONE="true",
        MCP_PROXY_LOCAL_AUTH_ENABLED="false",
    )
    assert settings.standalone is True
    assert settings.local_auth_enabled is False
