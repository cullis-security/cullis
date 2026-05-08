"""Regression tests for the SDK MCP server TLS verification default.

Closes audit finding U1 (Ultra Plan 2026-05-08): the MCP server wrapper used
to construct CullisClient with ``verify_tls=False`` hardcoded, exposing the
LLM-driven agent-host integration to MITM on the broker connection. The fix
defaults to ``verify_tls=True`` and only opts out when CULLIS_MCP_VERIFY_TLS
is explicitly set to a falsy string.
"""
from __future__ import annotations

import importlib

import pytest


def _reload_mcp_server():
    """Re-import the module so it picks up env at decision time."""
    import cullis_sdk.mcp_server as mod

    return importlib.reload(mod)


@pytest.fixture
def fake_client_class(monkeypatch):
    """Patch CullisClient inside the mcp_server module and capture call kwargs."""
    captured: dict = {}

    class _FakeClient:
        def __init__(self, broker, *, verify_tls=True, timeout=10.0):
            captured["broker"] = broker
            captured["verify_tls"] = verify_tls
            captured["timeout"] = timeout
            self.token = None  # avoids _get_client tripping later

        def login(self, *_a, **_kw):
            self.token = "stub"

        def login_from_pem(self, *_a, **_kw):
            self.token = "stub"

    mod = _reload_mcp_server()
    monkeypatch.setattr(mod, "CullisClient", _FakeClient)
    monkeypatch.setattr(mod, "_client", None, raising=False)
    return mod, captured


def test_default_verify_tls_is_true(fake_client_class, monkeypatch, tmp_path):
    """No env var set → CullisClient must be constructed with verify_tls=True."""
    monkeypatch.delenv("CULLIS_MCP_VERIFY_TLS", raising=False)

    cert = tmp_path / "agent.crt"
    cert.write_text("PEM")
    key = tmp_path / "agent.key"
    key.write_text("PEM")

    mod, captured = fake_client_class
    result = mod.cullis_connect(
        broker_url="https://broker.test",
        agent_id="orga::agent-a",
        org_id="orga",
        cert_path=str(cert),
        key_path=str(key),
    )

    assert "Connected" in result, result
    assert captured["verify_tls"] is True


@pytest.mark.parametrize("disable_value", ["false", "FALSE", "0", "no", "No"])
def test_env_disables_verify_tls(fake_client_class, monkeypatch, tmp_path, disable_value, capsys):
    """CULLIS_MCP_VERIFY_TLS in {false,0,no} (case-insensitive) opts out."""
    monkeypatch.setenv("CULLIS_MCP_VERIFY_TLS", disable_value)

    cert = tmp_path / "agent.crt"
    cert.write_text("PEM")
    key = tmp_path / "agent.key"
    key.write_text("PEM")

    mod, captured = fake_client_class
    mod.cullis_connect(
        broker_url="https://broker.test",
        agent_id="orga::agent-a",
        org_id="orga",
        cert_path=str(cert),
        key_path=str(key),
    )

    assert captured["verify_tls"] is False
    captured_streams = capsys.readouterr()
    assert "CULLIS_MCP_VERIFY_TLS is disabled" in captured_streams.err


@pytest.mark.parametrize("truthy_value", ["true", "1", "yes", "", "  ", "garbage"])
def test_non_falsy_env_keeps_verify_tls_on(fake_client_class, monkeypatch, tmp_path, truthy_value):
    """Anything not in {false,0,no} (case-insensitive) → verify_tls stays True."""
    monkeypatch.setenv("CULLIS_MCP_VERIFY_TLS", truthy_value)

    cert = tmp_path / "agent.crt"
    cert.write_text("PEM")
    key = tmp_path / "agent.key"
    key.write_text("PEM")

    mod, captured = fake_client_class
    mod.cullis_connect(
        broker_url="https://broker.test",
        agent_id="orga::agent-a",
        org_id="orga",
        cert_path=str(cert),
        key_path=str(key),
    )

    assert captured["verify_tls"] is True
