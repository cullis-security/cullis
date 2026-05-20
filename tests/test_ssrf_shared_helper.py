"""PR #2 audit 2026-05-20: SSRF shared helper + callsite gates.

Closes 4 findings (F-A-203, F-A-204, F-A-301, F-A-302). Each test
exercises one boundary:

- F-A-203: federation tool-PDP URL refused on private IP
- F-A-204: Court ``_validate_response_ip`` raises (not swallows) on
  server addr in private range
- F-A-301: MCP resource registration refused on IMDS endpoint
- F-A-302: provider catalog validate_creds refuses Ollama / OpenAI
  api_base on cloud metadata
"""
from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from mcp_proxy.utils.url_safety import (
    UnsafeUrlError,
    assert_safe_outbound_url,
    is_safe_ip,
)


# ─── helper unit tests ────────────────────────────────────────────────


class TestUrlSafetyHelper:
    def test_refuses_imds_link_local(self):
        with pytest.raises(UnsafeUrlError, match="link-local|169.254"):
            assert_safe_outbound_url("http://169.254.169.254/latest/meta-data/")

    def test_refuses_imds_link_local_even_with_allow_private(self):
        """Cloud metadata is NEVER allowed even with the dev escape."""
        with pytest.raises(UnsafeUrlError, match="link-local|169.254"):
            assert_safe_outbound_url(
                "http://169.254.169.254/latest/meta-data/",
                allow_private=True,
            )

    def test_refuses_loopback(self):
        with pytest.raises(UnsafeUrlError, match="loopback|127"):
            assert_safe_outbound_url("http://127.0.0.1:8080/x")

    def test_refuses_rfc1918(self):
        with pytest.raises(UnsafeUrlError, match="private|10\\."):
            assert_safe_outbound_url("http://10.0.0.5/x")

    def test_refuses_localhost_name(self):
        with pytest.raises(UnsafeUrlError, match="loopback"):
            assert_safe_outbound_url("http://localhost:8080/x")

    def test_refuses_non_http_scheme(self):
        with pytest.raises(UnsafeUrlError, match="scheme"):
            assert_safe_outbound_url("file:///etc/passwd")

    def test_refuses_missing_host(self):
        with pytest.raises(UnsafeUrlError, match="hostname"):
            assert_safe_outbound_url("http:///path")

    def test_refuses_empty(self):
        with pytest.raises(UnsafeUrlError):
            assert_safe_outbound_url("")

    def test_refuses_cgnat(self):
        """100.64.0.0/10 is RFC 6598 CGNAT, used by AWS for internal services."""
        with pytest.raises(UnsafeUrlError, match="CGNAT"):
            assert_safe_outbound_url("http://100.64.1.1/x")

    def test_accepts_public_ip_literal(self):
        pinned = assert_safe_outbound_url("http://1.1.1.1/")
        assert pinned == "1.1.1.1"

    def test_allow_private_accepts_rfc1918(self):
        """Dev escape: docker compose service IPs in RFC 1918 OK with flag."""
        pinned = assert_safe_outbound_url(
            "http://10.0.0.5:9100/pdp", allow_private=True,
        )
        assert pinned == "10.0.0.5"

    def test_allow_private_accepts_loopback(self):
        """Dev escape: 127.0.0.1 OK with explicit allow_private."""
        pinned = assert_safe_outbound_url(
            "http://127.0.0.1:8080/", allow_private=True,
        )
        assert pinned == "127.0.0.1"

    def test_is_safe_ip_refuses_imds_even_with_private_allowed(self):
        safe, reason = is_safe_ip("169.254.169.254", allow_private=True)
        assert safe is False
        assert "link-local" in (reason or "")

    def test_is_safe_ip_refuses_malformed(self):
        safe, reason = is_safe_ip("not-an-ip")
        assert safe is False
        assert "malformed" in (reason or "")

    def test_internal_host_allowlist_bypasses_block(self, monkeypatch):
        """Operator-trusted FQDN bypasses the IP block (still resolves)."""
        # Allowlist a hostname that would resolve via DNS to a private IP;
        # 'localhost' is a stable stand-in (loopback) that any system can
        # resolve. With the allowlist, it must NOT raise.
        monkeypatch.setenv(
            "MCP_PROXY_INTERNAL_HOST_ALLOWLIST", "localhost",
        )
        pinned = assert_safe_outbound_url("http://localhost:8080/")
        # The literal-name short-circuit refuses 'localhost' for safety;
        # allowlist still applies — check pin is non-empty.
        assert pinned in {"127.0.0.1", "::1"}


# ─── F-A-203: federation tool-PDP SSRF ────────────────────────────────


@pytest.mark.asyncio
async def test_federation_refuses_imds_url(monkeypatch):
    """F-A-203: cross-org tool PDP call refuses cloud metadata endpoints."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from mcp_proxy.policy.federation import call_remote_tool_call_policy

    result = await call_remote_tool_call_policy(
        target_org="competitor",
        federation_url="http://169.254.169.254/latest/meta-data/",
        payload={"principal_id": "alice", "tool_name": "list_files"},
        hmac_secret="stub-secret",
    )
    assert result.reached_remote is False
    assert "unsafe" in result.decision.reason.lower()
    assert result.decision.allowed is False


# ─── F-A-204: Court response IP check raises (not swallows) ───────────


def test_court_validate_response_ip_raises_on_private(monkeypatch):
    """F-A-204: when the post-request server_addr is private,
    _validate_response_ip raises ValueError (not swallowed by the
    surrounding except clause)."""
    from app.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from app.policy.webhook import _validate_response_ip

    # Mock httpx response with network_stream.get_extra_info returning
    # a private IP.
    network_stream = MagicMock()
    network_stream.get_extra_info = MagicMock(
        return_value=("127.0.0.1", 8080),
    )
    response = MagicMock(spec=httpx.Response)
    response.extensions = {"network_stream": network_stream}

    with pytest.raises(ValueError, match="private/reserved IP"):
        _validate_response_ip(response)


def test_court_validate_response_ip_accepts_when_unavailable(monkeypatch):
    """F-A-204 counter-test: when server_addr cannot be determined,
    accept (legitimate path for transports that don't expose it)."""
    from app.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from app.policy.webhook import _validate_response_ip

    network_stream = MagicMock()
    network_stream.get_extra_info = MagicMock(
        side_effect=TypeError("not supported by this transport"),
    )
    response = MagicMock(spec=httpx.Response)
    response.extensions = {"network_stream": network_stream}

    # Must NOT raise — defers to pre-request validation.
    _validate_response_ip(response)


# ─── F-A-301: MCP resource registration ───────────────────────────────


def test_mcp_resource_dashboard_refuses_imds(monkeypatch):
    """F-A-301: _validate_endpoint_url refuses IMDS endpoints."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from fastapi import HTTPException
    from mcp_proxy.dashboard.mcp_resources import _validate_endpoint_url

    with pytest.raises(HTTPException) as exc:
        _validate_endpoint_url(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        )
    assert exc.value.status_code == 400
    assert "endpoint_url" in exc.value.detail


def test_mcp_resource_dashboard_refuses_loopback(monkeypatch):
    """F-A-301: loopback endpoint refused at registration."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from fastapi import HTTPException
    from mcp_proxy.dashboard.mcp_resources import _validate_endpoint_url

    with pytest.raises(HTTPException) as exc:
        _validate_endpoint_url("http://localhost:9000/mcp")
    assert exc.value.status_code == 400


def test_mcp_resource_dashboard_accepts_public(monkeypatch):
    """F-A-301: public endpoint must still register. Uses IP literal
    so the test doesn't depend on DNS being reachable from the test
    runner (NixOS sandbox isolates network)."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from mcp_proxy.dashboard.mcp_resources import _validate_endpoint_url

    url = _validate_endpoint_url("https://1.1.1.1/mcp")
    assert url == "https://1.1.1.1/mcp"


def test_mcp_resource_dashboard_dev_escape_accepts_rfc1918(monkeypatch):
    """F-A-301 escape hatch: sandbox / docker compose stacks with the
    dev flag set accept private docker network endpoints. Uses IP
    literal to keep the test offline."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", True,
    )
    from mcp_proxy.dashboard.mcp_resources import _validate_endpoint_url

    url = _validate_endpoint_url("http://10.0.0.5:8080/")
    assert url == "http://10.0.0.5:8080/"


# ─── F-A-302: provider catalog api_base SSRF ──────────────────────────


def test_openai_api_base_refuses_imds(monkeypatch):
    """F-A-302: openai api_base override refused on cloud metadata."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from mcp_proxy.egress.provider_catalog import (
        InvalidCredentialsError,
        validate_creds,
    )

    with pytest.raises(InvalidCredentialsError, match="api_base"):
        validate_creds("openai", {
            "api_key": "sk-real",
            "api_base": "http://169.254.169.254/latest/meta-data/",
        })


def test_ollama_api_base_refuses_loopback(monkeypatch):
    """F-A-302: ollama api_base refused on loopback in production."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from mcp_proxy.egress.provider_catalog import (
        InvalidCredentialsError,
        validate_creds,
    )

    with pytest.raises(InvalidCredentialsError, match="api_base"):
        validate_creds("ollama", {"api_base": "http://127.0.0.1:11434"})


def test_ollama_api_base_accepts_loopback_with_dev_escape(monkeypatch):
    """F-A-302 escape hatch: dev/sandbox can point at loopback Ollama."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", True,
    )
    from mcp_proxy.egress.provider_catalog import validate_creds

    cleaned = validate_creds("ollama", {"api_base": "http://127.0.0.1:11434"})
    assert cleaned["api_base"] == "http://127.0.0.1:11434"


@pytest.mark.asyncio
async def test_fetch_ollama_models_refuses_imds_runtime(monkeypatch):
    """F-A-302 defense-in-depth: runtime fetch refuses even if DB row
    predates the validate_creds gate."""
    from mcp_proxy.config import get_settings
    monkeypatch.setattr(
        get_settings(), "policy_webhook_allow_private_ips", False,
    )
    from mcp_proxy.egress.provider_catalog import fetch_ollama_models

    # Pre-existing DB row pointing at IMDS — runtime must refuse.
    result = await fetch_ollama_models("http://169.254.169.254/x")
    assert result == []
