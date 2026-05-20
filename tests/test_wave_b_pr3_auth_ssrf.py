"""Wave B PR3 — C2 + B3 + D3 auth/SSRF quick wins.

Audit refs:
  - C2: imp/audits/2026-05-11-track-2-auth.md H4
  - B3: imp/audits/2026-05-11-track-7-owasp-frontend.md M-2
  - D3: imp/audits/2026-05-11-track-3-audit-pdp.md F-4
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest


# ─── C2 — X-Cullis-Mastio-Cert trusted-proxy gate ───


def _stub_request(*, host: str | None = "127.0.0.1", header: str | None = None):
    req = MagicMock()
    req.headers = {}
    if header:
        req.headers["X-Cullis-Mastio-Cert"] = header
    if host is None:
        req.client = None
    else:
        req.client = MagicMock(host=host)
    return req


def test_c2_empty_allowlist_fails_closed(monkeypatch):
    """F-A-101 (audit 2026-05-20): empty allowlist now fails closed.

    Pre-fix: empty allowlist accepted any peer with a warning, which
    let an attacker reaching the broker directly forge the
    ``X-Cullis-Mastio-Cert`` header and bypass the federation mTLS
    layer (SPKI byte-equality against the org's pinned mastio_pubkey
    is trivial when the public key is public material).

    Post-fix: empty allowlist returns False. ``validate_config``
    refuses to start in production when the env is unset; this runtime
    branch is the defense-in-depth safety net for dev/test."""
    from app.config import get_settings
    monkeypatch.setattr(
        get_settings(), "mastio_mtls_trusted_proxy_cidrs", "",
    )
    from app.auth.mastio_mtls import _peer_is_trusted_proxy
    req = _stub_request(host="203.0.113.10")
    assert _peer_is_trusted_proxy(req) is False


def test_c2_allowlist_rejects_non_member(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(
        get_settings(), "mastio_mtls_trusted_proxy_cidrs",
        "172.18.0.0/16",
    )
    from app.auth.mastio_mtls import _peer_is_trusted_proxy
    # Public IP not in 172.18/16 → rejected.
    assert _peer_is_trusted_proxy(_stub_request(host="8.8.8.8")) is False
    # In-CIDR peer → accepted.
    assert _peer_is_trusted_proxy(_stub_request(host="172.18.0.5")) is True


def test_c2_allowlist_handles_multiple_cidrs(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(
        get_settings(), "mastio_mtls_trusted_proxy_cidrs",
        "10.0.0.0/8, 192.168.42.0/24",
    )
    from app.auth.mastio_mtls import _peer_is_trusted_proxy
    assert _peer_is_trusted_proxy(_stub_request(host="10.5.5.5")) is True
    assert _peer_is_trusted_proxy(_stub_request(host="192.168.42.7")) is True
    assert _peer_is_trusted_proxy(_stub_request(host="192.168.43.1")) is False


def test_c2_allowlist_rejects_missing_client(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(
        get_settings(), "mastio_mtls_trusted_proxy_cidrs",
        "10.0.0.0/8",
    )
    from app.auth.mastio_mtls import _peer_is_trusted_proxy
    # No client info → can't prove peer trustedness → fail closed.
    assert _peer_is_trusted_proxy(_stub_request(host=None)) is False


def test_c2_allowlist_skips_malformed_cidr_entries(monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(
        get_settings(), "mastio_mtls_trusted_proxy_cidrs",
        "garbage,10.0.0.0/8",
    )
    from app.auth.mastio_mtls import _peer_is_trusted_proxy
    # Malformed entry skipped; valid 10/8 still matches.
    assert _peer_is_trusted_proxy(_stub_request(host="10.5.5.5")) is True


# ─── B3 — AI provider live-probe allow-list ───


def test_b3_openai_default_allowed_host_passes():
    from mcp_proxy.admin.ai_providers import _enforce_openai_compat_endpoint
    # No raise.
    _enforce_openai_compat_endpoint("https://api.openai.com/v1", allow_byo=False)
    _enforce_openai_compat_endpoint("https://api.anthropic.com/v1", allow_byo=False)


def test_b3_openai_unknown_host_refused_without_byo():
    from mcp_proxy.admin.ai_providers import _enforce_openai_compat_endpoint
    with pytest.raises(ValueError, match="allow-list"):
        _enforce_openai_compat_endpoint(
            "https://attacker.example.com/v1", allow_byo=False,
        )


def test_b3_openai_unknown_host_passes_with_byo_optin():
    from mcp_proxy.admin.ai_providers import _enforce_openai_compat_endpoint
    # Operator explicitly opted into BYO — host check is skipped.
    _enforce_openai_compat_endpoint(
        "https://api.azure-openai.example.com/v1", allow_byo=True,
    )


def test_b3_openai_http_scheme_refused_even_for_default_host():
    from mcp_proxy.admin.ai_providers import _enforce_openai_compat_endpoint
    with pytest.raises(ValueError, match="https"):
        _enforce_openai_compat_endpoint(
            "http://api.openai.com/v1", allow_byo=True,
        )


def test_b3_openai_non_http_scheme_refused():
    from mcp_proxy.admin.ai_providers import _enforce_openai_compat_endpoint
    with pytest.raises(ValueError, match="scheme"):
        _enforce_openai_compat_endpoint(
            "file:///etc/passwd", allow_byo=True,
        )


def test_b3_ollama_self_hosted_rfc1918_allowed():
    from mcp_proxy.admin.ai_providers import _enforce_self_hosted_endpoint
    # Ollama is self-hosted → docker-network IPs are legitimate.
    _enforce_self_hosted_endpoint("http://ollama:11434")
    _enforce_self_hosted_endpoint("http://172.18.0.5:11434")


def test_b3_ollama_refuses_non_http_scheme():
    from mcp_proxy.admin.ai_providers import _enforce_self_hosted_endpoint
    with pytest.raises(ValueError, match="scheme"):
        _enforce_self_hosted_endpoint("file:///root/ollama")


def test_b3_ollama_refuses_no_hostname():
    from mcp_proxy.admin.ai_providers import _enforce_self_hosted_endpoint
    with pytest.raises(ValueError, match="hostname"):
        _enforce_self_hosted_endpoint("http:///")


def test_b3_byo_endpoint_env_var_is_explicit_optin(monkeypatch):
    monkeypatch.delenv("MCP_PROXY_AI_PROBE_ALLOW_BYO_ENDPOINT", raising=False)
    from mcp_proxy.admin.ai_providers import _byo_endpoint_allowed
    assert _byo_endpoint_allowed() is False
    monkeypatch.setenv("MCP_PROXY_AI_PROBE_ALLOW_BYO_ENDPOINT", "true")
    assert _byo_endpoint_allowed() is True
    monkeypatch.setenv("MCP_PROXY_AI_PROBE_ALLOW_BYO_ENDPOINT", "1")
    assert _byo_endpoint_allowed() is True
    monkeypatch.setenv("MCP_PROXY_AI_PROBE_ALLOW_BYO_ENDPOINT", "yes")
    assert _byo_endpoint_allowed() is True
    monkeypatch.setenv("MCP_PROXY_AI_PROBE_ALLOW_BYO_ENDPOINT", "false")
    assert _byo_endpoint_allowed() is False


# ─── D3 — OPA SSRF DNS-pin ───


def test_d3_opa_uses_pinned_dns_backend_for_request(monkeypatch):
    """The dispatcher must construct the httpx client with
    ``_PinnedDNSBackend`` so the actual TCP dial uses the pre-resolved
    IP, not whatever a second DNS lookup returns. Pre-fix the
    re-validation ran AFTER the request and the body had already
    flown to the (potentially attacker-controlled) IP."""
    import inspect
    from app.policy import opa as opa_mod
    src = inspect.getsource(opa_mod.evaluate_session_via_opa)
    # The function must instantiate _PinnedDNSBackend before the
    # client.post call. The presence of the symbol in the source is
    # the structural assertion (a behavioural test would need a real
    # OPA running — covered by sandbox/integration).
    assert "_PinnedDNSBackend" in src
    # And the post-request validate_opa_url block must be gone.
    assert "DNS rebinding detected" not in src
    # And the validator import must be present.
    assert "_validate_and_resolve_webhook_url" in src
