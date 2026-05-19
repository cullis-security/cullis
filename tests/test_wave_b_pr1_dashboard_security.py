"""Wave B PR1 — G1 dashboard SSRF/XSS.

Audit refs:
  - imp/audits/2026-05-11-track-7-owasp-frontend.md H-1 (SSRF + XSS
    in 3 dashboard test endpoints)
  - imp/audits/2026-05-11-track-6-ai-frontdesk.md H-1 (temp password
    leak via URL query string — G2 was the original fix via a
    process-local ticket store; ADR-034 dogfood follow-up superseded
    the whole approach by making the admin pick the password through
    the form so there is no longer any server-side cleartext to
    surface back. ``_pwd_tickets`` module deleted, its tests removed
    along with it.)
"""
from __future__ import annotations

import pytest


# ─── G1 — _enforce_safe_outbound_url helper ───


def test_g1_helper_rejects_loopback():
    from mcp_proxy.dashboard.router import _enforce_safe_outbound_url
    for url in (
        "http://127.0.0.1:8080/foo",
        "http://localhost/foo",
        "http://[::1]/foo",
    ):
        with pytest.raises(ValueError, match="loopback"):
            _enforce_safe_outbound_url(url)


def test_g1_helper_rejects_rfc1918_after_resolution(monkeypatch):
    """A hostname that resolves to a private IP is refused. We
    monkeypatch socket.getaddrinfo so the test does not depend on
    real DNS."""
    import socket
    from mcp_proxy.dashboard import router

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("10.0.0.5", port or 80))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="private"):
        router._enforce_safe_outbound_url("https://attacker.example.com/path")


def test_g1_helper_rejects_link_local(monkeypatch):
    import socket
    from mcp_proxy.dashboard import router

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("169.254.169.254", port or 80))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    # Cloud metadata — the textbook SSRF target.
    with pytest.raises(ValueError, match="private|reserved"):
        router._enforce_safe_outbound_url("http://metadata.example.com/")


def test_g1_helper_rejects_non_http_scheme():
    from mcp_proxy.dashboard.router import _enforce_safe_outbound_url
    with pytest.raises(ValueError, match="scheme"):
        _enforce_safe_outbound_url("file:///etc/passwd")
    with pytest.raises(ValueError, match="scheme"):
        _enforce_safe_outbound_url("gopher://attacker/")


def test_g1_helper_allows_public_when_dns_returns_public(monkeypatch):
    import socket
    from mcp_proxy.dashboard import router

    def fake_getaddrinfo(host, port, *args, **kwargs):
        # 8.8.8.8 is unambiguously public (not reserved/private/loopback).
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("8.8.8.8", port or 443))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    # No raise — public IP passes.
    router._enforce_safe_outbound_url("https://api.example.com/")


def test_g1_helper_allow_private_skips_rfc1918_check(monkeypatch):
    """``allow_private=True`` is the legitimate Vault-in-docker case:
    refuses scheme-mismatch but lets RFC1918 through."""
    import socket
    from mcp_proxy.dashboard import router

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 ("172.18.0.5", port or 8200))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    # Private IP allowed when explicitly opted in.
    router._enforce_safe_outbound_url(
        "http://vault:8200/", allow_private=True,
    )
    # But scheme check still fires.
    with pytest.raises(ValueError, match="scheme"):
        router._enforce_safe_outbound_url(
            "file:///etc/shadow", allow_private=True,
        )
