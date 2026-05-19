"""Tests for ``mcp_proxy.lifespan._san_resolver.resolve_nginx_sans``.

Customer-blocker dogfood 2026-05-19: a Mastio VM at
``192.168.122.62`` deployed via ``cullis-mastio-bundle`` with
``MCP_PROXY_PROXY_PUBLIC_URL=https://192.168.122.62:9443`` minted
an nginx leaf SAN list of
``mastio.local,localhost,host.docker.internal,mastio-nginx,mcp-proxy``
(the bundle default). Every TLS-strict client (Frontdesk
Connector, Python SDK, browsers without ``--insecure``) refused
the handshake with ``CERTIFICATE_VERIFY_FAILED / hostname
'192.168.122.62' doesn't match``. The downstream cert minter
(``AgentManager.ensure_nginx_server_cert``) already splits IP
literals into iPAddress SAN entries and hostnames into dNSName;
the bug was that the SAN list passed in didn't include the host
the operator actually configured.

The resolver auto-appends the hostname of ``proxy_public_url`` so
fresh deploys + container restarts close the gap without needing
the operator to also edit ``MCP_PROXY_NGINX_SAN``. Integration
asserts pair with ``test_mastio_nginx_cert_san.py`` (which pins
the iPAddress vs dNSName split downstream).
"""
from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

from mcp_proxy.lifespan._san_resolver import resolve_nginx_sans


@dataclass
class _Settings:
    nginx_san: str = "mastio.local"
    proxy_public_url: str = ""


# ── Unit: resolver behaviour ───────────────────────────────────────


def test_empty_public_url_returns_split_nginx_san_unchanged():
    s = _Settings(
        nginx_san="mastio.local,localhost,host.docker.internal",
        proxy_public_url="",
    )
    assert resolve_nginx_sans(s) == [
        "mastio.local", "localhost", "host.docker.internal",
    ]


def test_ipv4_public_url_appends_once():
    s = _Settings(
        nginx_san="mastio.local,localhost",
        proxy_public_url="https://192.168.122.62:9443",
    )
    sans = resolve_nginx_sans(s)
    assert sans == ["mastio.local", "localhost", "192.168.122.62"]


def test_fqdn_public_url_appends_once():
    s = _Settings(
        nginx_san="mastio.local,localhost",
        proxy_public_url="https://mastio.acme.corp:9443",
    )
    sans = resolve_nginx_sans(s)
    assert sans == ["mastio.local", "localhost", "mastio.acme.corp"]


def test_public_url_host_already_in_san_does_not_duplicate():
    """Idempotency: default + already-listed host stays single entry."""
    s = _Settings(
        nginx_san="mastio.local,localhost",
        proxy_public_url="https://mastio.local:9443",
    )
    sans = resolve_nginx_sans(s)
    assert sans == ["mastio.local", "localhost"]


def test_ipv6_literal_returns_hostname_without_brackets():
    """urlparse strips the brackets, so the entry compares cleanly
    against ``ipaddress.ip_address(...)`` in the downstream split."""
    s = _Settings(
        nginx_san="mastio.local",
        proxy_public_url="https://[::1]:9443",
    )
    sans = resolve_nginx_sans(s)
    assert sans == ["mastio.local", "::1"]
    # And the resulting entry round-trips through ipaddress, so the
    # downstream IP-vs-DNS split picks it as an IP literal.
    assert ipaddress.ip_address(sans[-1])


def test_malformed_url_no_crash_and_no_append():
    """urlparse('not-a-url').hostname is None — must not crash,
    must not pollute the SAN list with garbage."""
    s = _Settings(
        nginx_san="mastio.local",
        proxy_public_url="not-a-url",
    )
    assert resolve_nginx_sans(s) == ["mastio.local"]


def test_whitespace_in_nginx_san_is_stripped():
    s = _Settings(
        nginx_san="mastio.local, localhost ,  host.docker.internal",
        proxy_public_url="",
    )
    assert resolve_nginx_sans(s) == [
        "mastio.local", "localhost", "host.docker.internal",
    ]


def test_idempotent_across_calls():
    """Watcher tick and boot must produce identical lists for the
    same settings, otherwise the cert reuse path triggers a
    spurious rotation on every restart."""
    s = _Settings(
        nginx_san="mastio.local,localhost,host.docker.internal,mastio-nginx,mcp-proxy",
        proxy_public_url="https://192.168.122.62:9443",
    )
    first = resolve_nginx_sans(s)
    second = resolve_nginx_sans(s)
    assert first == second


def test_empty_nginx_san_falls_back_to_default():
    s = _Settings(nginx_san="", proxy_public_url="")
    assert resolve_nginx_sans(s) == ["mastio.local"]


def test_logs_at_info_when_appending(monkeypatch):
    """Operators need to see ``auto-appended public_url host=X`` in
    the boot log so the fix is visible (not a silent surprise).

    Monkeypatching ``logger.info`` directly bypasses logging-framework
    state set by other mcp_proxy tests (propagate=False, handler
    overrides, logger.disabled, etc). See memory rule
    feedback-mcp-proxy-logger-caplog.
    """
    from mcp_proxy.lifespan import _san_resolver as mod

    captured: list[tuple] = []
    monkeypatch.setattr(
        mod.logger, "info",
        lambda fmt, *args: captured.append((fmt, args)),
    )

    s = _Settings(
        nginx_san="mastio.local",
        proxy_public_url="https://192.168.122.62:9443",
    )
    resolve_nginx_sans(s)

    rendered = [fmt % args if args else fmt for fmt, args in captured]
    assert any(
        "auto-appended" in m and "192.168.122.62" in m for m in rendered
    ), rendered


def test_no_log_when_no_append(monkeypatch):
    """Default settings (no public_url) must NOT emit the
    auto-append log, otherwise every test run / boot prints a
    noisy nonsense line."""
    from mcp_proxy.lifespan import _san_resolver as mod

    captured: list[str] = []
    monkeypatch.setattr(
        mod.logger, "info",
        lambda fmt, *args: captured.append(fmt % args if args else fmt),
    )

    s = _Settings(nginx_san="mastio.local", proxy_public_url="")
    resolve_nginx_sans(s)

    assert not any("auto-appended" in m for m in captured)


# ── Integration: resolver → ensure_nginx_server_cert SAN shape ─────


def _make_manager_with_ca():
    """Wire an AgentManager with an Org CA + Mastio Intermediate but
    skip Vault / DB bootstrap. Same fixture shape as
    ``test_mastio_nginx_cert_san.py``."""
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    from mcp_proxy.egress.agent_manager import AgentManager

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "test-org CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    mgr = AgentManager.__new__(AgentManager)
    mgr._org_ca_key = key
    mgr._org_ca_cert = cert
    mgr._mastio_ca_key = key
    mgr._mastio_ca_cert = cert
    mgr._org_id = "test-org"
    return mgr


def _read_sans(crt_path: Path) -> tuple[set[str], set[str]]:
    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName,
    ).value
    dns = set(san.get_values_for_type(x509.DNSName))
    ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    return dns, ips


def test_integration_ipv4_public_url_lands_as_ip_san(tmp_path):
    """End-to-end: resolver auto-appends, downstream minter routes
    the literal into iPAddress (not dNSName) — closes the dogfood
    bug for real."""
    settings = _Settings(
        nginx_san="mastio.local,localhost,host.docker.internal",
        proxy_public_url="https://192.168.122.62:9443",
    )
    mgr = _make_manager_with_ca()
    asyncio.run(
        mgr.ensure_nginx_server_cert(
            out_dir=tmp_path,
            sans=resolve_nginx_sans(settings),
            validity_days=30,
            renew_within_days=7,
        )
    )
    dns, ips = _read_sans(tmp_path / "mastio-server.crt")
    assert "192.168.122.62" in ips
    assert "192.168.122.62" not in dns
    assert {"mastio.local", "localhost", "host.docker.internal"} <= dns


def test_integration_fqdn_public_url_lands_as_dns_san(tmp_path):
    settings = _Settings(
        nginx_san="mastio.local,localhost",
        proxy_public_url="https://mastio.acme.corp:9443",
    )
    mgr = _make_manager_with_ca()
    asyncio.run(
        mgr.ensure_nginx_server_cert(
            out_dir=tmp_path,
            sans=resolve_nginx_sans(settings),
            validity_days=30,
            renew_within_days=7,
        )
    )
    dns, ips = _read_sans(tmp_path / "mastio-server.crt")
    assert "mastio.acme.corp" in dns
    assert ips == set()


def test_integration_default_settings_no_regression(tmp_path):
    """Operator who never sets PROXY_PUBLIC_URL must still get the
    legacy bundle SAN list verbatim — no regression on the existing
    docker-compose default install path."""
    settings = _Settings(
        nginx_san="mastio.local,localhost,host.docker.internal,mastio-nginx,mcp-proxy",
        proxy_public_url="",
    )
    mgr = _make_manager_with_ca()
    asyncio.run(
        mgr.ensure_nginx_server_cert(
            out_dir=tmp_path,
            sans=resolve_nginx_sans(settings),
            validity_days=30,
            renew_within_days=7,
        )
    )
    dns, ips = _read_sans(tmp_path / "mastio-server.crt")
    assert dns == {
        "mastio.local", "localhost", "host.docker.internal",
        "mastio-nginx", "mcp-proxy",
    }
    assert ips == set()
