"""Tests for the mastio-nginx leaf cert SAN encoding.

Closes the bug a non-tech operator hits the moment they deploy
``cullis-mastio-bundle`` to a VM with an IP-literal hostname:

  - ``./deploy.sh`` prompts for the public URL → operator types
    ``https://192.168.122.154:9443``.
  - ``deploy.sh`` extracts the host and writes
    ``MCP_PROXY_NGINX_SAN=192.168.122.154,mastio.local,localhost``.
  - The Mastio container boots, generates an Org CA, then asks
    ``InternalAgentManager.emit_nginx_server_cert(sans=[...])`` to
    mint a leaf for nginx.
  - Pre-fix: every SAN entry went into ``x509.DNSName(s)``. RFC 6125
    + Python's ``ssl`` reject IP literals matched against ``DNSName``
    SANs → every Connector dialing the IP failed
    ``[SSL: CERTIFICATE_VERIFY_FAILED] IP address mismatch`` despite
    a "valid" cert with ``DNS:192.168.122.154`` printed in it.

The fix splits ``sans`` into two buckets: real hostnames →
``x509.DNSName``, IP literals → ``x509.IPAddress``. These tests pin
that behaviour so a regression silently bringing the old shape back
shows up at unit-test time, not at the next dogfood.
"""
from __future__ import annotations

import asyncio
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_proxy.egress.agent_manager import AgentManager


def _make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Standalone Org CA — mirrors the fast-boot path in main.py
    without touching Vault or DB."""
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
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_manager_with_ca() -> AgentManager:
    """An AgentManager wired with an Org CA but skipping the
    Vault / DB bootstrap — the SAN logic only touches in-memory CA
    material + a path on disk."""
    mgr = AgentManager.__new__(AgentManager)
    key, cert = _make_ca()
    mgr._org_ca_key = key
    mgr._org_ca_cert = cert
    mgr._org_id = "test-org"
    return mgr


def _emit(mgr: AgentManager, out: Path, sans: list[str]) -> Path:
    """Run the emit method synchronously, return the leaf cert path."""
    asyncio.run(
        mgr.ensure_nginx_server_cert(
            out_dir=out,
            sans=sans,
            validity_days=30,
            renew_within_days=7,
        )
    )
    return out / "mastio-server.crt"


def _read_sans(crt_path: Path) -> tuple[set[str], set[str]]:
    """Return (DNS names, IP literals as strings) from the cert SAN."""
    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName,
    ).value
    dns = set(san.get_values_for_type(x509.DNSName))
    ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    return dns, ips


# ── Mint path ──────────────────────────────────────────────────────


def test_mint_ipv4_literal_lands_in_ip_address_san(tmp_path):
    """The IP-literal-on-VM bug — pin it to the iPAddress slot."""
    mgr = _make_manager_with_ca()
    crt = _emit(mgr, tmp_path, ["192.168.122.154", "mastio.local", "localhost"])
    dns, ips = _read_sans(crt)
    assert dns == {"mastio.local", "localhost"}
    assert ips == {"192.168.122.154"}


def test_mint_ipv6_literal_lands_in_ip_address_san(tmp_path):
    """IPv6 deploys deserve the same treatment — same bug, different
    address family. Operator using ``[::1]`` or a ULA hits this on
    home-lab setups."""
    mgr = _make_manager_with_ca()
    crt = _emit(mgr, tmp_path, ["::1", "mastio.local"])
    dns, ips = _read_sans(crt)
    assert dns == {"mastio.local"}
    # cryptography normalises IPv6 to canonical form on read.
    assert ips == {str(ipaddress.ip_address("::1"))}


def test_mint_pure_hostnames_unchanged(tmp_path):
    """No IPs in the list → IPAddress SAN must be empty (regression
    guard for environments that still use only DNS-style SANs)."""
    mgr = _make_manager_with_ca()
    crt = _emit(mgr, tmp_path, ["mastio.acme.local", "localhost"])
    dns, ips = _read_sans(crt)
    assert dns == {"mastio.acme.local", "localhost"}
    assert ips == set()


# ── Reuse path ──────────────────────────────────────────────────────


def test_reuse_path_accepts_existing_cert_with_correct_split(tmp_path):
    """A second boot with the same SAN list must NOT regenerate the
    cert. This was already the contract pre-fix, just on DNSName-only
    inputs — pin it for the new mixed-type case."""
    mgr = _make_manager_with_ca()
    sans = ["192.168.122.154", "mastio.local"]
    crt1 = _emit(mgr, tmp_path, sans)
    serial1 = x509.load_pem_x509_certificate(crt1.read_bytes()).serial_number

    # Second emit with the same input — must reuse, not regenerate.
    _emit(mgr, tmp_path, sans)
    serial2 = x509.load_pem_x509_certificate(crt1.read_bytes()).serial_number
    assert serial1 == serial2, (
        "second emit regenerated the leaf — reuse path didn't recognise "
        "the existing cert with mixed DNS+IP SANs"
    )


def test_reuse_path_regenerates_when_san_list_changes(tmp_path):
    """Changing IPs/hosts must trigger a fresh mint — otherwise an
    operator who edits MCP_PROXY_NGINX_SAN would silently keep the old
    cert and the new hostname would still fail validation."""
    mgr = _make_manager_with_ca()
    crt = _emit(mgr, tmp_path, ["192.168.122.154", "mastio.local"])
    serial1 = x509.load_pem_x509_certificate(crt.read_bytes()).serial_number

    _emit(mgr, tmp_path, ["10.0.0.5", "mastio.local"])
    serial2 = x509.load_pem_x509_certificate(crt.read_bytes()).serial_number
    assert serial1 != serial2, (
        "SAN list changed (192.168.122.154 → 10.0.0.5) but the leaf "
        "wasn't regenerated"
    )
    dns, ips = _read_sans(crt)
    assert ips == {"10.0.0.5"}


def test_reuse_path_regenerates_when_legacy_cert_has_ip_in_dns_san(tmp_path):
    """A pre-fix cert (IP shoved into DNSName) MUST be regenerated on
    next boot — otherwise the operator never sees the bug fix even
    after upgrading. Simulate the legacy state by emitting the cert
    with the buggy code path, then re-emit with the same input and
    assert the new cert has the right shape."""
    # Build a legacy-shape cert by hand (IP in DNSName SAN) so we
    # don't depend on the buggy code path still existing.
    out = tmp_path
    out.mkdir(parents=True, exist_ok=True)
    ca_path = out / "org-ca.crt"
    crt_path = out / "mastio-server.crt"
    key_path = out / "mastio-server.key"

    mgr = _make_manager_with_ca()
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    legacy = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "192.168.122.154"),
        ]))
        .issuer_name(mgr._org_ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=180))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("192.168.122.154"),  # ← the legacy bug
                x509.DNSName("mastio.local"),
            ]),
            critical=False,
        )
        .sign(mgr._org_ca_key, hashes.SHA256())
    )
    crt_path.write_bytes(legacy.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    ca_path.write_bytes(
        mgr._org_ca_cert.public_bytes(serialization.Encoding.PEM)
    )

    _emit(mgr, out, ["192.168.122.154", "mastio.local"])
    dns, ips = _read_sans(crt_path)
    assert dns == {"mastio.local"}
    assert ips == {"192.168.122.154"}, (
        "legacy cert with IP-as-DNSName was reused instead of being "
        "replaced — operator stays stuck with CERTIFICATE_VERIFY_FAILED"
    )
