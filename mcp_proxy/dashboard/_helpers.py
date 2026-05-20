"""Mastio dashboard — shared helpers for sub-routers.

Sprint F-B-201 PR-1 of 10. Extracted from
``mcp_proxy/dashboard/router.py`` so the upcoming per-feature sub-routers
can import these helpers without dragging the whole 5106-LOC router.

Mirrors the Court sibling ``app/dashboard/_helpers.py`` (F-B-202 PR-1).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import Request

from mcp_proxy.dashboard.session import ProxyDashboardSession


def _ctx(request: Request, session: ProxyDashboardSession, **kwargs) -> dict:
    """Build the standard template context."""
    return {
        "request": request,
        "session": session,
        "csrf_token": session.csrf_token,
        **kwargs,
    }


# Wave B G1 (audit 2026-05-11) — SSRF guard for the dashboard's three
# outbound-fetch test endpoints (test-connection / test-webhook /
# vault/test). Refuses loopback / RFC1918 / link-local / reserved IPs
# unless ``allow_private=True`` (the Vault case in docker-compose).
# Resolves the hostname so a public DNS that points at 127.0.0.1
# can't bypass the check via a CNAME.
def _enforce_safe_outbound_url(url: str, *, allow_private: bool = False) -> None:
    """Raise ValueError when ``url`` resolves to a forbidden target.

    The check parses the URL, resolves the hostname, and inspects every
    returned IP. ``allow_private=True`` skips the RFC1918/loopback ban
    for legitimate same-network targets (Vault, dev fixtures); the
    hostname-resolution + scheme check still fires."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Only http(s) URLs are allowed (got scheme {parsed.scheme!r})"
        )
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")
    if not allow_private and hostname in (
        "localhost", "127.0.0.1", "::1", "0.0.0.0",
    ):
        raise ValueError(f"URL points to loopback address: {hostname}")
    try:
        addrs = socket.getaddrinfo(
            hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname: {hostname}") from exc
    for _family, _type, _proto, _canonname, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if not allow_private and (
            ip.is_private or ip.is_loopback
            or ip.is_link_local or ip.is_reserved
        ):
            raise ValueError(
                f"URL resolves to private/reserved IP: {ip}"
            )


def _login_client_ip(request: Request) -> str:
    """Best-effort client IP for the login handler.

    Uses the immediate transport peer rather than ``X-Forwarded-For``:
    nginx in front of the Mastio handles trusted-proxy resolution and
    rewrites ``request.client`` accordingly, while in dev / direct
    deployments ``X-Forwarded-For`` is attacker-controlled and would
    let any client mint a fresh "IP" per request to dodge the lockout.
    """
    client = request.client
    return client.host if client is not None else "unknown"


async def _post_login_redirect() -> str:
    """Where to send a freshly-authenticated admin.

    - No broker uplink yet     -> /proxy/setup (wizard)
    - Fully configured         -> /proxy/overview (landing)
    """
    from mcp_proxy.db import get_config
    org_id = await get_config("org_id")
    return "/proxy/overview" if org_id else "/proxy/setup"


async def _load_display_name() -> str:
    """Safe helper: org display name for the login page header."""
    from mcp_proxy.db import get_config
    try:
        return (await get_config("display_name")) or ""
    except Exception:
        return ""


def generate_org_ca(org_id: str) -> tuple[str, str]:
    """Generate self-signed Org CA. Returns (cert_pem, key_pem).

    10-year validity: this is an offline-held root (NIST SP 800-57
    Part 1 §5.3.6 — root CAs held offline with long lifetimes).
    All online signing is done by the Mastio intermediate CA minted
    underneath this root; the intermediate rotates on a shorter cycle.
    """
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        # pathLen=1 because this Org CA signs a Mastio intermediate
        # (_mint_mastio_ca) which then signs agent leaves. RFC 5280
        # §4.2.1.9: pathLen=0 would forbid the intermediate and any
        # stdlib verifier (OpenSSL, Go crypto/x509, webpki, browser)
        # would reject the full chain at federation/mTLS time. See #280.
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


async def _test_vault_connectivity(vault_addr: str, vault_token: str) -> tuple[bool, str]:
    """Test Vault connectivity. Returns (success, message)."""
    import httpx
    from mcp_proxy.config import get_settings, vault_tls_verify
    try:
        async with httpx.AsyncClient(
            verify=vault_tls_verify(get_settings()), timeout=5.0,
        ) as client:
            resp = await client.get(
                f"{vault_addr.rstrip('/')}/v1/sys/health",
                headers={"X-Vault-Token": vault_token},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("sealed"):
                    return False, "Vault is sealed"
                return True, "Connected"
            return False, f"HTTP {resp.status_code}"
    except Exception as exc:
        return False, f"Connection failed: {exc}"


async def _store_ca_key_in_vault(vault_addr: str, vault_token: str, org_id: str, key_pem: str) -> None:
    """Store Org CA private key in Vault."""
    import httpx
    from mcp_proxy.config import get_settings, vault_tls_verify
    path = f"secret/data/mcp-proxy/{org_id}/org-ca"
    url = f"{vault_addr.rstrip('/')}/v1/{path}"
    async with httpx.AsyncClient(
        verify=vault_tls_verify(get_settings()), timeout=5.0,
    ) as client:
        resp = await client.post(
            url,
            json={"data": {"key_pem": key_pem}},
            headers={"X-Vault-Token": vault_token},
        )
        resp.raise_for_status()
