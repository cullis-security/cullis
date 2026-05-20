"""Outbound URL safety helper (PR #2 audit 2026-05-20).

Closes F-A-203, F-A-301, F-A-302 by centralising SSRF defence at every
admin-supplied / operator-supplied URL boundary in the Mastio. The
sister implementation in ``app/policy/webhook.py`` (Court) is the
reference; this module is the Mastio mirror to avoid cross-project
imports (Court does not depend on Mastio and vice versa).

Usage::

    from mcp_proxy.utils.url_safety import assert_safe_outbound_url

    try:
        pinned_ip = assert_safe_outbound_url(url, allow_private=False)
    except UnsafeUrlError as exc:
        raise HTTPException(400, str(exc))

The helper refuses:
- non-http(s) schemes
- IP literals or hostnames that resolve into private/loopback/link-local
  / reserved / cloud-metadata / shared (CGNAT) ranges
- malformed URLs / unresolvable hostnames

The override hatch ``allow_private`` is for dev/sandbox stacks where
the Mastio legitimately reaches a service on a docker-compose network.
The env-driven host allowlist ``MCP_PROXY_INTERNAL_HOST_ALLOWLIST``
lets on-prem operators opt in specific internal MCP servers
(comma-separated FQDN list) without flipping the entire dev escape.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

__all__ = [
    "UnsafeUrlError",
    "assert_safe_outbound_url",
    "is_safe_ip",
]

_log = logging.getLogger(__name__)

# Blocked address-space catalogue. Documented inline so the matrix is
# visible without chasing CIDR libraries.
_BLOCK_REASONS = {
    "is_loopback": "loopback (127.0.0.0/8, ::1)",
    "is_link_local": "link-local (169.254.0.0/16, fe80::/10) — cloud metadata",
    "is_private": "private (RFC 1918, RFC 4193)",
    "is_reserved": "reserved",
    "is_unspecified": "unspecified (0.0.0.0, ::)",
    "is_multicast": "multicast",
}

# 100.64.0.0/10 (RFC 6598 — carrier-grade NAT) is NOT in ipaddress.is_private
# but matters in cloud (AWS uses it for internal services).
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


class UnsafeUrlError(ValueError):
    """Raised when an outbound URL fails SSRF safety checks."""


def is_safe_ip(ip_str: str, *, allow_private: bool = False) -> tuple[bool, str | None]:
    """Return ``(safe, reason)`` for a parsed IP literal.

    ``allow_private=True`` permits RFC 1918 + loopback (dev/sandbox).
    Cloud-metadata (169.254/16) and CGNAT (100.64/10) are NEVER allowed
    even with the dev escape — the IMDS attack surface is the whole point
    of this defence.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError) as exc:
        return False, f"malformed IP {ip_str!r}: {exc}"

    # Cloud metadata and CGNAT are always refused.
    if ip.is_link_local:
        return False, _BLOCK_REASONS["is_link_local"]
    if ip.version == 4 and ip in _CGNAT_V4:
        return False, "CGNAT (100.64.0.0/10) — AWS internal range"

    if allow_private:
        # Dev/sandbox path: loopback + RFC 1918 OK, the cloud-metadata
        # / CGNAT block above still applies.
        if ip.is_multicast or ip.is_unspecified:
            return False, _BLOCK_REASONS["is_multicast" if ip.is_multicast else "is_unspecified"]
        return True, None

    # Production posture: refuse anything not globally routable.
    for attr in ("is_loopback", "is_private", "is_reserved", "is_unspecified", "is_multicast"):
        if getattr(ip, attr):
            return False, _BLOCK_REASONS[attr]
    return True, None


def _internal_host_allowlist() -> frozenset[str]:
    """Parse MCP_PROXY_INTERNAL_HOST_ALLOWLIST (comma-separated FQDNs).

    Hostnames listed here skip the IP-block check entirely. Use for
    explicit internal MCP servers (e.g. ``internal-mcp.corp.example``)
    that the operator has audited and trusts."""
    raw = os.environ.get("MCP_PROXY_INTERNAL_HOST_ALLOWLIST", "")
    return frozenset(
        host.strip().lower() for host in raw.split(",") if host.strip()
    )


def assert_safe_outbound_url(
    url: str,
    *,
    allow_private: bool = False,
) -> str:
    """Validate ``url`` is safe to fetch and return the pinned IP.

    The pinned IP can be passed to a custom transport so the actual
    socket connect goes to that address (defends against DNS rebinding
    where a later resolve flips to an internal address).

    Raises ``UnsafeUrlError`` on:
    - non-http(s) scheme
    - missing hostname
    - hostname in the cloud-metadata or CGNAT family
    - hostname resolves to a private/loopback/reserved address (when
      ``allow_private=False``)
    - unresolvable hostname

    The ``MCP_PROXY_INTERNAL_HOST_ALLOWLIST`` env (comma-separated)
    bypasses the IP block for explicit operator-trusted FQDNs (still
    returns the first resolved IP for pinning).
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeUrlError("URL is empty")

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise UnsafeUrlError(
            f"URL scheme {scheme!r} not allowed (only http/https accepted)"
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise UnsafeUrlError("URL has no hostname")

    # Bypass IP-block for explicit operator-trusted FQDNs (still resolve
    # for pinning).
    in_allowlist = hostname in _internal_host_allowlist()

    # Early refuse: explicit loopback names (operator can override via
    # allow_private=True for sandbox / docker compose).
    if not allow_private and not in_allowlist and hostname in {
        "localhost", "ip6-localhost", "ip6-loopback",
    }:
        raise UnsafeUrlError(f"hostname {hostname!r} is loopback (set allow_private for dev)")

    # IP-literal hostname: validate directly without DNS.
    try:
        ipaddress.ip_address(hostname)
        is_literal = True
    except ValueError:
        is_literal = False

    if is_literal:
        safe, reason = is_safe_ip(hostname, allow_private=allow_private)
        if not safe and not in_allowlist:
            raise UnsafeUrlError(
                f"URL IP literal {hostname!r} is blocked: {reason}"
            )
        return hostname

    # Hostname: resolve and check every returned address.
    try:
        addr_infos = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if scheme == "https" else 80),
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise UnsafeUrlError(
            f"cannot resolve hostname {hostname!r}: {exc}"
        ) from exc

    if not addr_infos:
        raise UnsafeUrlError(f"hostname {hostname!r} resolved to no addresses")

    pinned_ip: str | None = None
    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        # Strip IPv6 zone id (e.g. "fe80::1%eth0") before validation.
        ip_str_clean = ip_str.split("%", 1)[0]
        safe, reason = is_safe_ip(ip_str_clean, allow_private=allow_private)
        if not safe:
            if in_allowlist:
                _log.warning(
                    "url_safety: %s resolves to %s (%s) but is in "
                    "MCP_PROXY_INTERNAL_HOST_ALLOWLIST — allowing",
                    hostname, ip_str_clean, reason,
                )
            else:
                raise UnsafeUrlError(
                    f"hostname {hostname!r} resolves to {ip_str_clean} which is blocked: {reason}"
                )
        if pinned_ip is None:
            pinned_ip = ip_str_clean

    if pinned_ip is None:
        # Should be unreachable given the empty-list check above.
        raise UnsafeUrlError(f"hostname {hostname!r} produced no usable address")

    return pinned_ip
