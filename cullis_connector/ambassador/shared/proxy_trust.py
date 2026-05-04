"""Reverse-proxy SSO header trust (ADR-021 §6).

Cullis does not implement SAML/OIDC. The reverse proxy in front of
the Frontdesk container does, and forwards the authenticated subject
in ``X-Forwarded-User``. We trust that header IF AND ONLY IF the
TCP peer of the request is in the operator-supplied allowlist.

Default allowlist: ``127.0.0.1/32, ::1/128``. Production deployments
override via ``CULLIS_TRUSTED_PROXIES`` (comma-separated CIDRs).
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Iterable, Optional

_log = logging.getLogger("cullis_connector.ambassador.shared.proxy_trust")

DEFAULT_TRUSTED_CIDRS = ("127.0.0.1/32", "::1/128")
SSO_HEADER = "x-forwarded-user"
SSO_GROUPS_HEADER = "x-forwarded-groups"  # optional, for future RBAC


@dataclass(frozen=True)
class TrustedProxiesAllowlist:
    """Wraps a set of ``ipaddress`` networks for ``contains`` checks."""

    networks: tuple[ipaddress._BaseNetwork, ...]

    @classmethod
    def from_cidrs(cls, cidrs: Iterable[str]) -> "TrustedProxiesAllowlist":
        nets: list[ipaddress._BaseNetwork] = []
        for cidr in cidrs:
            cidr = cidr.strip()
            if not cidr:
                continue
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as exc:
                raise ValueError(
                    f"invalid CIDR in trusted proxies allowlist: {cidr!r}: {exc}",
                ) from exc
        if not nets:
            raise ValueError("trusted proxies allowlist cannot be empty")
        return cls(networks=tuple(nets))

    def contains(self, peer_ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(peer_ip)
        except ValueError:
            return False
        # ipaddress quirk: a v4 address is not "in" a v6 network and
        # vice-versa, so we just walk the list.
        for net in self.networks:
            if addr.version != net.version:
                continue
            if addr in net:
                return True
        return False


def extract_sso_subject(headers: dict[str, str]) -> Optional[str]:
    """Pull the SSO subject from a request's headers, lowercase-keyed.

    Returns ``None`` if absent. The header value is sanitised
    (stripped, length-capped) but no further normalisation happens
    here — a tenant-specific transform (e.g. ``mario@acme.it`` →
    ``mario``) is applied by the caller.
    """
    raw = headers.get(SSO_HEADER, "")
    if not raw:
        return None
    sub = raw.strip()
    if not sub or len(sub) > 255:
        return None
    if not sub.isprintable() or any(c in sub for c in "\r\n\t"):
        return None
    return sub


__all__ = [
    "DEFAULT_TRUSTED_CIDRS",
    "SSO_GROUPS_HEADER",
    "SSO_HEADER",
    "TrustedProxiesAllowlist",
    "extract_sso_subject",
]
