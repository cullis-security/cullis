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
