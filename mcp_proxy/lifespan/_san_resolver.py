"""Build the SAN list for the nginx sidecar server cert.

Single source of truth for both the boot-time
``ensure_nginx_server_cert`` call in ``mcp_proxy.main`` and the
periodic ``nginx_cert_watcher_loop``. Starts from
``settings.nginx_san`` (comma-split, default ``"mastio.local"``)
and appends the hostname of ``settings.proxy_public_url`` when
that URL is set and its host isn't already in the list.

Closes the customer-blocker reproduced on 2026-05-19: a Mastio VM
at ``192.168.122.62`` configured with
``MCP_PROXY_PROXY_PUBLIC_URL=https://192.168.122.62:9443`` minted
a leaf with SAN ``mastio.local,localhost,host.docker.internal,
mastio-nginx,mcp-proxy`` (the bundle default) and every TLS-strict
client refused the handshake with ``CERTIFICATE_VERIFY_FAILED /
hostname '192.168.122.62' doesn't match``. The downstream cert
minter (``AgentManager.ensure_nginx_server_cert``) already splits
IP literals into ``iPAddress`` SAN entries and hostnames into
``dNSName``; the bug was upstream, in the list passed in.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("mcp_proxy.lifespan._san_resolver")


def resolve_nginx_sans(settings: Any) -> list[str]:
    """Return the SAN list for the nginx server cert.

    Starts from ``settings.nginx_san`` (comma-split, default
    ``"mastio.local"``), then appends the hostname of
    ``settings.proxy_public_url`` when set and not already present.
    Idempotent: safe to call from both the lifespan one-shot path
    and the periodic cert watcher.
    """
    raw = getattr(settings, "nginx_san", "") or "mastio.local"
    sans: list[str] = [s.strip() for s in raw.split(",") if s.strip()]

    public_url = getattr(settings, "proxy_public_url", "") or ""
    if not public_url:
        return sans

    try:
        host = urlparse(public_url).hostname
    except (ValueError, TypeError):
        host = None
    if not host:
        return sans

    # urlparse strips the brackets from IPv6 literals already, so
    # the value is comparable directly to entries in ``sans``.
    if host in sans:
        return sans

    sans.append(host)
    logger.info(
        "nginx_san: auto-appended proxy_public_url host=%s (now: %s)",
        host, sans,
    )
    return sans


__all__ = ["resolve_nginx_sans"]
