"""ADR-004 reverse-proxy middleware.

Forwards /v1/broker/*, /v1/auth/*, /v1/registry/* to the configured broker,
preserving method, path, body, and auth-relevant headers (DPoP, Authorization,
client_assertion x5c). Host header from the inbound request is propagated so
the broker's DPoP htu validator sees the URL the SDK actually used.

WebSocket upgrade forwarding is not implemented here — see ADR-004 §5 Q2.
"""
from mcp_proxy.reverse_proxy.forwarder import (
    FORWARDED_PREFIXES,
    build_reverse_proxy_router,
)

__all__ = ["FORWARDED_PREFIXES", "build_reverse_proxy_router"]
