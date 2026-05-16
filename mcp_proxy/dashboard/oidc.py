"""OIDC for the MCP Proxy dashboard.

Protocol-level helpers (PKCE state, discovery, authorization URL, ID
token exchange) live in :mod:`cullis_sdk.oidc` — single source of truth
shared with ``cullis-connector login`` (ADR-032 Layer 2). This file
re-exports the public surface and keeps the proxy-local DB-bound
config helpers (``load_oidc_config`` / ``save_oidc_config`` /
``is_oidc_configured``).

The earlier duplication between this file, ``app/dashboard/oidc.py``,
and the Connector copy is folded into the shared module.
"""
from __future__ import annotations

from cullis_sdk.oidc import (  # noqa: F401  re-export
    OidcError,
    OidcFlowState,
    OidcIdentity,
    build_authorization_url,
    create_oidc_state,
    exchange_code_for_identity,
)


# ── Config helpers (proxy_config-bound) ────────────────────────────────────

OIDC_ISSUER_URL_KEY = "oidc_issuer_url"
OIDC_CLIENT_ID_KEY = "oidc_client_id"
OIDC_CLIENT_SECRET_KEY = "oidc_client_secret"


async def load_oidc_config() -> dict[str, str]:
    """Return the proxy OIDC configuration from proxy_config.

    Keys: issuer_url, client_id, client_secret. Missing entries resolve
    to empty strings so callers can test ``bool(cfg["issuer_url"])``.
    """
    from mcp_proxy.db import get_config

    return {
        "issuer_url": (await get_config(OIDC_ISSUER_URL_KEY)) or "",
        "client_id": (await get_config(OIDC_CLIENT_ID_KEY)) or "",
        "client_secret": (await get_config(OIDC_CLIENT_SECRET_KEY)) or "",
    }


async def save_oidc_config(
    issuer_url: str,
    client_id: str,
    client_secret: str | None = None,
) -> None:
    """Persist OIDC config to proxy_config. Empty client_secret is preserved
    only when explicitly passed; `None` means "leave existing value untouched"."""
    from mcp_proxy.db import set_config

    await set_config(OIDC_ISSUER_URL_KEY, issuer_url.strip())
    await set_config(OIDC_CLIENT_ID_KEY, client_id.strip())
    if client_secret is not None:
        await set_config(OIDC_CLIENT_SECRET_KEY, client_secret)


async def is_oidc_configured() -> bool:
    """Return True when the minimum OIDC config (issuer + client_id) is set."""
    cfg = await load_oidc_config()
    return bool(cfg["issuer_url"] and cfg["client_id"])
