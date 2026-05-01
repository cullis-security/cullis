"""Dashboard RBAC helpers — role-gated FastAPI dependencies.

The community build only ever sees ``role="admin"`` (single-admin pattern
preserved by ``mcp_proxy.dashboard.session``). When the enterprise plugin
``rbac_multi_admin`` is loaded it mints sessions with a wider ``roles``
tuple (admin / operator / viewer) and routes that opt into RBAC use
``require_role`` to gate access.

Two stable roles are defined here so handlers can reference them by name
without reaching into plugin internals; additional roles introduced by
plugins are accepted at runtime and matched verbatim.
"""
from __future__ import annotations

from typing import Iterable

from fastapi import HTTPException, Request

from mcp_proxy.dashboard.session import ProxyDashboardSession, get_session

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"


def has_role(session: ProxyDashboardSession, *roles: str) -> bool:
    """True iff the session carries at least one of ``roles``."""
    if not session.logged_in or not session.roles:
        return False
    allowed = set(roles)
    return any(r in allowed for r in session.roles)


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: 401 if logged out, 403 if role mismatch.

    ``admin`` is implicitly accepted on every gate so the single-admin
    community deploy never needs to opt into per-route role lists. When the
    enterprise RBAC plugin is active, sessions minted without ``admin`` in
    their ``roles`` tuple (operator / viewer) must match one of the
    declared ``allowed_roles`` to pass.
    """
    if not allowed_roles:
        raise ValueError("require_role needs at least one allowed role")
    permitted = {ROLE_ADMIN, *allowed_roles}

    def _dep(request: Request) -> ProxyDashboardSession:
        session = get_session(request)
        if not session.logged_in:
            raise HTTPException(status_code=401, detail="login required")
        if not any(r in permitted for r in session.roles):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "role_required",
                    "allowed": sorted(allowed_roles),
                },
            )
        return session

    return _dep


def filter_roles(roles: Iterable[str]) -> tuple[str, ...]:
    """Drop empties + dedupe while preserving order. Used by plugins minting sessions."""
    seen: set[str] = set()
    kept: list[str] = []
    for r in roles:
        if not r or r in seen:
            continue
        seen.add(r)
        kept.append(r)
    return tuple(kept)
