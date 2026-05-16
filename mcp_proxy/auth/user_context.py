"""Per-request "on behalf of user" context (ADR-032 Layer 2).

Mirrors :mod:`mcp_proxy.auth.dpop_context`. Auth deps that successfully
verify a Connector ``X-Cullis-Session-Token`` stamp the bound
``principal_id`` here; :func:`mcp_proxy.db.log_audit` reads it as a
default for ``audit_log.on_behalf_of_user_id`` so the row carries dual
attribution (the calling agent + the user the agent is acting for)
without threading the value through every call site.

Stamp ONLY on the success path — a 401 must not bleed a rejected
``principal_id`` into a sibling audit row.
"""
from __future__ import annotations

from contextvars import ContextVar, Token


_on_behalf_of_user: ContextVar[str | None] = ContextVar(
    "cullis_on_behalf_of_user", default=None,
)


def set_on_behalf_of_user(principal_id: str | None) -> Token[str | None]:
    """Stamp the user principal_id the current request acts on behalf of."""
    return _on_behalf_of_user.set(principal_id)


def current_on_behalf_of_user() -> str | None:
    """Read the principal_id stamped for the current request, or ``None``."""
    return _on_behalf_of_user.get()


def reset_on_behalf_of_user(token: Token[str | None]) -> None:
    """Restore the contextvar to its previous value (test-only)."""
    _on_behalf_of_user.reset(token)
