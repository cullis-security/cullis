"""Per-request DPoP key thumbprint context (P1.2).

The auth dependencies that verify a DPoP proof already compute the
proof key's JWK thumbprint (``jkt``); the audit writer downstream
needs the same value to populate ``audit_log.dpop_jkt`` without
threading it through every call site. A :class:`ContextVar` is the
cleanest fit:

* set once per request by the auth dep (``verify_token`` and the
  local-agent flow);
* read by :func:`mcp_proxy.db.log_audit` as a default when the
  caller doesn't pass it explicitly;
* automatically scoped to the request task in asyncio.

Set via :func:`set_dpop_jkt` and read via :func:`current_dpop_jkt`.
Tests can reset between cases with :func:`reset_dpop_jkt`.

The auth deps that ``raise`` after computing the jkt (e.g. the
proof key did not match the token binding) intentionally do NOT
stamp the contextvar — we don't want the audit row for the 401 to
correlate to a thumbprint that the verifier just rejected. Only
successful DPoP verifications stamp.
"""
from __future__ import annotations

from contextvars import ContextVar, Token


_dpop_jkt: ContextVar[str | None] = ContextVar("cullis_dpop_jkt", default=None)


def set_dpop_jkt(jkt: str | None) -> Token[str | None]:
    """Stamp the current request's DPoP JWK thumbprint.

    Returns the ``Token`` so the caller can ``reset_dpop_jkt(token)``
    in a ``finally`` block when needed (most call sites don't, since
    the contextvar is naturally scoped to the request task).
    """
    return _dpop_jkt.set(jkt)


def current_dpop_jkt() -> str | None:
    """Read the JWK thumbprint stamped for the current request, or
    ``None`` if no DPoP-bound auth dep ran on this task."""
    return _dpop_jkt.get()


def reset_dpop_jkt(token: Token[str | None]) -> None:
    """Restore the contextvar to its previous value. Test-only;
    request-task contextvars normally don't need explicit reset."""
    _dpop_jkt.reset(token)
