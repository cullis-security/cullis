"""Auth mode resolver for Cullis Connector — ADR-025 Phase 2.

The Connector decides at boot which auth model to enable:

  - ``"local"``  — local users.db + signed session cookie (default,
                   Frontdesk SMB scenario).
  - ``"oidc"``   — corporate IdP via OIDC (single-tenant single-user;
                   Phase 6+ wires the Connector to the existing Mastio
                   /auth/oidc helpers).
  - ``"shared"`` — multi-tenant Frontdesk shared mode (ADR-019/021).
                   Triggered by the legacy ``AMBASSADOR_MODE=shared`` env.

Precedence:

  1. ``AMBASSADOR_MODE=shared`` env wins → ``"shared"`` (back-compat
     for existing ADR-021 deployments that have only ever set this var).
  2. ``AUTH_MODE`` env value, lowercased and validated against the set
     above. Anything unrecognised falls back to ``"local"`` with a
     warning so a typo'd env doesn't silently disable the auth surface.
  3. Default ``"local"``.

The helpers exist as a single source of truth so the dashboard, the
admin router, and the (Phase 2) login router all read the same value
without duplicating env parsing.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

_log = logging.getLogger("cullis_connector.identity.auth_mode")

ENV_AUTH_MODE = "AUTH_MODE"
ENV_AMBASSADOR_MODE = "AMBASSADOR_MODE"

MODE_LOCAL = "local"
MODE_OIDC = "oidc"
MODE_SHARED = "shared"

_VALID_MODES = (MODE_LOCAL, MODE_OIDC, MODE_SHARED)


def read_auth_mode(env: Optional[dict] = None) -> str:
    """Return the active auth mode, one of ``local`` / ``oidc`` / ``shared``.

    ``env`` lets tests inject a dict instead of the live ``os.environ``.
    """
    e = env if env is not None else os.environ
    ambassador = (e.get(ENV_AMBASSADOR_MODE) or "").strip().lower()
    if ambassador == "shared":
        return MODE_SHARED
    raw = (e.get(ENV_AUTH_MODE) or "").strip().lower()
    if not raw:
        return MODE_LOCAL
    if raw in _VALID_MODES:
        return raw
    _log.warning(
        "AUTH_MODE=%r is not one of %s; falling back to %s",
        raw, _VALID_MODES, MODE_LOCAL,
    )
    return MODE_LOCAL


def is_local_mode(env: Optional[dict] = None) -> bool:
    return read_auth_mode(env) == MODE_LOCAL


def is_oidc_mode(env: Optional[dict] = None) -> bool:
    return read_auth_mode(env) == MODE_OIDC


def is_shared_mode(env: Optional[dict] = None) -> bool:
    return read_auth_mode(env) == MODE_SHARED


__all__ = [
    "ENV_AMBASSADOR_MODE",
    "ENV_AUTH_MODE",
    "MODE_LOCAL",
    "MODE_OIDC",
    "MODE_SHARED",
    "is_local_mode",
    "is_oidc_mode",
    "is_shared_mode",
    "read_auth_mode",
]
