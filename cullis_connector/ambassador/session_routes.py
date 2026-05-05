"""Session endpoints for the single-mode Ambassador (ADR-019 Phase 8a).

Adds ``/api/session/init``, ``/api/session/whoami`` and
``/api/session/logout`` so a browser SPA served directly by the
Connector (Astro static, no Astro server in front) can:

  1. Mint an HttpOnly cookie from the Connector's local Bearer token,
     then call ``/v1/chat/completions`` and friends with just the
     cookie. ``require_bearer`` accepts either the cookie or the
     legacy ``Authorization: Bearer`` header, so existing clients are
     unaffected.
  2. Read its own identity (``user · local`` in single mode) for the
     IdentityBadge component without needing the SPA's server-side
     translation that exists today.
  3. Cleanly clear the cookie on logout.

Shared mode (``AMBASSADOR_MODE=shared``) ships its own equivalent in
``cullis_connector/ambassador/shared/router.py`` because it has very
different semantics (session signed by a cookie secret, lookup of a
per-user agent identity). The two routers do not share code on
purpose: collapsing them would force shared-mode complexity into the
single-mode path that today is "one Connector, one user, one Bearer".
"""
from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, Request, Response

from cullis_connector.ambassador.auth import (
    LOCAL_SESSION_COOKIE,
    require_loopback,
)

_log = logging.getLogger("cullis_connector.ambassador.session_routes")

# 30 minutes — matches the SPA's `SESSION_TTL_SECONDS` so users see
# the same refresh cadence whether they go via the Astro server or
# directly. Bumping requires a coordinated SPA change so the
# client-side ``ensureSession`` cadence stays aligned.
SESSION_TTL_SECONDS = 30 * 60

router = APIRouter(tags=["ambassador-session"])


def _enforce_loopback(request: Request) -> None:
    """Apply ``require_loopback`` only when the Ambassador is configured to.

    Mirrors the helper in ``router.py``: shares the same state key so
    the ``--no-loopback-only`` operator override (test fixtures, CI)
    affects every Ambassador surface uniformly.
    """
    state = getattr(request.app.state, "ambassador", None)
    if state and state.get("require_local_only", True):
        require_loopback(request)


def _state(request: Request) -> dict[str, Any]:
    """Pull the Ambassador's per-app state, set by ``install_ambassador``."""
    state = getattr(request.app.state, "ambassador", None)
    if not state:
        # Should never happen in practice — install_ambassador runs in
        # the lifespan before any request can reach this router. Keep
        # the guard explicit to fail loud if wiring ever regresses.
        raise RuntimeError("Ambassador not installed on this app")
    return state


@router.post("/api/session/init", dependencies=[Depends(_enforce_loopback)])
def session_init(request: Request, response: Response) -> dict[str, Any]:
    """Mint an HttpOnly session cookie carrying the local Bearer token.

    The cookie value is the same secret that ``Authorization: Bearer
    <token>`` carries today — two paths to one credential. The browser
    cannot read the cookie (HttpOnly), only ride along on subsequent
    same-origin requests.

    Why ``Secure=False``: in topology L (laptop, single user) the
    Ambassador binds to ``127.0.0.1`` only. Browsers refuse Secure
    cookies on plain ``http://localhost`` origins on every major
    browser (Chrome since ~2023, Firefox, Safari), so flagging the
    cookie Secure here would make ``init`` succeed but every
    subsequent request arrive cookie-less. Loopback is the security
    boundary, not the cookie's Secure flag.
    """
    state = _state(request)
    token = state["bearer_token"]
    response.set_cookie(
        LOCAL_SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        path="/",
        httponly=True,
        secure=False,  # see docstring
        samesite="strict",
    )
    _log.info(
        "session_init: minted cookie ttl=%ds for agent=%s",
        SESSION_TTL_SECONDS, state.get("agent_id", "<unknown>"),
    )
    return {"ok": True, "ttl": SESSION_TTL_SECONDS}


@router.post("/api/session/logout", dependencies=[Depends(_enforce_loopback)])
def session_logout(response: Response) -> dict[str, Any]:
    """Clear the session cookie. Idempotent: clears whether or not one is set."""
    response.delete_cookie(LOCAL_SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/api/session/whoami", dependencies=[Depends(_enforce_loopback)])
def session_whoami(request: Request) -> dict[str, Any]:
    """Return the resolved principal in the ADR-020 shape.

    In single mode the answer is fixed: there is exactly one identity
    served by this Connector, the active profile's agent. We surface
    it as ``principal_type=user`` so the SPA's ``IdentityBadge``
    renders ``user · <name>`` consistently with shared mode.

    Auth: requires either the session cookie or the Bearer header.
    Mirrors ``require_bearer`` semantics by hand because we need to
    differentiate "no auth" (return a public placeholder so the badge
    can show ``offline``) from "wrong token" (401). Both shared mode
    and Cursor-style direct callers expect the same shape, so we keep
    the response stable.
    """
    state = _state(request)
    expected = state["bearer_token"]
    presented = _extract_token(request)
    if not presented:
        return _placeholder_principal(reason="no_session")
    if presented != expected:
        # Wrong token: surface an explicit error rather than a
        # placeholder, so a misconfigured client doesn't silently fall
        # back to "looks like it works".
        return _placeholder_principal(reason="invalid_token")

    agent_id = state.get("agent_id", "")
    org_id = state.get("org_id", "")
    if "::" in agent_id:
        # ``agent_id`` is ``<org>::<name>`` per CullisClient convention.
        # The principal_id we surface is the SPIFFE-derived
        # ``<trust-domain>/<org>/<principal-type>/<name>`` minus the
        # ``spiffe://`` scheme; since single mode is laptop-only we use
        # ``laptop`` as the trust-domain placeholder. Shared mode
        # overrides this with the real Frontdesk trust domain.
        _, name = agent_id.split("::", 1)
    else:
        name = agent_id or "local"
    trust_domain = "laptop"
    principal_type = "user"
    principal_id = f"{trust_domain}/{org_id or 'local'}/{principal_type}/{name}"

    return {
        "ok": True,
        "principal": {
            "spiffe_id": f"spiffe://{principal_id}",
            "principal_type": principal_type,
            "name": name,
            "org": org_id or "local",
            "trust_domain": trust_domain,
            "sub": name,
            "source": "single",
        },
        # Stable across mode for clients that just want the bare facts.
        "principal_id": principal_id,
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }


def _extract_token(request: Request) -> str:
    """Pull the local Bearer from header or cookie, whichever is present."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.cookies.get(LOCAL_SESSION_COOKIE, "")


def _placeholder_principal(*, reason: str) -> dict[str, Any]:
    """Public-shape response when no valid auth is presented.

    Returning 200 + a placeholder lets the SPA's IdentityBadge render
    ``offline`` without crashing on the network error of a 401. The
    ``ok=false`` field tells the badge to render the offline state.
    """
    return {
        "ok": False,
        "error": reason,
        "principal": {
            "spiffe_id": None,
            "principal_type": "user",
            "name": "local",
            "org": "local",
            "trust_domain": None,
            "sub": "local",
            "source": "single-fallback",
        },
    }
