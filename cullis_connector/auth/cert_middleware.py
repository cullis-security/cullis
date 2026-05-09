"""Per-request user-cert binding for /v1/* — ADR-025 Phase 3.

Resolves the calling user's :class:`UserCredentials` from the cookie
on every ``/v1/*`` request and stashes them on
``request.state.user_credentials`` so downstream handlers (Ambassador
chat-completions / MCP) can swap the per-user cert+key into the
``CullisClient`` they construct.

Lookup order on each request:

  1. read the ``cullis_local_session`` cookie → parse + verify HMAC
     against the cookie secret (rejects expired / tampered cookies
     identically — see ``parse_local_cookie``)
  2. derive a stable ``session_id`` from ``(iat, user_name)`` and look
     up the persisted binding in ``users.db``
  3. consult the in-process :class:`UserCredentialCache`; on hit the
     middleware is fast-path
  4. on miss (cache TTL elapsed, process restart, eviction) call
     :meth:`LocalUserProvisioner.get_or_provision_for_user` which
     re-mints a fresh cert via ``UserProvisioner`` + Mastio CSR

Why a middleware and not a per-route ``Depends``: the Ambassador
single-mode router is mounted unconditionally in single mode and we
want to layer ``user_credentials`` next to it without reaching into
each handler. Routes that do not look at
``request.state.user_credentials`` keep working unchanged. Any route
that wants to honour the per-user cert just reads the attribute.

The middleware never raises 401 by itself for missing cookies on
``/v1/*`` — that decision belongs to the local router's auth
dependency. We simply do nothing when no valid cookie is presented and
let the route-level auth (Bearer or cookie via ``require_bearer``)
make the call. This keeps the middleware idempotent and side-effect-
free for legacy callers that still hit the Ambassador with the local
Bearer token instead of the local-mode cookie.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Awaitable, Callable, Optional

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import Response

from cullis_connector.ambassador.shared.credentials import UserCredentials
from cullis_connector.identity.cert_session_map import (
    derive_session_id,
    lookup_binding,
    record_binding,
)
from cullis_connector.identity.csr_flow import (
    LocalProvisioningError,
    LocalUserProvisioner,
)
from cullis_connector.identity.local_session import (
    LOCAL_SESSION_COOKIE_NAME,
    LocalSessionPayload,
    parse_local_cookie,
)

_log = logging.getLogger("cullis_connector.auth.cert_middleware")


# Path prefixes guarded by this middleware — only the OpenAI-shaped
# chat surface needs per-user cert binding. /v1/ambassador/health is a
# liveness probe and stays exempt.
_GUARDED_PREFIXES = ("/v1/chat/completions", "/v1/models", "/v1/mcp")


def _is_guarded(path: str) -> bool:
    return any(path.startswith(p) for p in _GUARDED_PREFIXES)


def _cert_thumbprint(cert_pem: str) -> str:
    """SHA-256 hex of the cert DER. 64 hex chars.

    Imported lazily so this module does not pull cryptography on
    boot for tests that never mint a cert.
    """
    import hashlib
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    from cryptography.hazmat.primitives import serialization
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


async def _resolve_credentials(
    *,
    config_dir: Path,
    cookie_secret: bytes,
    provisioner: LocalUserProvisioner,
    raw_cookie: str,
) -> tuple[Optional[LocalSessionPayload], Optional[UserCredentials]]:
    """Cookie + binding + cache → (payload, credentials).

    Returns ``(None, None)`` for any failure (missing cookie, bad
    signature, expired). Returns ``(payload, None)`` only when the
    cookie is valid but provisioning fails — the caller can decide to
    surface that as a 502 on guarded routes or drop the binding for
    permissive ones.
    """
    payload = parse_local_cookie(raw_cookie, cookie_secret)
    if payload is None:
        return None, None
    session_id = derive_session_id(
        iat=payload.iat, user_name=payload.user_name,
    )
    # Cache fast path — the in-memory cache key is the principal_id
    # which the provisioner derives the same way every time.
    coords = provisioner.coordinates_for(payload.user_name)
    cached = await provisioner.cache.get(coords.principal_id)
    if cached is not None:
        return payload, cached

    # Cache miss. The persisted binding tells us the principal_id we
    # were last bound to; if it disagrees with what we'd derive now
    # (e.g. an admin renamed the org) the re-provision below uses the
    # current coordinates and the binding gets refreshed on next
    # write. We don't trust the binding for principal_id resolution.
    binding = await lookup_binding(config_dir, session_id)
    try:
        cred = await provisioner.get_or_provision_for_user(payload.user_name)
    except LocalProvisioningError as exc:
        _log.warning(
            "cert middleware re-provision failed user_name=%s: %s",
            payload.user_name, exc,
        )
        return payload, None

    # Refresh the persisted binding so a future cache miss can resolve
    # the cert without re-running this branch (cheap upsert).
    try:
        thumbprint = _cert_thumbprint(cred.cert_pem)
    except Exception as exc:  # noqa: BLE001 — log + continue; thumbprint is a breadcrumb
        _log.warning(
            "cert middleware could not compute thumbprint for %s: %s",
            cred.principal_id, exc,
        )
        thumbprint = ""
    if binding is None or binding.cert_thumbprint != thumbprint:
        await record_binding(
            config_dir,
            session_id=session_id,
            user_name=payload.user_name,
            principal_id=cred.principal_id,
            cert_thumbprint=thumbprint,
            cert_not_after=cred.cert_not_after.isoformat(),
        )
    return payload, cred


def install_cert_middleware(
    app: FastAPI,
    *,
    config_dir: Path,
) -> None:
    """Register the per-request cert-binding middleware on ``app``.

    Idempotent — calling twice raises so a double-install bug does not
    silently double-stamp ``request.state``. The middleware reads its
    runtime dependencies (``app.state.local_provisioner``,
    ``app.state.local_cookie_secret``) at request time so they can be
    seeded later in lifespan without a chicken-and-egg ordering.
    """
    if getattr(app.state, "local_cert_middleware_installed", False):
        raise RuntimeError("local cert middleware already installed on this app")

    @app.middleware("http")
    async def _cert_middleware(  # type: ignore[no-untyped-def]
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Default state — the request has no per-user creds. Set it up
        # front so every downstream handler can read the attribute
        # without try/except for missing-attr.
        request.state.user_credentials = None
        request.state.local_session_payload = None

        if not _is_guarded(request.url.path):
            return await call_next(request)

        provisioner: Optional[LocalUserProvisioner] = getattr(
            request.app.state, "local_provisioner", None,
        )
        cookie_secret: Optional[bytes] = getattr(
            request.app.state, "local_cookie_secret", None,
        )
        if provisioner is None or cookie_secret is None:
            # Local-mode wiring not active on this app — fall through
            # without binding. Single-mode (Bearer) callers continue
            # to work because the route-level ``require_bearer``
            # dependency still authenticates them.
            return await call_next(request)

        raw = request.cookies.get(LOCAL_SESSION_COOKIE_NAME, "")
        if not raw:
            return await call_next(request)

        payload, cred = await _resolve_credentials(
            config_dir=config_dir,
            cookie_secret=cookie_secret,
            provisioner=provisioner,
            raw_cookie=raw,
        )
        request.state.local_session_payload = payload
        request.state.user_credentials = cred
        return await call_next(request)

    app.state.local_cert_middleware_installed = True
    _log.info("ADR-025 Phase 3 cert middleware installed (config_dir=%s)", config_dir)


__all__ = [
    "install_cert_middleware",
]
