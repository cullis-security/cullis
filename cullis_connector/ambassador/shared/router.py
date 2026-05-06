"""FastAPI router for Cullis Frontdesk shared mode (ADR-021 PR4b).

Endpoints:

  POST /api/session/init        cookie issuance from X-Forwarded-User
  POST /api/session/logout      cookie invalidation
  GET  /v1/models               list models (cookie-authed, per user)
  POST /v1/chat/completions     chat (cookie-authed, per user, tool-use)

Activation: ``install_shared_ambassador(app, ...)`` mounts the
router and stashes shared-mode state on ``app.state.shared_ambassador``.
The Connector dashboard ``build_app`` factory chooses between
``install_ambassador`` (single mode) and this when
``AMBASSADOR_MODE=shared``.

Single-mode router (``cullis_connector/ambassador/router.py``) is
unchanged — both modes can coexist on the same image.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from fastapi import (
    APIRouter, Depends, FastAPI, HTTPException, Request, Response, status,
)
from fastapi.responses import JSONResponse, StreamingResponse

from cullis_connector.ambassador.loop import run_tool_use_loop
from cullis_connector.ambassador.models import ChatCompletionRequest
from cullis_connector.ambassador.shared.cookie import (
    SessionPayload, issue, parse_cookie,
)
from cullis_connector.ambassador.shared.credentials import (
    DEFAULT_TTL_SECONDS, UserCredentials,
)
from cullis_connector.ambassador.shared.provisioning import (
    MastioCsrError, UserProvisioner,
)
from cullis_connector.ambassador.shared.proxy_trust import (
    TrustedProxiesAllowlist, extract_sso_subject,
)
from cullis_connector.ambassador.streaming import (
    extract_assistant_text, fake_stream,
)

_log = logging.getLogger("cullis_connector.ambassador.shared.router")

router = APIRouter(tags=["ambassador-shared"])


COOKIE_NAME = "cullis_session"
DEFAULT_COOKIE_TTL_SECONDS = DEFAULT_TTL_SECONDS  # 1h


# ── State plumbing ────────────────────────────────────────────────


@dataclass
class SharedAmbassadorState:
    """Wiring stashed on ``app.state.shared_ambassador``."""

    cookie_secret: bytes
    cookie_ttl_seconds: int
    trusted_proxies: TrustedProxiesAllowlist
    org_id: str
    trust_domain: str
    sso_subject_to_name: Any  # callable: subject_str -> name_str
    provisioner: UserProvisioner
    advertised_models: list[str]
    site_url: str
    # When False, skip the X-Forwarded-Proxy peer check. Test-only —
    # production must keep this True so the SSO header is only honoured
    # from the configured reverse proxy.
    enforce_proxy_trust: bool = True


def _state(request: Request) -> SharedAmbassadorState:
    s = getattr(request.app.state, "shared_ambassador", None)
    if s is None:
        raise HTTPException(503, "shared Ambassador not initialised on this app")
    return s


# ── Helpers ───────────────────────────────────────────────────────


def _peer_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _enforce_trusted_proxy(request: Request, state: SharedAmbassadorState) -> None:
    if not state.enforce_proxy_trust:
        return
    if not state.trusted_proxies.contains(_peer_ip(request)):
        _log.warning(
            "shared ambassador rejecting request from non-trusted peer %s on %s %s",
            _peer_ip(request), request.method, request.url.path,
        )
        raise HTTPException(401, "untrusted proxy peer")


def _principal_id_for(state: SharedAmbassadorState, sso_subject: str) -> str:
    name = state.sso_subject_to_name(sso_subject)
    if not name:
        raise HTTPException(400, "could not derive principal name from SSO subject")
    return f"{state.trust_domain}/{state.org_id}/user/{name}"


async def _require_session(request: Request) -> SessionPayload:
    state = _state(request)
    cookie = request.cookies.get(COOKIE_NAME, "")
    payload = parse_cookie(cookie, state.cookie_secret)
    if payload is None:
        raise HTTPException(401, "missing or invalid session cookie")
    return payload


async def _require_credentials(
    request: Request,
    payload: SessionPayload = Depends(_require_session),
) -> UserCredentials:
    state = _state(request)
    try:
        cred = await state.provisioner.get_or_provision(
            principal_id=payload.principal_id,
            sso_subject=payload.sub,
        )
    except MastioCsrError as exc:
        _log.exception("provisioning failed for %s", payload.principal_id)
        raise HTTPException(502, f"user provisioning failed: {exc}") from exc
    return cred


# ── /api/session/init ─────────────────────────────────────────────


@router.post("/api/session/init")
async def session_init(request: Request) -> JSONResponse:
    """Issue a cookie from the SSO subject in ``X-Forwarded-User``.

    Idempotent: a returning user with a still-valid cookie is given a
    fresh one (sliding refresh) but the principal stays the same.
    """
    state = _state(request)
    _enforce_trusted_proxy(request, state)

    headers = {k.lower(): v for k, v in request.headers.items()}
    sso_subject = extract_sso_subject(headers)
    if not sso_subject:
        raise HTTPException(401, "missing or invalid X-Forwarded-User header")

    principal_id = _principal_id_for(state, sso_subject)
    cookie_value, payload = issue(
        sub=sso_subject,
        org=state.org_id,
        principal_id=principal_id,
        secret=state.cookie_secret,
        ttl_seconds=state.cookie_ttl_seconds,
    )
    resp = JSONResponse({
        "principal_id": principal_id,
        "sub": sso_subject,
        "org": state.org_id,
        "exp": payload.exp,
    })
    resp.set_cookie(
        key=COOKIE_NAME,
        value=cookie_value,
        max_age=state.cookie_ttl_seconds,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    _log.info(
        "shared ambassador session issued sub=%s principal=%s",
        sso_subject, principal_id,
    )
    return resp


# ── /api/session/logout ───────────────────────────────────────────


@router.post("/api/session/logout")
async def session_logout(
    request: Request,
    payload: SessionPayload = Depends(_require_session),
) -> Response:
    """Invalidate the cookie immediately by setting Max-Age=0."""
    resp = JSONResponse({"ok": True, "principal_id": payload.principal_id})
    resp.set_cookie(
        key=COOKIE_NAME,
        value="",
        max_age=0,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    _log.info(
        "shared ambassador logout principal=%s sub=%s",
        payload.principal_id, payload.sub,
    )
    return resp


# ── /api/session/whoami ───────────────────────────────────────────


@router.get("/api/session/whoami")
async def session_whoami(
    payload: SessionPayload = Depends(_require_session),
) -> dict:
    """Resolve the authenticated principal in ADR-020 wrapped shape.

    Matches single mode (cullis_connector/ambassador/session_routes.py)
    after Phase 8b-2a — both modes now return ``{ok, principal: <ADR-020
    shape>, principal_id, sub, org, exp}`` so the SPA's IdentityBadge
    consumes one wire shape regardless of where the Ambassador runs.

    Top-level ``principal_id``, ``sub``, ``org``, ``exp`` are preserved
    for back-compat with callers (incl. Frontdesk smoke tests) that read
    them directly. The ``principal`` subobject is the additive piece.
    """
    parts = payload.principal_id.split("/")
    if len(parts) == 4:
        trust_domain, org, principal_type, name = parts
    else:
        # Malformed principal_id: surface what we have. Should not
        # happen in practice (init validates the shape) but is a
        # defensive fallback so the badge still renders.
        trust_domain = ""
        org = payload.org
        principal_type = "user"
        name = payload.sub
    return {
        "ok": True,
        "principal": {
            "spiffe_id": f"spiffe://{payload.principal_id}",
            "principal_type": principal_type,
            "name": name,
            "org": org,
            "trust_domain": trust_domain,
            "sub": payload.sub,
            "source": "shared",
        },
        "principal_id": payload.principal_id,
        "sub": payload.sub,
        "org": payload.org,
        "exp": payload.exp,
    }


# ── /v1/models ────────────────────────────────────────────────────


@router.get("/v1/models")
async def list_models(
    request: Request,
    _payload: SessionPayload = Depends(_require_session),
) -> dict:
    state = _state(request)
    return {
        "object": "list",
        "data": [
            {"id": m, "object": "model", "owned_by": "cullis", "created": 0}
            for m in (state.advertised_models or ["claude-haiku-4-5"])
        ],
    }


# ── /v1/chat/completions ─────────────────────────────────────────


def _build_user_client(state: SharedAmbassadorState, cred: UserCredentials):
    """Construct a CullisClient logged in with the user's cert+key.

    Uses :meth:`CullisClient.from_user_principal_pem` so the user's
    cert is presented at the TLS handshake — required by the Mastio
    nginx ``location ~ ^/v1/(egress|agents|audit|llm|chat)`` mTLS gate
    that fronts the AI gateway. The factory derives the canonical
    typed ``agent_id`` (``{org}::user::{name}``) from the 4-segment
    principal_id so the JWT ``sub`` lines up with the broker
    x509_verifier's SPIFFE-SAN parse (no 401 'sub mismatch').

    v0.1 builds fresh per request (~100ms login + tempfile setup).
    v0.2 will cache these clients keyed on principal_id with TTL
    matching the cert, behind a tiny adapter so this function stays
    the entry point.
    """
    from cullis_sdk import CullisClient
    client = CullisClient.from_user_principal_pem(
        state.site_url,
        principal_id=cred.principal_id,
        cert_pem=cred.cert_pem,
        key_pem=cred.key_pem,
    )
    client.login_via_proxy_with_local_key()
    return client


@router.post("/v1/chat/completions")
async def chat_completions(
    req: ChatCompletionRequest,
    request: Request,
    cred: UserCredentials = Depends(_require_credentials),
):
    state = _state(request)
    body = req.model_dump(exclude_none=True)

    try:
        client = _build_user_client(state, cred)
    except Exception as exc:
        _log.exception("shared ambassador SDK login failed for %s", cred.principal_id)
        raise HTTPException(502, f"Cullis cloud login failed: {exc}") from exc

    try:
        response, truncated = run_tool_use_loop(client, body, max_iters=8)
    except Exception as exc:
        _log.exception(
            "shared ambassador tool-use loop failed for %s", cred.principal_id,
        )
        raise HTTPException(502, f"Cullis cloud call failed: {exc}") from exc

    model_out = body.get("model") or "claude-haiku-4-5"

    if req.stream:
        answer = extract_assistant_text(response)
        headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        if truncated:
            headers["X-Cullis-Tool-Use-Truncated"] = "true"
        return StreamingResponse(
            fake_stream(answer, model=model_out),
            media_type="text/event-stream",
            headers=headers,
        )

    if truncated:
        return JSONResponse(
            response, headers={"X-Cullis-Tool-Use-Truncated": "true"}
        )
    return response


# ── Wiring ────────────────────────────────────────────────────────


def install_shared_ambassador(
    app: FastAPI,
    *,
    cookie_secret: bytes,
    trusted_proxies: TrustedProxiesAllowlist,
    org_id: str,
    trust_domain: str,
    provisioner: UserProvisioner,
    sso_subject_to_name=lambda sub: sub.split("@")[0] if "@" in sub else sub,
    advertised_models: list[str] | None = None,
    cookie_ttl_seconds: int = DEFAULT_COOKIE_TTL_SECONDS,
    site_url: str = "",
    enforce_proxy_trust: bool = True,
) -> None:
    """Stash shared-mode state on ``app.state.shared_ambassador`` and mount.

    ``enforce_proxy_trust=False`` is for test scaffolding only —
    the FastAPI ``TestClient`` reports ``request.client.host =
    'testclient'`` which is not a valid IP and cannot be in any
    CIDR. Production callers MUST leave this True so the SSO
    header is only honoured from the configured reverse proxy.
    """
    if hasattr(app.state, "shared_ambassador") and app.state.shared_ambassador:
        raise RuntimeError("shared Ambassador already installed on this app")
    if len(cookie_secret) < 32:
        raise ValueError("cookie_secret must be at least 32 bytes")
    app.state.shared_ambassador = SharedAmbassadorState(
        cookie_secret=cookie_secret,
        cookie_ttl_seconds=cookie_ttl_seconds,
        trusted_proxies=trusted_proxies,
        org_id=org_id,
        trust_domain=trust_domain,
        sso_subject_to_name=sso_subject_to_name,
        provisioner=provisioner,
        advertised_models=list(advertised_models or ["claude-haiku-4-5"]),
        site_url=site_url,
        enforce_proxy_trust=enforce_proxy_trust,
    )
    app.include_router(router)
    _log.info(
        "shared ambassador installed org=%s trust_domain=%s site=%s",
        org_id, trust_domain, site_url,
    )


__all__ = [
    "COOKIE_NAME",
    "DEFAULT_COOKIE_TTL_SECONDS",
    "SharedAmbassadorState",
    "install_shared_ambassador",
    "router",
]
