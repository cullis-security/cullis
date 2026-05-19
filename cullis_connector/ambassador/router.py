"""FastAPI router for the Connector Ambassador.

Mounted on the Connector dashboard app when
``config.ambassador.enabled`` is true. Exposes:

  GET  /v1/ambassador/health   — unauthenticated, for liveness probes
  GET  /v1/models              — Bearer-authed; lists Cullis-routed models
  POST /v1/chat/completions    — Bearer-authed; OpenAI ChatCompletion
                                 with server-side tool-use loop
  POST /v1/mcp                 — Bearer-authed; JSON-RPC MCP passthrough

All routes (except ``/v1/ambassador/health``) require:
  - the request to come from a loopback peer (127.0.0.1 / ::1)
  - a valid Bearer token matching the local ``local.token`` file

Any 401 from the SDK invalidates the cached client so the next call
re-logs in.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from cullis_connector.ambassador.auth import require_bearer, require_loopback
from cullis_connector.ambassador.client import AmbassadorClient
from cullis_connector.ambassador.loop import run_tool_use_loop
from cullis_connector.ambassador.models import ChatCompletionRequest
from cullis_connector.ambassador.session_routes import router as session_router
from cullis_connector.ambassador.streaming import (
    extract_assistant_text,
    fake_stream,
)
from cullis_connector.ambassador.streaming_loop import stream_tool_use_loop
from cullis_connector.identity.auth_mode import is_frontdesk_bundle

_log = logging.getLogger("cullis_connector.ambassador.router")

router = APIRouter(tags=["ambassador"])


def _per_user_credentials(request: Request):
    """Return ``request.state.user_credentials`` or ``None``.

    Wrapped so the chat-completions handler can stay tidy even though
    Starlette's request.state is just a plain object (``getattr`` to
    ride out the missing-attr branch on legacy paths).
    """
    return getattr(request.state, "user_credentials", None)


def _build_user_client(request: Request, cred: Any):
    """Construct a per-request CullisClient logged in as ``cred``.

    Mirrors ``cullis_connector/ambassador/shared/router.py::
    _build_user_client``: uses ``CullisClient.from_user_principal_pem``
    so the user's cert is presented at the TLS handshake. The
    site_url is read from the Ambassador state (set by
    ``install_ambassador``).
    """
    state = getattr(request.app.state, "ambassador", None)
    if state is None:
        raise HTTPException(503, "Ambassador not initialized on this app")
    site_url = state.get("site_url") or ""
    if not site_url:
        raise HTTPException(
            503, "Ambassador site_url unknown — cannot build per-user client",
        )
    from cullis_sdk import CullisClient
    import os as _os
    try:
        _req_timeout = float(_os.environ.get("CULLIS_REQUEST_TIMEOUT_S", "10"))
    except ValueError:
        _req_timeout = 10.0

    # Defence-in-depth for headless Frontdesk auto-enroll: surface the
    # operator-pinned Org CA bundle to the per-user CullisClient so its
    # TLS verify against the Mastio's self-signed cert succeeds even if
    # the profile-level ``ca-chain.pem`` is missing (the bundle skips
    # the manual ``/setup/pin-ca`` step). Pre-fix the factory defaulted
    # to httpx's system CA store, which never carries the Org Root and
    # every ``/v1/principals/csr`` call collapsed to
    # ``provisioning="deferred"`` with ``CERTIFICATE_VERIFY_FAILED``.
    # Shares :func:`cullis_connector.config._resolve_env_ca_path` with
    # :func:`verify_arg_for` so the env precedence stays in one place.
    #
    # Sync I/O (``open(...).read()``) is intentional: this helper is a
    # ``def`` (not ``async def``), invoked under a request that already
    # pays three round-trip HTTPS calls inside
    # :meth:`login_via_proxy_with_local_key`; the marginal file read is
    # noise. If this is ever moved to ``async def``, wrap the read in
    # ``await asyncio.to_thread(...)``.
    from cullis_connector.config import _resolve_env_ca_path
    _ca_chain_pem: str | None = None
    _ca_path = _resolve_env_ca_path()
    if _ca_path is not None:
        try:
            with open(_ca_path, "r", encoding="utf-8") as _f:
                _ca_chain_pem = _f.read()
        except OSError as _exc:
            _log.warning(
                "could not read CA bundle at %s: %s — TLS verify may fail",
                _ca_path, _exc,
            )

    client = CullisClient.from_user_principal_pem(
        site_url,
        principal_id=cred.principal_id,
        cert_pem=cred.cert_pem,
        key_pem=cred.key_pem,
        ca_chain_pem=_ca_chain_pem,
        timeout=_req_timeout,
    )
    client.login_via_proxy_with_local_key()
    return client


# ── unauth liveness probe ───────────────────────────────────────────

def _enforce_loopback(request: Request) -> None:
    """Apply ``require_loopback`` only when the Ambassador is configured to.

    ADR-025 escape hatch: when the local cert middleware has resolved a
    valid ``cullis_session`` cookie into a per-user UserPrincipal cert
    (``request.state.user_credentials``), the cookie + cert chain is the
    actual auth gate and the loopback check would only block legitimate
    browser traffic arriving via the Frontdesk reverse proxy. The
    handler still re-checks ``user_credentials`` to build the per-user
    CullisClient, so an unauthenticated request never reaches Mastio.
    """
    if _per_user_credentials(request) is not None:
        return
    state = getattr(request.app.state, "ambassador", None)
    if state and state.get("require_local_only", True):
        require_loopback(request)


def _enforce_bearer(request: Request, state: dict) -> None:
    """Run ``require_bearer`` unless an ADR-025 user cert is already bound.

    The bearer token is the Connector-agent-wide secret (single shared
    value), so it's the right gate when there's no per-user binding —
    e.g. Cursor / LibreChat on the laptop. The moment the cert
    middleware has minted a ``user_credentials`` from the
    ``cullis_session`` cookie, the request is already authenticated as
    that user; demanding the shared bearer on top would force the
    Frontdesk SPA to also know the agent-wide secret, defeating the
    point of per-user auth.
    """
    if _per_user_credentials(request) is not None:
        return
    require_bearer(state["bearer_token"])(request)


@router.get("/v1/ambassador/health")
def health(request: Request) -> dict:
    """Liveness check. Loopback-only, no Bearer required."""
    _enforce_loopback(request)
    state = getattr(request.app.state, "ambassador", None)
    if state is None:
        return {"status": "ok", "agent_id": None, "site_url": None}
    return {
        "status": "ok",
        "agent_id": state.get("agent_id"),
        "site_url": state.get("site_url"),
    }


# ── /v1/models ──────────────────────────────────────────────────────

def _get_state(request: Request) -> dict:
    state = getattr(request.app.state, "ambassador", None)
    if state is None:
        raise HTTPException(503, "Ambassador not initialized on this app")
    return state


# In-process cache for the upstream model list. The Mastio answer is
# stable per-deployment until an admin edits AI Providers, so a 30s
# TTL keeps the chat sidebar snappy without hammering the egress.
_MODELS_CACHE_TTL_S = 30.0
# Cached tuple is (cached_at, data, source) where source ∈ {"live",
# "fallback"} so the SPA can surface "Model list unavailable, showing
# cached defaults" instead of silently showing the wrong dropdown.
_models_cache: dict[str, tuple[float, list[dict], str]] = {}


def _fallback_models(state: dict) -> list[dict]:
    advertised = state["advertised_models"] or ["claude-haiku-4-5"]
    return [
        {"id": m, "object": "model", "owned_by": "cullis", "created": 0}
        for m in advertised
    ]


@router.get("/v1/models")
def list_models(request: Request):
    """List the models reachable through Cullis.

    Single mode (Cullis Chat desktop, ``AMBASSADOR_MODE != "shared"``):
    fall back to ``advertised_models`` when the live Mastio fetch
    fails. The desktop user keeps a usable dropdown when Mastio is
    momentarily unreachable, which matches the consumer UX baseline.

    Shared mode (Frontdesk container, ``AMBASSADOR_MODE=shared``):
    fail loud with a 503 instead of returning a hardcoded list. In
    multi-user deployments the admin configures providers via the
    Mastio dashboard; a fallback list would advertise models that
    aren't actually configured and the user would click chat only to
    get ``provider not configured`` from Mastio. ADR-034 §5 promotes
    the inconsistency upstream.
    """
    _enforce_loopback(request)
    state = _get_state(request)
    _enforce_bearer(request, state)

    # ADR-025 Phase 3 — when the cert middleware bound a per-user cert
    # to the request (``request.state.user_credentials``), key the cache
    # on ``principal_id`` and fetch live models via a per-user
    # CullisClient. The workload-cred holder would 401 at the Mastio's
    # ``location ~ ^/v1/(egress|agents|...)`` mTLS gate — the workload
    # cert is not a UserPrincipal. Mirrors the chat_completions handler
    # below and ``ambassador/shared/router.py::list_models``.
    user_creds = _per_user_credentials(request)
    cache_key = (
        user_creds.principal_id if user_creds is not None
        else state.get("agent_id") or "default"
    )
    cached = _models_cache.get(cache_key)
    now = time.monotonic()
    if cached is not None and (now - cached[0]) < _MODELS_CACHE_TTL_S:
        return _models_response(cached[1], cached[2])

    data: list[dict] = []
    source = "live"
    error_reason: str | None = None
    if user_creds is not None:
        per_user_client = None
        try:
            per_user_client = _build_user_client(request, user_creds)
            live = per_user_client.list_models()
            if live:
                data = live
            else:
                error_reason = "Mastio returned empty model list"
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            error_reason = str(exc) or exc.__class__.__name__
            _log.debug(
                "per-user /v1/models fetch failed for %s: %s",
                user_creds.principal_id, exc,
            )
        finally:
            close = getattr(per_user_client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001
                    pass
    else:
        holder = state.get("client")
        if holder is not None:
            try:
                client = holder.get()
                live = client.list_models()
                if live:
                    data = live
                else:
                    error_reason = "Mastio returned empty model list"
            except Exception as exc:
                error_reason = str(exc) or exc.__class__.__name__
                _log.debug(
                    "Mastio /v1/models fetch failed: %s", exc,
                )
        else:
            error_reason = "Ambassador has no Mastio client wired"

    if not data:
        # Live fetch did not yield a usable list. ADR-034 §5: in
        # multi-user deployments (legacy ``AMBASSADOR_MODE=shared`` and
        # modern ``FRONTDESK_BUNDLE=1`` modern bundle alike) fail loud so
        # the SPA can banner the issue; in single-user desktop mode keep
        # the legacy fallback for UX. The 503 path skips the cache write
        # so a transient fetch error doesn't pin the dropdown to error
        # for 30s.
        if is_frontdesk_bundle():
            _log.warning(
                "Mastio /v1/models unavailable in Frontdesk bundle: %s",
                error_reason,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "mastio_unavailable",
                    "cullis_meta": {
                        "source": "error",
                        "error": error_reason or "mastio_unavailable",
                    },
                },
            )
        data = _fallback_models(state)
        source = "fallback"

    _models_cache[cache_key] = (now, data, source)
    return _models_response(data, source, error=error_reason)


def _models_response(
    data: list[dict], source: str, *, error: str | None = None,
) -> dict:
    """OpenAI-compatible body plus an additive ``cullis_meta`` block.

    OpenAI clients ignore unknown top-level fields, so this stays a
    drop-in for `api.openai.com/v1/models`. The Cullis SPA reads
    ``cullis_meta.source`` to render a banner when the live fetch
    failed and the dropdown is showing the hardcoded fallback list.
    Shared-mode failure no longer reaches this helper — see ADR-034
    §5 and the 503 branch in ``list_models``.
    """
    body: dict = {"object": "list", "data": data}
    meta: dict = {"source": source}
    if source == "fallback" and error:
        meta["error"] = error
    body["cullis_meta"] = meta
    return body


# ── /v1/chat/completions ────────────────────────────────────────────

def _completion_envelope(answer: str, model: str) -> dict:
    return {
        "id": f"chatcmpl-cullis-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": answer},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


@router.post("/v1/chat/completions")
def chat_completions(req: ChatCompletionRequest, request: Request):
    _enforce_loopback(request)
    state = _get_state(request)
    _enforce_bearer(request, state)

    client_holder: AmbassadorClient = state["client"]
    body = req.model_dump(exclude_none=True)

    # ADR-025 Phase 3 — when AUTH_MODE=local + a per-user cert was
    # bound to the request by ``cert_middleware``, prefer it over the
    # Connector-agent client_holder. Mirrors how the shared-mode
    # router builds a per-user CullisClient (see
    # ``ambassador/shared/router.py::_build_user_client``) so the
    # downstream Mastio sees the user's SPIFFE id, not the Connector's
    # agent id, on chat traffic.
    user_creds = _per_user_credentials(request)
    if user_creds is not None:
        try:
            client = _build_user_client(request, user_creds)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            _log.exception(
                "user-bound CullisClient build failed for %s",
                user_creds.principal_id,
            )
            raise HTTPException(
                502, f"per-user Cullis cloud login failed: {exc}",
            ) from exc
    else:
        try:
            client = client_holder.get()
        except Exception as exc:
            _log.exception("ambassador SDK login failed")
            raise HTTPException(502, f"Cullis cloud login failed: {exc}") from exc

    # ADR-029 Phase D, opt-in PDP gate on each tool call inside the loop.
    # Off by default so existing deployments keep dispatching tools
    # without a per-call PDP roundtrip; once an operator enables the
    # flag on both sides (Connector and Mastio) the loop refuses tools
    # the Mastio's policy_rules.tool_rules does not authorise.
    _pdp_enabled = (os.getenv("CULLIS_CONNECTOR_TOOL_PDP_ENABLED", "false").lower()
                    in ("1", "true", "yes", "on"))
    _principal_id: str | None = None
    _principal_type = "user"
    _principal_org: str | None = None
    if user_creds is not None:
        _principal_id = user_creds.principal_id
        _principal_type = getattr(user_creds, "principal_type", "user") or "user"
        _principal_org = getattr(user_creds, "org", None)
    elif _pdp_enabled:
        # Agent-bound mode (no per-user credentials): fall back to the
        # client's own agent id so the audit row still names who acted.
        _principal_id = getattr(client, "agent_id", None)
        _principal_type = "agent"

    # P1 Tier B F2b — streaming tool-use loop opt-in. When the env
    # flag is on AND the request asks for stream=true, bridge the
    # multi-turn loop to a real SSE pass-through so the SPA's
    # ToolCallIndicator chip + audit panel render against live
    # traffic (PR #719 is the Mastio emit side, this completes the
    # browser-visible side). Default false to keep fake_stream as the
    # back-compat path while the streaming branch matures.
    _stream_loop_enabled = (
        os.getenv("CULLIS_CONNECTOR_STREAMING_LOOP", "false").lower()
        in ("1", "true", "yes", "on")
    )

    if req.stream and _stream_loop_enabled:
        def _stream_then_invalidate():
            try:
                yield from stream_tool_use_loop(
                    client,
                    body,
                    max_iters=8,
                    pdp_enabled=_pdp_enabled,
                    principal_id=_principal_id,
                    principal_type=_principal_type,
                    principal_org=_principal_org,
                )
            except Exception:
                # Mirror the non-streaming exception handling: a
                # mid-stream auth failure invalidates the cached
                # agent-bound client so the next request re-logs in
                # fresh. Per-user clients are short-lived. The error
                # then propagates and Starlette closes the connection.
                if user_creds is None:
                    client_holder.invalidate()
                _log.exception("streaming tool-use loop failed")
                raise

        return StreamingResponse(
            _stream_then_invalidate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    try:
        response, truncated = run_tool_use_loop(
            client,
            body,
            max_iters=8,
            pdp_enabled=_pdp_enabled,
            principal_id=_principal_id,
            principal_type=_principal_type,
            principal_org=_principal_org,
        )
    except Exception as exc:
        # Defensive: any auth-shaped error invalidates the cached
        # client so the next request re-logs in fresh. Per-user
        # clients are short-lived (built fresh above) so there is no
        # cache to invalidate; agent-bound traffic still goes through
        # ``client_holder``.
        if user_creds is None:
            client_holder.invalidate()
        _log.exception("tool-use loop failed")
        raise HTTPException(502, f"Cullis cloud call failed: {exc}") from exc

    model_out = body.get("model") or "claude-haiku-4-5"

    if req.stream:
        # v0.1 fake-stream: compute answer non-stream then fan out.
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
        # Echo through; clients can detect via this custom header.
        return JSONResponse(
            response, headers={"X-Cullis-Tool-Use-Truncated": "true"}
        )
    return response


# ── /v1/mcp passthrough ─────────────────────────────────────────────

@router.post("/v1/mcp")
async def mcp_passthrough(request: Request) -> JSONResponse:
    """Forward a JSON-RPC MCP body verbatim to the Cullis proxy.

    Useful for clients that want to drive the loop themselves (e.g.
    Cursor in agent mode) instead of letting the Ambassador run it.
    Bearer-authed and loopback-restricted just like the other routes.
    """
    _enforce_loopback(request)
    state = _get_state(request)
    _enforce_bearer(request, state)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "invalid JSON body")
    if not isinstance(body, dict):
        raise HTTPException(400, "MCP body must be a JSON object")

    method = body.get("method")
    if method == "tools/list":
        client = state["client"].get()
        tools = await asyncio.to_thread(client.list_mcp_tools)
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {"tools": tools},
        })
    if method == "tools/call":
        params = body.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not name:
            raise HTTPException(400, "tools/call params.name required")
        client = state["client"].get()
        try:
            result = await asyncio.to_thread(client.call_mcp_tool, name, arguments)
        except Exception as exc:
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": -32000, "message": str(exc)},
            })
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": result,
        })

    return JSONResponse({
        "jsonrpc": "2.0",
        "id": body.get("id"),
        "error": {"code": -32601, "message": f"method {method!r} not supported by Ambassador"},
    })


# ── /v1/inbox — intra-org user-to-user messaging ────────────────────
#
# ADR-008 / ADR-020: passes through to the Mastio's
# ``/v1/egress/message/{send,inbox}`` using the calling user's
# UserPrincipal cert (set by ``cert_middleware``). Auth gate mirrors
# /v1/chat/completions: when ``user_credentials`` is bound, bypass
# loopback + bearer; otherwise the route 401s. The Cullis SDK's
# ``send_oneshot`` does the resolve + sign + envelope dance, so the
# Connector just plumbs request → SDK call → response.
#
# Cross-org via broker is intentionally NOT wired here yet — the
# shared-mode router (``ambassador/shared/router.py``) carries that
# code path. Standalone Mastio + ADR-025 local-auth covers intra-org
# only, which is the v0.2 dogfood scope.

def _coerce_payload(value: Any) -> dict:
    """SPA may send the message body as a string ("ciao alice") or as a
    structured dict ({"text": "ciao alice"}). Mastio's
    ``SendOneShotRequest.payload`` is typed as ``dict``, so coerce a
    bare string to ``{"text": <str>}`` for the operator-friendly UX."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return {"text": value}
    raise HTTPException(400, "payload must be a JSON object or string")


@router.post("/v1/inbox/send")
def inbox_send(request: Request, body: dict):
    """Send a one-shot message via the Mastio's intra-org egress.

    Requires the cert middleware to have resolved a user principal
    (``request.state.user_credentials``); shared bearer + loopback
    enforcement still apply when no per-user cert is bound, so a CLI
    caller using the local Bearer can also send if it carries the
    Connector-agent identity.
    """
    user_creds = _per_user_credentials(request)
    if user_creds is None:
        _enforce_loopback(request)
        state = _get_state(request)
        _enforce_bearer(request, state)
        client_holder: AmbassadorClient = state["client"]
        try:
            client = client_holder.get()
        except Exception as exc:
            _log.exception("ambassador SDK login failed (inbox send)")
            raise HTTPException(502, f"Cullis cloud login failed: {exc}") from exc
    else:
        try:
            client = _build_user_client(request, user_creds)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            _log.exception(
                "user-bound CullisClient build failed (inbox send) for %s",
                user_creds.principal_id,
            )
            raise HTTPException(
                502, f"per-user Cullis cloud login failed: {exc}",
            ) from exc

    recipient_id = body.get("recipient_id")
    if not isinstance(recipient_id, str) or not recipient_id:
        raise HTTPException(400, "recipient_id is required (str)")
    payload = _coerce_payload(body.get("payload", ""))
    correlation_id = body.get("correlation_id")
    reply_to = body.get("reply_to")
    ttl_seconds = int(body.get("ttl_seconds", 300) or 300)
    capabilities = body.get("capabilities") or []
    if not isinstance(capabilities, list):
        raise HTTPException(400, "capabilities must be a list of strings")

    try:
        result = client.send_oneshot(
            recipient_id,
            payload,
            correlation_id=correlation_id,
            reply_to=reply_to,
            ttl_seconds=ttl_seconds,
            capabilities=capabilities,
        )
    except Exception as exc:
        _log.exception("inbox send failed for recipient=%s", recipient_id)
        raise HTTPException(502, f"inbox send failed: {exc}") from exc
    return result


@router.get("/v1/inbox")
def inbox_list(
    request: Request,
    since: str | None = None,
    limit: int = 50,
):
    """Poll the calling principal's intra-org one-shot inbox."""
    user_creds = _per_user_credentials(request)
    if user_creds is None:
        _enforce_loopback(request)
        state = _get_state(request)
        _enforce_bearer(request, state)
        client_holder: AmbassadorClient = state["client"]
        try:
            client = client_holder.get()
        except Exception as exc:
            _log.exception("ambassador SDK login failed (inbox list)")
            raise HTTPException(502, f"Cullis cloud login failed: {exc}") from exc
    else:
        try:
            client = _build_user_client(request, user_creds)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            _log.exception(
                "user-bound CullisClient build failed (inbox list) for %s",
                user_creds.principal_id,
            )
            raise HTTPException(
                502, f"per-user Cullis cloud login failed: {exc}",
            ) from exc

    params: dict[str, Any] = {"limit": int(limit)}
    if since is not None:
        params["since"] = since
    try:
        resp = client._authed_request("GET", "/v1/egress/message/inbox", params=params)
    except Exception as exc:
        _log.exception("inbox list HTTP failed")
        raise HTTPException(502, f"inbox list failed: {exc}") from exc
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, detail=resp.text[:400])
    return resp.json()


# ── Wiring helper ───────────────────────────────────────────────────

def install_ambassador(
    app: Any,
    *,
    bearer_token: str,
    client: AmbassadorClient,
    advertised_models: list[str],
    require_local_only: bool = True,
) -> None:
    """Stash Ambassador state on ``app.state.ambassador`` and mount the router.

    Caller is the ``build_app`` factory in ``cullis_connector/web.py``.
    Idempotent: if the router is already mounted, raise; we want a
    loud signal not a silent double-mount.
    """
    if hasattr(app.state, "ambassador") and app.state.ambassador:
        raise RuntimeError("Ambassador already installed on this app")
    app.state.ambassador = {
        "bearer_token": bearer_token,
        "client": client,
        "advertised_models": list(advertised_models),
        "agent_id": client.agent_id,
        "org_id": client.org_id,
        "site_url": getattr(client, "_site_url", ""),
        "require_local_only": require_local_only,
    }
    app.include_router(router)
    # Session endpoints (init / whoami / logout). The single-mode router
    # delegates to ``request.state.user_credentials`` when present (see
    # session_routes.session_whoami) so the SPA's IdentityBadge surfaces
    # the local-auth user, not the container's bearer identity.
    app.include_router(session_router)
    _log.info(
        "ambassador installed: agent=%s site=%s models=%s",
        client.agent_id, getattr(client, "_site_url", ""), advertised_models,
    )
