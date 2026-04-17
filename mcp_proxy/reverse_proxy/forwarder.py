"""HTTP reverse-proxy forwarder for ADR-004 PR A.

The SDK always connects to the proxy (never direct to broker). For operations
that conceptually belong to the broker — auth token, sessions, registry — the
proxy forwards the request as-is to the configured broker URL.

Invariants:
- Method / path / query / body pass through unchanged.
- Authorization and DPoP headers pass through unchanged (the broker does the
  actual verification — the proxy is transparent at the auth layer).
- Host header from the inbound request is forwarded. The broker's DPoP htu
  validator uses request.url (derived from Host); the SDK computed htu from
  its own base URL, so they line up.
- Hop-by-hop headers (RFC 7230 §6.1) are stripped.
- Responses are returned verbatim with an extra `x-cullis-role: proxy` header
  so SDKs can detect whether they are talking to a proxy or directly to the
  broker.
"""
from __future__ import annotations

import logging
from typing import Iterable

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

_log = logging.getLogger("mcp_proxy.reverse_proxy")

FORWARDED_PREFIXES: tuple[str, ...] = (
    "/v1/broker",
    "/v1/auth",
    "/v1/registry",
    # ADR-010 Phase 6a-4 — Court's cross-org agent read API lives under
    # /v1/federation/. The proxy serves the public-key sub-path locally
    # (mcp_proxy/registry/public_key.py) and forwards the rest so SDK
    # discover() / search / get-by-id calls transit the proxy cleanly.
    "/v1/federation",
)

_HOP_BY_HOP = frozenset(
    h.lower()
    for h in (
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        # content-length is recomputed by httpx / starlette from the body.
        "content-length",
    )
)


def _filter_request_headers(headers: Iterable[tuple[bytes, bytes]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in headers:
        lname = name.decode("latin-1").lower()
        if lname in _HOP_BY_HOP:
            continue
        out[lname] = value.decode("latin-1")
    return out


def _filter_response_headers(resp: httpx.Response) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in resp.headers.items():
        if name.lower() in _HOP_BY_HOP:
            continue
        out[name] = value
    return out


def _maybe_countersign_token_body(
    path: str, method: str, body: bytes, headers: dict[str, str], app_state,
) -> None:
    """ADR-009 Phase 4 — when the reverse-proxy forwards ``POST /v1/auth/token``
    for an in-process SDK client (sender container with cert + key locally),
    inject the mastio counter-signature on its behalf. Without this, the
    Court would refuse the login since Phase 4 removed the NULL-pubkey
    legacy path. This keeps the SDK transparent — agents that ``login()``
    directly through the proxy don't need to know about counter-sig.

    Mutates ``headers`` in place. No-op when the proxy has no mastio
    identity loaded or the body isn't a valid token-request JSON.
    """
    if method != "POST" or path != "/v1/auth/token":
        return
    if "x-cullis-mastio-signature" in headers:
        return  # caller already set it — don't overwrite (login_via_proxy path)
    mgr = getattr(app_state, "agent_manager", None)
    if mgr is None or not getattr(mgr, "mastio_loaded", False):
        return
    try:
        import json as _json
        payload = _json.loads(body)
        assertion = payload.get("client_assertion")
        if not isinstance(assertion, str):
            return
        headers["x-cullis-mastio-signature"] = mgr.countersign(assertion.encode())
    except Exception as exc:  # defensive — never block the forward
        _log.warning("reverse-proxy: mastio countersign skipped: %s", exc)


async def _forward(request: Request, broker_url: str, client: httpx.AsyncClient) -> Response:
    target = broker_url.rstrip("/") + request.url.path
    if request.url.query:
        target = f"{target}?{request.url.query}"

    body = await request.body()
    headers = _filter_request_headers(request.headers.raw)

    _maybe_countersign_token_body(
        request.url.path, request.method, body, headers, request.app.state,
    )

    # The broker's DPoP htu validator needs to reconstruct the URL the SDK
    # used — but its Host reaches it via X-Forwarded-Host (uvicorn
    # --proxy-headers honours it when the peer is in FORWARDED_ALLOW_IPS).
    # The inbound Host header itself is discarded so shared ingress
    # (Traefik, nginx) can't accidentally route the forwarded request back
    # to the proxy's own vhost. httpx sets a fresh Host from broker_url.
    inbound_host = headers.pop("host", None)
    if inbound_host and not headers.get("x-forwarded-host"):
        headers["x-forwarded-host"] = inbound_host
    # If an upstream TLS terminator (Traefik, nginx) already set
    # X-Forwarded-Proto=https, keep it — request.url.scheme here is "http"
    # because the proxy listens on plain HTTP behind the terminator, and
    # overwriting would cause the broker to reconstruct the wrong htu.
    headers.setdefault("x-forwarded-proto", request.url.scheme)

    # Propagate the caller's IP so the broker's rate limiter can distinguish
    # per-agent load instead of collapsing every agent of an org onto the
    # single proxy IP. Broker must trust the proxy (FORWARDED_ALLOW_IPS) for
    # this to count — same contract as any L7 load balancer.
    client_host = request.client.host if request.client else None
    if client_host:
        existing = headers.get("x-forwarded-for")
        headers["x-forwarded-for"] = (
            f"{existing}, {client_host}" if existing else client_host
        )

    try:
        upstream = await client.request(
            request.method,
            target,
            content=body if body else None,
            headers=headers,
        )
    except httpx.ConnectError as exc:
        _log.warning("reverse-proxy: broker unreachable (%s): %s", target, exc)
        raise HTTPException(status_code=502, detail="broker unreachable") from exc
    except httpx.TimeoutException as exc:
        _log.warning("reverse-proxy: broker timeout (%s): %s", target, exc)
        raise HTTPException(status_code=504, detail="broker timeout") from exc

    out_headers = _filter_response_headers(upstream)
    out_headers["x-cullis-role"] = "proxy"

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=out_headers,
        media_type=upstream.headers.get("content-type"),
    )


def build_reverse_proxy_router() -> APIRouter:
    """Return an APIRouter that forwards the ADR-004 prefixes to the broker.

    The handler reads broker URL and httpx client from ``request.app.state`` so
    tests can monkey-patch either one and so the same router works regardless
    of the lifespan-initialized values.
    """
    router = APIRouter(tags=["reverse-proxy"])

    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]

    async def _handler(request: Request) -> Response:
        broker_url: str | None = getattr(request.app.state, "reverse_proxy_broker_url", None)
        client: httpx.AsyncClient | None = getattr(
            request.app.state, "reverse_proxy_client", None,
        )
        if not broker_url or client is None:
            raise HTTPException(
                status_code=503,
                detail="reverse proxy not configured (broker_url missing)",
            )
        return await _forward(request, broker_url, client)

    for prefix in FORWARDED_PREFIXES:
        router.add_api_route(
            f"{prefix}/{{path:path}}",
            _handler,
            methods=methods,
            include_in_schema=False,
        )
        # Also match the bare prefix (no trailing segment) — FastAPI's `path:path`
        # placeholder requires at least an empty segment, which matches ``/v1/auth/``
        # but not ``/v1/auth``. Both are valid URLs, so register the bare form too.
        router.add_api_route(
            prefix,
            _handler,
            methods=methods,
            include_in_schema=False,
        )

    return router
