"""
MCP Proxy — FastAPI application.

Org-level gateway between internal AI agents and the Cullis trust broker.
Standalone component with ZERO imports from app/.

Lifespan: validate_config -> init_db -> JWKS fetch -> yield -> cleanup
"""
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from mcp_proxy.config import get_settings, validate_config
from mcp_proxy.db import dispose_db, get_db, init_db
from mcp_proxy.logging_setup import configure_json_logging

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

configure_json_logging()
_log = logging.getLogger("mcp_proxy")

# ─────────────────────────────────────────────────────────────────────────────
# JWKS client reference (set during lifespan)
# ─────────────────────────────────────────────────────────────────────────────

_jwks_client = None


def get_jwks_client():
    """Return the global JWKSClient instance (available after startup)."""
    return _jwks_client


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _jwks_client
    settings = get_settings()

    # 1. Validate configuration
    validate_config(settings)

    # 2. Initialize database
    await init_db(settings.database_url)

    # 3. Initialize JWKS client (for external JWT validation)
    from mcp_proxy.auth.jwks_client import JWKSClient
    _jwks_client = JWKSClient(
        jwks_url=settings.broker_jwks_url,
        override_path=settings.jwks_override_path,
        refresh_interval=settings.jwks_refresh_interval_seconds,
    )
    if settings.broker_jwks_url or settings.jwks_override_path:
        try:
            await _jwks_client.fetch()
            _log.info("JWKS cache populated")
        except Exception as exc:
            _log.warning("JWKS initial fetch failed (will retry on demand): %s", exc)

    # 4. Generate initial DPoP nonce
    from mcp_proxy.auth.dpop import generate_dpop_nonce
    generate_dpop_nonce()

    # 5. Initialize BrokerBridge for egress (if broker_url configured and
    # the proxy is not in standalone mode). Standalone deploys skip broker
    # uplink entirely — the reverse-proxy catch-all will 503 on any
    # federation-bound path, and /readyz won't fail on JWKS staleness.
    from mcp_proxy.db import get_config
    if settings.standalone:
        broker_url = ""
        org_id = settings.org_id
        app.state.reverse_proxy_broker_url = None
        app.state.reverse_proxy_client = None
        _log.info("Standalone mode — broker uplink skipped.")
    else:
        broker_url = await get_config("broker_url") or settings.broker_url
        org_id = await get_config("org_id") or settings.org_id

        # ADR-004 PR A — reverse-proxy httpx client. One shared AsyncClient
        # so the forwarder re-uses HTTP/2 connections across requests.
        import httpx as _httpx
        app.state.reverse_proxy_broker_url = broker_url
        app.state.reverse_proxy_client = _httpx.AsyncClient(
            timeout=30.0,
            verify=settings.broker_verify_tls,
            follow_redirects=False,
        )

    if broker_url:
        from mcp_proxy.egress.agent_manager import AgentManager
        from mcp_proxy.egress.broker_bridge import BrokerBridge
        agent_mgr = AgentManager(org_id=org_id, trust_domain=settings.trust_domain)
        await agent_mgr.load_org_ca_from_config()
        bridge = BrokerBridge(
            broker_url=broker_url,
            org_id=org_id,
            agent_manager=agent_mgr,
            verify_tls=settings.broker_verify_tls,
            trust_domain=settings.trust_domain,
            intra_org_routing=settings.intra_org_routing,
        )
        app.state.broker_bridge = bridge
        _log.info(
            "BrokerBridge initialized (broker=%s, org=%s, trust_domain=%s, intra_org=%s)",
            broker_url, org_id, settings.trust_domain, settings.intra_org_routing,
        )
    else:
        _log.warning("No broker_url configured — egress endpoints will return 503")

    # ADR-001 Phase 3a — local session store (intra-org mini-broker).
    # Instantiated regardless of the feature flag so the DB schema is always
    # readable; the egress router only dispatches into it when the flag is on
    # and the routing decision returns "intra".
    from mcp_proxy.local.persistence import restore_sessions
    from mcp_proxy.local.session import LocalSessionStore
    from mcp_proxy.local.ws_manager import LocalConnectionManager
    local_store = LocalSessionStore()
    try:
        await restore_sessions(local_store)
    except Exception as exc:
        _log.warning("Failed to restore local sessions from DB: %s", exc)
    app.state.local_session_store = local_store

    # Phase 3b — local WS manager. Phase 3c will plug this into message
    # delivery (push-vs-queue decision). Today the endpoint accepts
    # connections so SDKs can start depending on it behind the same
    # PROXY_INTRA_ORG flag.
    app.state.local_ws_manager = LocalConnectionManager()

    # Phase 3d — sweeper. Closes idle/TTL-expired local sessions and
    # expires pending messages whose TTL lapsed, best-effort notifying
    # peers. Only spawned when PROXY_INTRA_ORG is on (otherwise no
    # intra-org traffic ever lands in local_* tables, so there's
    # nothing to sweep). Also explicitly skippable via
    # PROXY_LOCAL_SWEEPER_DISABLED=1 for deterministic tests.
    if settings.intra_org_routing and os.environ.get("PROXY_LOCAL_SWEEPER_DISABLED") != "1":
        from mcp_proxy.local.sweeper import sweeper_loop as _local_sweeper_loop
        stop_event = asyncio.Event()
        sweeper_task = asyncio.create_task(
            _local_sweeper_loop(
                local_store,
                app.state.local_ws_manager,
                stop_event=stop_event,
            ),
            name="local_sweeper",
        )
        app.state.local_sweeper_stop = stop_event
        app.state.local_sweeper_task = sweeper_task

    # Phase 4c — federation SSE subscriber. Wires the Phase 4b cache
    # to the live broker stream. Off by default; flip via
    # PROXY_FEDERATION_SYNC=true. The auth surface (DPoP / mTLS / SPIFFE)
    # is delegated to an externally-provided client factory set on
    # `app.state.federation_subscriber_factory`. Wiring an actual
    # credential is a follow-up — keeping the factory injectable lets
    # deployments pick the auth flavor without forking this module.
    if settings.federation_sync_enabled and broker_url and org_id:
        factory = getattr(app.state, "federation_subscriber_factory", None)
        if factory is None:
            _log.warning(
                "PROXY_FEDERATION_SYNC=on but no "
                "federation_subscriber_factory registered on app.state "
                "— subscriber not started. Set one before app startup.",
            )
        else:
            from mcp_proxy.sync.subscriber import (
                SubscriberConfig,
                run_subscriber,
            )
            sub_cfg = SubscriberConfig(
                broker_url=broker_url,
                org_id=org_id,
                client_factory=factory,
            )
            sub_stop = asyncio.Event()
            sub_task = asyncio.create_task(
                run_subscriber(sub_cfg, stop_event=sub_stop),
                name="federation_subscriber",
            )
            app.state.federation_subscriber_stop = sub_stop
            app.state.federation_subscriber_task = sub_task
            app.state.federation_subscriber_stats = sub_cfg.stats
            _log.info("federation subscriber started (org=%s)", org_id)

    _log.info(
        "MCP Proxy started (host=%s, port=%d, env=%s)",
        settings.host, settings.port, settings.environment,
    )

    yield

    # Cleanup
    stop_event = getattr(app.state, "local_sweeper_stop", None)
    sweeper_task = getattr(app.state, "local_sweeper_task", None)
    if stop_event is not None:
        stop_event.set()
    if sweeper_task is not None:
        try:
            await asyncio.wait_for(sweeper_task, timeout=5.0)
        except asyncio.TimeoutError:
            sweeper_task.cancel()
            try:
                await sweeper_task
            except (asyncio.CancelledError, Exception):
                pass

    sub_stop = getattr(app.state, "federation_subscriber_stop", None)
    sub_task = getattr(app.state, "federation_subscriber_task", None)
    if sub_stop is not None:
        sub_stop.set()
    if sub_task is not None:
        try:
            await asyncio.wait_for(sub_task, timeout=5.0)
        except asyncio.TimeoutError:
            sub_task.cancel()
            try:
                await sub_task
            except (asyncio.CancelledError, Exception):
                pass

    ws_manager = getattr(app.state, "local_ws_manager", None)
    if ws_manager is not None:
        await ws_manager.shutdown()
    bridge = getattr(app.state, "broker_bridge", None)
    if bridge is not None:
        await bridge.shutdown()
    rp_client = getattr(app.state, "reverse_proxy_client", None)
    if rp_client is not None:
        await rp_client.aclose()
    if _jwks_client:
        await _jwks_client.close()
    await dispose_db()
    _log.info("MCP Proxy shutdown complete")


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Cullis MCP Proxy",
    description=(
        "Org-level MCP gateway for the Cullis trust network. "
        "Routes tool calls from internal AI agents through the trust broker."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


# ─────────────────────────────────────────────────────────────────────────────
# Exception handler
# ─────────────────────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    import traceback
    tb = traceback.format_exception(type(exc), exc, exc.__traceback__)
    _log.error(
        "Unhandled error on %s %s: %s\n%s",
        request.method, request.url.path, exc, "".join(tb),
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ─────────────────────────────────────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────────────────────────────────────

settings = get_settings()
_cors_origins = [o.strip() for o in settings.allowed_origins.split(",") if o.strip()]

if _cors_origins:
    _cors_allow_credentials = "*" not in _cors_origins
    if not _cors_allow_credentials:
        _log.warning("CORS allow_origins='*' — credentials disabled.")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=_cors_allow_credentials,
        allow_methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "DPoP", "X-API-Key"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Security headers middleware
# ─────────────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Let operators tell at a glance whether this proxy is running
    # standalone or fronting a Cullis broker.
    response.headers.setdefault(
        "x-cullis-mode",
        "standalone" if get_settings().standalone else "federation",
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"

    # DPoP-Nonce on API responses only (not on dashboard/health routes, and
    # not on ADR-004 reverse-proxied paths — those carry the broker's own
    # DPoP-Nonce header verbatim; overriding it here would break the SDK's
    # use_dpop_nonce retry loop).
    from mcp_proxy.reverse_proxy import FORWARDED_PREFIXES as _RP_PREFIXES
    _no_dpop_nonce = ("/proxy/", "/health", "/healthz", "/readyz") + _RP_PREFIXES
    if not any(request.url.path.startswith(p) for p in _no_dpop_nonce):
        from mcp_proxy.auth.dpop import get_current_dpop_nonce
        response.headers["DPoP-Nonce"] = get_current_dpop_nonce()

    # CSP on dashboard pages.
    # Shake-out P0-09 + P1-10: htmx and Tailwind are now bundled under /static,
    # so cdn.tailwindcss.com and unpkg.com are no longer whitelisted.
    # Google Fonts is still allowed for the webfonts link (consider bundling next).
    if request.url.path.startswith("/proxy") or request.url.path.startswith("/static"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )

    return response


# ─────────────────────────────────────────────────────────────────────────────
# Routers
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Built-in PDP endpoint — the broker calls this for policy decisions
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/pdp/policy", tags=["pdp"])
async def pdp_policy(request: Request):
    """Policy Decision Point webhook.

    The broker calls this endpoint for every session request involving this org.
    Evaluates rules from the dashboard Policies page (proxy_config DB).
    Default: allow all (empty rules = no restrictions).
    """
    import json as _json
    from mcp_proxy.db import get_config

    body = await request.json()
    initiator = body.get("initiator_agent_id", "?")
    target = body.get("target_agent_id", "?")
    context = body.get("session_context", "?")

    # Load rules from DB (configured via dashboard Policies page)
    rules_raw = await get_config("policy_rules")
    if rules_raw:
        try:
            rules = _json.loads(rules_raw)
        except _json.JSONDecodeError:
            rules = {}
    else:
        rules = {}

    # Evaluate rules (empty = allow all)
    decision = "allow"
    reason = ""

    blocked = rules.get("blocked_agents", [])
    if initiator in blocked or target in blocked:
        decision = "deny"
        reason = f"Agent blocked by policy"

    allowed_orgs = rules.get("allowed_orgs", [])
    if allowed_orgs:
        initiator_org = body.get("initiator_org_id", "")
        target_org = body.get("target_org_id", "")
        peer_org = initiator_org if context == "target" else target_org
        if peer_org not in allowed_orgs:
            decision = "deny"
            reason = f"Organization '{peer_org}' not in allowed list"

    allowed_caps = rules.get("capabilities", [])
    if allowed_caps and isinstance(allowed_caps, list):
        requested = body.get("capabilities", [])
        denied = [c for c in requested if c not in allowed_caps]
        if denied:
            decision = "deny"
            reason = f"Capabilities not allowed: {denied}"

    _log.info("PDP %s: %s -> %s (ctx=%s) %s", decision.upper(), initiator, target, context, reason)

    resp: dict = {"decision": decision}
    if reason:
        resp["reason"] = reason
    return JSONResponse(resp)


@app.get("/pdp/health", tags=["pdp"])
async def pdp_health():
    """PDP health check."""
    return {"status": "ok", "mode": "built-in"}


# ADR-004 PR D — proxy-native /v1/auth/sign-assertion. Must precede the
# reverse-proxy catch-all so the sign endpoint wins route matching.
from mcp_proxy.auth.sign_assertion import router as sign_assertion_router
app.include_router(sign_assertion_router)

# ADR-004 PR A — reverse-proxy router for /v1/broker/*, /v1/auth/*,
# /v1/registry/*. Registered before local handlers so the proxy owns these
# paths by default; local endpoints live under /v1/egress/* and /v1/ingress/*.
from mcp_proxy.reverse_proxy import build_reverse_proxy_router
app.include_router(build_reverse_proxy_router())

from mcp_proxy.ingress.router import router as ingress_router
app.include_router(ingress_router)

from mcp_proxy.egress.router import router as egress_router
app.include_router(egress_router)

from mcp_proxy.local.ws_router import router as local_ws_router
app.include_router(local_ws_router)

from mcp_proxy.enrollment.router import router as enrollment_router
app.include_router(enrollment_router)

from mcp_proxy.audit.router import router as audit_router
app.include_router(audit_router)

from mcp_proxy.dashboard.router import router as dashboard_router
app.include_router(dashboard_router)

# Static assets for the dashboard (compiled Tailwind CSS + bundled htmx).
# Shake-out P0-09 + P1-10: serve /static/css/tailwind.css and /static/vendor/htmx.min.js
# locally instead of pulling from cdn.tailwindcss.com / unpkg.com.
_static_dir = Path(__file__).parent / "dashboard" / "static"
if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


# ─────────────────────────────────────────────────────────────────────────────
# Health endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["infra"])
async def health():
    """Basic health check — always 200 if the process is running."""
    return {"status": "ok", "version": "0.1.0"}


@app.get("/healthz", tags=["infra"])
async def healthz():
    """Liveness probe — process is alive."""
    return {"status": "ok"}


@app.get("/readyz", tags=["infra"])
async def readyz():
    """Readiness probe — checks DB writable and JWKS cache age."""
    checks: dict[str, str] = {}

    # Database writable
    try:
        async with get_db() as db:
            await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"
        return JSONResponse(
            {"status": "not_ready", "checks": checks}, status_code=503,
        )

    # Standalone deploys have no broker, so no JWKS to check — skip.
    if get_settings().standalone:
        checks["jwks_cache"] = "standalone"
        return {"status": "ready", "checks": checks}

    # JWKS cache freshness — distinguish "never fetched" from "stale".
    # A proxy that has never talked to the broker (e.g. first boot in
    # a fresh cluster, broker not up yet) should NOT fail readyz: it
    # can still serve egress endpoints and will fetch JWKS lazily when
    # an ingress request needs it. Only "was fresh, now stale" is a
    # real readiness problem worth propagating to the load balancer.
    jwks = get_jwks_client()
    if jwks is not None and (jwks._jwks_url or jwks._override_path):
        if jwks._last_fetch == 0:
            checks["jwks_cache"] = "initializing"
        else:
            age = time.time() - jwks._last_fetch
            max_age = get_settings().jwks_refresh_interval_seconds * 2
            if age <= max_age:
                checks["jwks_cache"] = "ok"
            else:
                checks["jwks_cache"] = f"stale (age={age:.0f}s, max={max_age}s)"
                return JSONResponse(
                    {"status": "not_ready", "checks": checks}, status_code=503,
                )
    else:
        checks["jwks_cache"] = "not_configured"

    return {"status": "ready", "checks": checks}
