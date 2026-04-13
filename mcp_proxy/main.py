"""
MCP Proxy — FastAPI application.

Org-level gateway between internal AI agents and the Cullis trust broker.
Standalone component with ZERO imports from app/.

Lifespan: validate_config -> init_db -> JWKS fetch -> yield -> cleanup
"""
import logging
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

    # 5. Initialize BrokerBridge for egress (if broker_url configured)
    from mcp_proxy.db import get_config
    broker_url = await get_config("broker_url") or settings.broker_url
    org_id = await get_config("org_id") or settings.org_id
    if broker_url:
        from mcp_proxy.egress.agent_manager import AgentManager
        from mcp_proxy.egress.broker_bridge import BrokerBridge
        agent_mgr = AgentManager(org_id=org_id)
        await agent_mgr.load_org_ca_from_config()
        bridge = BrokerBridge(
            broker_url=broker_url,
            org_id=org_id,
            agent_manager=agent_mgr,
            verify_tls=settings.broker_verify_tls,
        )
        app.state.broker_bridge = bridge
        _log.info("BrokerBridge initialized (broker=%s, org=%s)", broker_url, org_id)
    else:
        _log.warning("No broker_url configured — egress endpoints will return 503")

    _log.info(
        "MCP Proxy started (host=%s, port=%d, env=%s)",
        settings.host, settings.port, settings.environment,
    )

    yield

    # Cleanup
    if hasattr(app.state, "broker_bridge"):
        await app.state.broker_bridge.shutdown()
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
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"

    # DPoP-Nonce on API responses only (not on dashboard/health routes)
    _no_dpop_nonce = ("/proxy/", "/health", "/healthz", "/readyz")
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


from mcp_proxy.ingress.router import router as ingress_router
app.include_router(ingress_router)

from mcp_proxy.egress.router import router as egress_router
app.include_router(egress_router)

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
