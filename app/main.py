import asyncio
import logging
import signal
from contextlib import asynccontextmanager
from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


# ── Graceful shutdown coordination ───────────────────────────────────────────
# Set when SIGTERM/SIGINT arrives. While set:
#   - /readyz returns 503 (load balancer stops sending new traffic)
#   - the lifespan exits and triggers cleanup
# This is module-level so the signal handler can flip it without needing
# access to the FastAPI app instance.
_shutdown_event: asyncio.Event | None = None


def _is_draining() -> bool:
    """True once the broker has received a shutdown signal."""
    return _shutdown_event is not None and _shutdown_event.is_set()


class _QuietBadgeFilter(logging.Filter):
    """Suppress noisy HTMX badge polling from uvicorn access log."""
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "/dashboard/badge/" in msg:
            return False
        return True


from fastapi.staticfiles import StaticFiles
from app.config import get_settings
from app.telemetry import init_telemetry, shutdown_telemetry
from app.db.database import init_db, AsyncSessionLocal
from app.redis.pool import init_redis, close_redis
from app.auth.jti_blacklist import JtiBlacklist as _JtiBlacklist  # noqa — registers in Base.metadata
from app.broker.db_models import SessionRecord as _SR, SessionMessageRecord as _SMR  # noqa — registers in Base.metadata
from app.broker.notifications import Notification as _Notification  # noqa — registers in Base.metadata
from app.broker.persistence import restore_sessions
from app.broker.session import session_store
from app.auth.router import router as auth_router
from app.registry.org_router import router as org_router
from app.registry.binding_router import router as binding_router
from app.broker.router import router as broker_router
from app.policy.router import router as policy_router
from app.onboarding.router import onboarding_router, admin_router
from app.dashboard.router import router as dashboard_router

settings = get_settings()

from app.logging_config import configure_logging
configure_logging(settings.log_format)
logging.getLogger("uvicorn.access").addFilter(_QuietBadgeFilter())

logger = logging.getLogger("agent_trust")


_DRAIN_GRACE_SECONDS = 5


async def _drain_watcher() -> None:
    """
    Background task: when SIGTERM/SIGINT arrives, immediately notify every
    WebSocket client with close code 1012 ("service restart") so they can
    reconnect to another instance during the drain window.

    Without this watcher, clients only learn the broker is going away when
    the lifespan post-yield path runs — which is up to ~30 seconds after
    the signal, depending on uvicorn's graceful_timeout. By that point the
    process is about to die and clients have no time to reconnect cleanly.

    The watcher runs in parallel with normal request handling. It exits as
    soon as `notify_shutdown_to_clients()` returns; the lifespan post-yield
    path still runs the full `ws_manager.shutdown()` for cleanup, but the
    notify call there is a no-op (idempotent).
    """
    if _shutdown_event is None:
        return
    try:
        await _shutdown_event.wait()
    except asyncio.CancelledError:
        return

    logger.warning(
        "Drain watcher: shutdown signal received — notifying WebSocket clients",
    )
    from app.broker.ws_manager import ws_manager
    try:
        await ws_manager.notify_shutdown_to_clients()
    except Exception as exc:
        logger.error("Drain watcher: notify_shutdown_to_clients failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Debug: logger.info is dropped because configure_logging leaves the
    # agent_trust logger at default WARNING in text mode. Use print to
    # stderr with explicit flush so every step is visible in kubectl logs.
    import sys
    import traceback as _tb
    def _step(msg: str) -> None:
        print(f"LIFESPAN: {msg}", file=sys.stderr, flush=True)
    try:
        _step("validate_config")
        from app.config import validate_config
        validate_config(settings)
        _step("init_telemetry")
        init_telemetry()
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)
        except Exception:
            pass
        _step("init_db")
        await init_db()
        _step("ensure_bootstrapped (admin_secret)")
        from app.kms.admin_secret import ensure_bootstrapped
        await ensure_bootstrapped()
        _step("init_redis")
        await init_redis(settings.redis_url)
        _step("ws_manager.init_redis")
        from app.broker.ws_manager import ws_manager
        await ws_manager.init_redis()
        _step("restore_sessions")
        async with AsyncSessionLocal() as db:
            restored = await restore_sessions(db, session_store)
            if restored:
                logger.info("Restored %d session(s) from DB", restored)
        _step("startup steps complete")
    except BaseException as exc:
        print(
            f"LIFESPAN FAILED: {type(exc).__name__}: {exc}\n"
            f"{_tb.format_exc()}",
            file=sys.stderr, flush=True,
        )
        raise

    # ── Install SIGTERM/SIGINT handlers for graceful shutdown ────────────────
    # The handler flips _shutdown_event so:
    #   1. /readyz starts returning 503 (load balancer notice)
    #   2. _drain_watcher unblocks and immediately closes all WebSockets
    #      with code 1012 so clients can reconnect elsewhere
    #   3. uvicorn's own shutdown sequence still calls our cleanup post-yield
    global _shutdown_event
    _shutdown_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _signal_handler(signum: int) -> None:
        sig_name = signal.Signals(signum).name
        logger.warning(
            "Received %s — entering drain mode (/readyz now returns 503)",
            sig_name,
        )
        if _shutdown_event is not None:
            _shutdown_event.set()

    def _signal_handler_threadsafe(signum: int, _frame=None) -> None:
        # signal.signal callbacks run in the main thread but outside the
        # event loop. Schedule the event set on the loop instead of touching
        # asyncio internals from sync context.
        try:
            loop.call_soon_threadsafe(_signal_handler, signum)
        except RuntimeError:
            pass  # loop already closed

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _signal_handler, sig)
        except (NotImplementedError, ValueError, RuntimeError):
            # add_signal_handler raises:
            #   - NotImplementedError on Windows
            #   - ValueError for unknown signals
            #   - RuntimeError ("set_wakeup_fd only works in main thread")
            #     when the loop is running outside the main thread, e.g.
            #     under pytest-asyncio or uvicorn worker spawns.
            # Try the synchronous signal.signal fallback, which itself
            # fails with the same RuntimeError off the main thread. In
            # that case there is no signal-driven shutdown — the caller
            # must trigger via _shutdown_event directly. This is fine
            # for tests, where the lifespan is exited via httpx teardown.
            try:
                signal.signal(sig, _signal_handler_threadsafe)
            except (RuntimeError, ValueError) as exc:
                logger.debug(
                    "Cannot install signal handler for %s: %s "
                    "(graceful shutdown via signal disabled)",
                    sig, exc,
                )

    # Spawn the drain watcher. It blocks on _shutdown_event and runs the
    # WebSocket notification path the moment a signal arrives.
    drain_task = asyncio.create_task(_drain_watcher(), name="cullis-drain-watcher")

    # M1.1 — Session sweeper: periodically close idle/expired sessions,
    # persist state, and notify peers via session.closed events.
    from app.broker.session_sweeper import sweeper_loop
    sweeper_stop = asyncio.Event()
    sweeper_task = asyncio.create_task(
        sweeper_loop(session_store, stop_event=sweeper_stop),
        name="cullis-session-sweeper",
    )

    # Audit TSA worker: periodically anchor per-org chain heads to an
    # external RFC 3161 TSA. Opt-in via `audit_tsa_enabled` so default
    # deployments don't call out to the network.
    tsa_task = None
    tsa_stop = None
    if getattr(settings, "audit_tsa_enabled", False):
        from app.audit.tsa_worker import start_worker_task
        tsa_task, tsa_stop = start_worker_task(settings)

    # Enterprise plugin startup hooks. Discovered + license-filtered at
    # module import; here we let each plugin allocate its own resources
    # (e.g. SAML SP, TSA worker overrides). Failures are logged inside
    # the registry and never block core boot.
    from app.plugins import get_registry as _get_plugin_registry
    await _get_plugin_registry().run_startup(app)

    yield

    # Stop enterprise plugins before tearing down core services so they
    # can flush state (audit watermarks, TSA queues) while engine +
    # redis are still up.
    await _get_plugin_registry().run_shutdown(app)

    # ── Drain phase ──────────────────────────────────────────────────────────
    # If a signal was received, give the load balancer a few seconds to
    # notice the 503 from /readyz and stop routing new traffic before we
    # tear down DB / Redis connections. The WS notification has already
    # happened (drain_task ran the moment the event was set).
    if _shutdown_event is not None and _shutdown_event.is_set():
        logger.info(
            "Draining for %ds before tearing down connections",
            _DRAIN_GRACE_SECONDS,
        )
        await asyncio.sleep(_DRAIN_GRACE_SECONDS)

    # Cancel the drain watcher if it never fired (clean shutdown via reload
    # or test teardown that does not send a signal).
    if not drain_task.done():
        drain_task.cancel()
        try:
            await drain_task
        except (asyncio.CancelledError, Exception):
            pass

    # Stop the session sweeper cleanly.
    sweeper_stop.set()
    sweeper_task.cancel()
    try:
        await sweeper_task
    except (asyncio.CancelledError, Exception):
        pass

    # Stop the TSA worker cleanly if it was started.
    if tsa_task is not None and tsa_stop is not None:
        tsa_stop.set()
        tsa_task.cancel()
        try:
            await tsa_task
        except (asyncio.CancelledError, Exception):
            pass

    await ws_manager.shutdown()
    await close_redis()
    shutdown_telemetry()
    logger.info("Cullis broker shutdown complete")


app = FastAPI(
    title="Cullis — Federated Trust Broker",
    description=(
        "Zero-trust identity for AI agents. "
        "Federated inter-organizational trust protocol with registry, "
        "JWT authentication, and session broker."
    ),
    version=settings.app_version,
    lifespan=lifespan,
)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    import traceback
    tb = traceback.format_exception(type(exc), exc, exc.__traceback__)
    logger.error("Unhandled error on %s %s: %s\n%s", request.method, request.url.path, exc, "".join(tb))
    print(f"[500] {request.method} {request.url.path}: {exc}", flush=True)
    print("".join(tb), flush=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

_cors_origins = [o.strip() for o in settings.allowed_origins.split(",") if o.strip()]

if _cors_origins:
    if "*" in _cors_origins:
        logger.warning(
            "CORS allow_origins='*' — credentials disabled. "
            "Set ALLOWED_ORIGINS to specific origins for production."
        )
        _cors_allow_credentials = False
    else:
        _cors_allow_credentials = True

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=_cors_allow_credentials,
        allow_methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "DPoP"],
    )
else:
    logger.info(
        "CORS middleware not enabled — ALLOWED_ORIGINS is empty. "
        "Set ALLOWED_ORIGINS to allow cross-origin requests."
    )


# Enterprise plugin middlewares. Registered before `security_headers` /
# CORS so Starlette's LIFO order runs core admission first; plugins
# only see traffic that already passed the core middleware stack.
from app.plugins import get_registry as _get_plugin_registry_for_middlewares

_court_plugin_registry = _get_plugin_registry_for_middlewares()
_court_plugin_registry.add_middlewares(app)
if _court_plugin_registry.plugins:
    logger.info(
        "enterprise middlewares registered: %s",
        [p.name for p in _court_plugin_registry.plugins],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # ADR-004 — broker self-identifies so SDKs connected directly can warn
    # about the deprecated path. The proxy forwards this header unchanged
    # (the reverse-proxy middleware overwrites it with "proxy", so a caller
    # that sees "broker" is definitively talking to the broker directly).
    response.headers.setdefault("x-cullis-role", "broker")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # JWKS endpoint should be cacheable; everything else is no-store
    if request.url.path == "/.well-known/jwks.json":
        response.headers["Cache-Control"] = "public, max-age=3600"
    else:
        response.headers["Cache-Control"] = "no-store"
    # DPoP-Nonce on API responses only (RFC 9449 §8)
    _no_dpop_nonce = ("/dashboard", "/health", "/.well-known/", "/readyz")
    if not any(request.url.path.startswith(p) for p in _no_dpop_nonce):
        from app.auth.dpop import get_current_dpop_nonce
        response.headers["DPoP-Nonce"] = get_current_dpop_nonce()
    if request.url.path.startswith("/dashboard") or request.url.path.startswith("/static"):
        # Shake-out P0-09 + P1-10: htmx and Tailwind are bundled under /static,
        # so cdn.tailwindcss.com and unpkg.com are no longer whitelisted.
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

# ── API v1 ────────────────────────────────────────────────────────────────────
v1 = APIRouter(prefix="/v1")
v1.include_router(auth_router)
v1.include_router(org_router)
v1.include_router(binding_router)
v1.include_router(broker_router)
v1.include_router(policy_router)
v1.include_router(onboarding_router)
v1.include_router(admin_router)

# ADR-001 Phase 4a — federation event stream for proxies to mirror
# broker state (agent lifecycle, policies, bindings) via SSE.
from app.broker.federation_router import router as federation_router
v1.include_router(federation_router)

# ADR-008 Phase 1 PR #2 — cross-org sessionless one-shot forwarding.
from app.broker.oneshot_router import router as oneshot_router
v1.include_router(oneshot_router)

# ADR-002 Phase 2a — A2A protocol adapter (read-only AgentCard + directory).
# Gated on settings.a2a_adapter (default False) so existing deployments
# see no surface change.
if settings.a2a_adapter:
    from app.a2a.router import router as a2a_router
    v1.include_router(a2a_router)

app.include_router(v1)

# ADR-010 Phase 1 — Mastio-sovereign registry. Federation router has its
# own full /v1/federation prefix so register it at the app level.
from app.federation.publish import router as federation_router
app.include_router(federation_router)

# ADR-010 Phase 6a-1 — read-side federation API (cross-org discovery +
# public-key lookup). The legacy /v1/registry/agents GET mirror was
# dropped in Phase 6a-4; these endpoints are now the only read path.
from app.federation.read import router as federation_read_router
app.include_router(federation_read_router)

# Enterprise plugin routers. Mounted after every core router so a plugin
# can never shadow a core endpoint by registering a conflicting path;
# FastAPI keeps registration order on routing.
_court_plugin_registry.mount_routers(app)
if _court_plugin_registry.plugins:
    logger.info(
        "enterprise routers mounted from plugins: %s",
        [p.name for p in _court_plugin_registry.plugins],
    )

# ── Static files ─────────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# ── Non-versioned routes ──────────────────────────────────────────────────────
app.include_router(dashboard_router)


@app.get("/", include_in_schema=False)
async def root_redirect():
    from starlette.responses import RedirectResponse
    return RedirectResponse(url="/dashboard/login")


@app.get("/health", tags=["infra"])
async def health():
    return {"status": "ok", "version": settings.app_version}


@app.get("/healthz", tags=["infra"])
async def healthz():
    """Liveness probe — process is alive."""
    return {"status": "ok"}


@app.get("/readyz", tags=["infra"])
async def readyz():
    """Readiness probe — all critical dependencies reachable.

    Returns 503 immediately if the broker is in drain mode (received
    SIGTERM/SIGINT). The load balancer should stop sending new traffic
    while in-flight requests complete.
    """
    from fastapi.responses import JSONResponse
    from sqlalchemy import text
    from app.db.database import AsyncSessionLocal

    if _is_draining():
        return JSONResponse(
            {"status": "draining", "checks": {}},
            status_code=503,
        )

    checks: dict[str, str] = {}

    def _fail(check: str, exc: Exception) -> JSONResponse:
        checks[check] = f"error: {exc}"
        # Surface on stderr so `kubectl logs` shows why /readyz went 503.
        # Kubelet probes don't log response bodies, so without this we have
        # no way to diagnose a stuck deploy from the cluster side.
        import sys
        print(f"READYZ FAIL [{check}]: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return JSONResponse({"status": "not_ready", "checks": checks}, status_code=503)

    # Database
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        return _fail("database", exc)

    # Redis (optional — skip if not configured)
    try:
        from app.redis.pool import get_redis
        redis = get_redis()
        if redis is not None:
            await redis.ping()
            checks["redis"] = "ok"
        else:
            checks["redis"] = "not_configured"
    except Exception as exc:
        return _fail("redis", exc)

    # KMS
    try:
        from app.kms.factory import get_kms_provider
        kms = get_kms_provider()
        await kms.get_broker_public_key_pem()
        checks["kms"] = "ok"
    except Exception as exc:
        return _fail("kms", exc)

    return {"status": "ready", "checks": checks}


@app.get("/metrics", tags=["infra"], include_in_schema=False)
async def prometheus_metrics():
    """
    Prometheus scrape endpoint. Active only when PROMETHEUS_ENABLED=true.

    Exposes the same instruments emitted via OTLP, formatted in the
    Prometheus text exposition format. Use this when running an in-cluster
    Prometheus instance instead of (or alongside) the OTel collector.
    """
    from fastapi.responses import Response
    if not settings.prometheus_enabled:
        return Response("Prometheus exporter disabled\n", status_code=404,
                        media_type="text/plain")
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, REGISTRY
        return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)
    except ImportError:
        return Response("prometheus_client not installed\n", status_code=503,
                        media_type="text/plain")


@app.get("/.well-known/jwks.json", tags=["infra"])
async def jwks_endpoint():
    """Public JWKS endpoint — broker signing key(s) in JWK format (RFC 7517)."""
    from app.auth.jwt import _get_broker_keys
    from app.auth.jwks import rsa_pem_to_jwk, build_jwks, compute_kid

    _, pub_pem = await _get_broker_keys()
    kid = compute_kid(pub_pem)
    jwk = rsa_pem_to_jwk(pub_pem, kid=kid)
    return build_jwks([jwk])
