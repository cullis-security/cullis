import logging
from contextlib import asynccontextmanager
from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


class _QuietBadgeFilter(logging.Filter):
    """Suppress noisy HTMX badge polling from uvicorn access log."""
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "/dashboard/badge/" in msg:
            return False
        return True


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
from app.registry.router import router as registry_router
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.config import validate_config
    validate_config(settings)
    init_telemetry()
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        pass
    await init_db()
    await init_redis(settings.redis_url)
    from app.broker.ws_manager import ws_manager
    await ws_manager.init_redis()
    async with AsyncSessionLocal() as db:
        restored = await restore_sessions(db, session_store)
        if restored:
            logger.info("Restored %d session(s) from DB", restored)
    yield
    await ws_manager.shutdown()
    await close_redis()
    shutdown_telemetry()


app = FastAPI(
    title="Agent Trust Network — Broker",
    description=(
        "Federated inter-organizational trust protocol for AI agents. "
        "Week 1 MVP: registry + JWT authentication + session broker."
    ),
    version=settings.app_version,
    lifespan=lifespan,
)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled error on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
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


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
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
    if request.url.path.startswith("/dashboard"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.tailwindcss.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
    return response

# ── API v1 ────────────────────────────────────────────────────────────────────
v1 = APIRouter(prefix="/v1")
v1.include_router(auth_router)
v1.include_router(registry_router)
v1.include_router(org_router)
v1.include_router(binding_router)
v1.include_router(broker_router)
v1.include_router(policy_router)
v1.include_router(onboarding_router)
v1.include_router(admin_router)
app.include_router(v1)

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
    """Readiness probe — all critical dependencies reachable."""
    from fastapi.responses import JSONResponse
    from sqlalchemy import text
    from app.db.database import AsyncSessionLocal

    checks: dict[str, str] = {}

    # Database
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"
        return JSONResponse({"status": "not_ready", "checks": checks}, status_code=503)

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
        checks["redis"] = f"error: {exc}"
        return JSONResponse({"status": "not_ready", "checks": checks}, status_code=503)

    # KMS
    try:
        from app.kms.factory import get_kms_provider
        kms = get_kms_provider()
        await kms.get_broker_public_key_pem()
        checks["kms"] = "ok"
    except Exception as exc:
        checks["kms"] = f"error: {exc}"
        return JSONResponse({"status": "not_ready", "checks": checks}, status_code=503)

    return {"status": "ready", "checks": checks}


@app.get("/.well-known/jwks.json", tags=["infra"])
async def jwks_endpoint():
    """Public JWKS endpoint — broker signing key(s) in JWK format (RFC 7517)."""
    from app.auth.jwt import _get_broker_keys
    from app.auth.jwks import rsa_pem_to_jwk, build_jwks, compute_kid

    _, pub_pem = await _get_broker_keys()
    kid = compute_kid(pub_pem)
    jwk = rsa_pem_to_jwk(pub_pem, kid=kid)
    return build_jwks([jwk])
