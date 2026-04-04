import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


class _QuietBadgeFilter(logging.Filter):
    """Suppress noisy HTMX badge polling from uvicorn access log."""
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "/dashboard/badge/" in msg:
            return False
        return True


logging.getLogger("uvicorn.access").addFilter(_QuietBadgeFilter())

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
logger = logging.getLogger("agent_trust")


@asynccontextmanager
async def lifespan(app: FastAPI):
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "DPoP"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # DPoP-Nonce on all API responses (RFC 9449 §8)
    if not request.url.path.startswith("/dashboard"):
        from app.auth.dpop import get_current_dpop_nonce
        response.headers["DPoP-Nonce"] = get_current_dpop_nonce()
    if request.url.path.startswith("/dashboard"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
    return response

app.include_router(auth_router)
app.include_router(registry_router)
app.include_router(org_router)
app.include_router(binding_router)
app.include_router(broker_router)
app.include_router(policy_router)
app.include_router(onboarding_router)
app.include_router(admin_router)
app.include_router(dashboard_router)


@app.get("/health", tags=["infra"])
async def health():
    return {"status": "ok", "version": settings.app_version}
