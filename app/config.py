import logging
import pathlib

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    jwt_algorithm: str = "RS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_session_token_expire_minutes: int = 60

    broker_ca_key_path: str = "certs/broker-ca-key.pem"
    broker_ca_cert_path: str = "certs/broker-ca.pem"

    broker_host: str = "0.0.0.0"
    broker_port: int = 8000

    database_url: str = "sqlite+aiosqlite:///./agent_trust.db"

    require_cert_validation: bool = False
    allowed_origins: str = ""

    environment: str = "development"  # "development" or "production"

    app_version: str = "0.1.0"

    admin_secret: str = "change-me-in-production"
    dashboard_signing_key: str = ""  # separate key for dashboard cookie HMAC; auto-generated if empty

    trust_domain: str = "atn.local"
    require_spiffe_san: bool = False

    anthropic_api_key: str = ""
    injection_llm_judge_enabled: bool = True
    injection_llm_confidence_threshold: float = 0.7

    # Redis — used for DPoP JTI store, rate limiting, and WebSocket pub/sub.
    # Empty string disables Redis; all components fall back to in-memory.
    redis_url: str = ""

    # Public URL of the broker — used to build canonical HTU for DPoP proof
    # validation behind a reverse proxy or load balancer.
    # Example: "https://broker.company.com"
    # If empty, the URL is reconstructed from the incoming request
    # (requires uvicorn --proxy-headers when behind a proxy).
    broker_public_url: str = ""

    # OpenTelemetry — traces and metrics exported via OTLP/gRPC to Jaeger
    otel_enabled: bool = True
    otel_service_name: str = "agent-trust-broker"
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_traces_sampler_arg: float = 1.0
    otel_metrics_export_interval_ms: int = 10000
    otel_exporter_insecure: bool = False

    # Logging — "text" (default) or "json" (structured for SIEM)
    log_format: str = "text"

    # OIDC for network admin login (optional — admin_secret remains as fallback)
    admin_oidc_issuer_url: str = ""
    admin_oidc_client_id: str = ""
    admin_oidc_client_secret: str = ""

    # Policy backend — "webhook" (per-org PDP webhooks) or "opa" (Open Policy Agent)
    policy_backend: str = "webhook"
    opa_url: str = ""  # e.g. "http://opa:8181"

    # KMS backend — "local" (filesystem) or "vault" (HashiCorp Vault KV v2)
    kms_backend: str = "local"
    vault_addr: str = ""
    vault_token: str = ""
    vault_secret_path: str = "secret/data/broker"

    class Config:
        env_file = ".env"
        extra = "ignore"


_INSECURE_DEFAULT_SECRET = "change-me-in-production"
_INSECURE_VAULT_TOKEN = "dev-root-token"
_startup_logger = logging.getLogger("agent_trust.startup")


def validate_config(settings: "Settings") -> None:
    """Validate broker configuration at startup.

    Raises SystemExit for fatal mis-configurations in production.
    Logs warnings for non-critical issues in any mode.
    """
    is_production = settings.environment == "production"

    # ── Fatal checks (production only) ─────────────────────────────────────
    if is_production:
        if not settings.database_url or settings.database_url.startswith("sqlite"):
            _startup_logger.critical(
                "DATABASE_URL is not set or points to SQLite ('%s'). "
                "Production requires PostgreSQL.", settings.database_url)
            raise SystemExit(1)

        if not pathlib.Path(settings.broker_ca_key_path).exists():
            _startup_logger.critical(
                "BROKER_CA_KEY_PATH '%s' does not exist on disk.",
                settings.broker_ca_key_path)
            raise SystemExit(1)

        if settings.admin_secret == _INSECURE_DEFAULT_SECRET:
            _startup_logger.critical(
                "ADMIN_SECRET is still the insecure default in production.")
            raise SystemExit(1)

    # ── Warning checks (all environments) ──────────────────────────────────
    if not is_production and settings.admin_secret == _INSECURE_DEFAULT_SECRET:
        _startup_logger.warning("ADMIN_SECRET is the insecure default — acceptable in dev only.")

    if not settings.redis_url:
        _startup_logger.warning("REDIS_URL not set — falling back to in-memory stores.")

    if settings.vault_token == _INSECURE_VAULT_TOKEN:
        _startup_logger.warning("VAULT_TOKEN is the default dev token '%s'.", _INSECURE_VAULT_TOKEN)

    if settings.allowed_origins.strip() == "*":
        _startup_logger.warning("ALLOWED_ORIGINS is '*' — CORS fully open.")

    _startup_logger.info("Startup validation passed (environment=%s).", settings.environment)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.admin_secret == _INSECURE_DEFAULT_SECRET:
        import logging
        logging.getLogger("agent_trust").critical(
            "SECURITY: admin_secret is set to the default value '%s'. "
            "Set ADMIN_SECRET to a strong random value before deploying to production.",
            _INSECURE_DEFAULT_SECRET,
        )
    return s
