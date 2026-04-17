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

    trust_domain: str = "cullis.local"
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

    # ADR-002 — A2A protocol adapter at the broker edge. When false (default),
    # /v1/a2a/* endpoints are not registered. Cullis-native surface stays
    # always-on. Phase 2a only exposes read-only AgentCard + directory.
    a2a_adapter: bool = False

    # OpenTelemetry — traces and metrics exported via OTLP/gRPC to Jaeger
    otel_enabled: bool = True
    otel_service_name: str = "cullis-broker"
    otel_exporter_otlp_endpoint: str = "http://localhost:4317"
    otel_traces_sampler_arg: float = 1.0
    otel_metrics_export_interval_ms: int = 10000
    otel_exporter_insecure: bool = False

    # Prometheus /metrics endpoint — when true, the broker exposes metrics
    # at /metrics for Prometheus scrape, in addition to the OTLP push.
    # Required by the alert rules in enterprise-kit/monitoring/.
    prometheus_enabled: bool = False

    # Logging — "text" (default) or "json" (structured for SIEM)
    log_format: str = "text"

    # OIDC for network admin login (optional — admin_secret remains as fallback)
    admin_oidc_issuer_url: str = ""
    admin_oidc_client_id: str = ""
    admin_oidc_client_secret: str = ""

    # Policy backend — "webhook" (per-org PDP webhooks) or "opa" (Open Policy Agent)
    policy_backend: str = "webhook"
    opa_url: str = ""  # e.g. "http://opa:8181"
    policy_enforcement: bool = True  # False = bypass all policy checks (demo mode)
    # SSRF escape hatch for the PDP webhook validator. When False (the
    # production default) the broker rejects any webhook URL that resolves
    # to a private/loopback/link-local/reserved IP. Set to True ONLY for
    # local docker compose / e2e / demo stacks where the PDP webhook lives
    # on the same private docker network as the broker.
    policy_webhook_allow_private_ips: bool = False

    # mTLS binding (RFC 8705 §3) — defense-in-depth at /auth/token.
    # When the broker sits behind a reverse proxy that terminates mTLS,
    # the proxy forwards the client certificate via an HTTP header. The
    # broker then verifies that the mTLS cert and the cert in the JWT
    # client_assertion (x5c) are the same — an attacker who steals a JWT
    # needs the matching client cert to open the tunnel in the first place.
    #   off      → header ignored (default, backward compatible)
    #   optional → if header present, enforce match; if absent, allow
    #   required → header must be present and match; 401 otherwise
    mtls_binding: str = "off"
    mtls_client_cert_header: str = "X-SSL-Client-Cert"

    # KMS backend — "local" (filesystem) or "vault" (HashiCorp Vault KV v2)
    kms_backend: str = "vault"
    vault_addr: str = ""
    vault_token: str = ""
    vault_secret_path: str = "secret/data/broker"

    # Audit hash chain TSA anchoring (issue #75). When enabled, a
    # background worker periodically timestamps each per-org chain head
    # with an external TSA so the broker operator cannot silently
    # rewrite history. Backend "mock" writes a deterministic broker-
    # signed anchor (ok for dev/demo but NOT dispute-grade); "rfc3161"
    # uses a real TSA per RFC 3161 (requires the `rfc3161-client`
    # runtime dep, set url via audit_tsa_url).
    audit_tsa_enabled: bool = False
    audit_tsa_backend: str = "mock"  # "mock" | "rfc3161"
    audit_tsa_url: str = "http://timestamp.digicert.com"
    audit_tsa_interval_seconds: int = 3600  # default: hourly anchor

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

        # Audit F-E-03 — KMS_BACKEND=local reads the CA private key straight
        # from the container filesystem. No audit trail, no rotation story,
        # and a ConfigMap/Secret mount compromise leaks the CA key. Only
        # 'vault' is supported in production per CLAUDE.md KMS section.
        if settings.kms_backend.lower() != "vault":
            _startup_logger.critical(
                "KMS_BACKEND=%r is not supported in production. "
                "Set KMS_BACKEND=vault (HashiCorp Vault KV v2) and configure "
                "VAULT_ADDR + VAULT_TOKEN. 'local' keeps the CA private key "
                "on the filesystem with no audit trail — dev/test only.",
                settings.kms_backend,
            )
            raise SystemExit(1)

        # Audit F-E-04 — DPoP replay protection requires a shared JTI store
        # across workers. An empty REDIS_URL in production silently falls
        # back to per-process memory: replay windows survive crashes and
        # multi-worker deploys (Helm / uvicorn --workers N>1) can't share
        # JTIs at all.
        if not settings.redis_url:
            _startup_logger.critical(
                "REDIS_URL is empty in production. A shared Redis is "
                "required for DPoP replay protection across workers "
                "(RFC 9449) — in-memory fallback is single-worker only. "
                "Set REDIS_URL to the redis:// or rediss:// URL of your "
                "shared Redis instance.",
            )
            raise SystemExit(1)

    # ── Fatal checks (all environments) ─────────────────────────────────────
    if not is_production and settings.admin_secret == _INSECURE_DEFAULT_SECRET:
        _startup_logger.critical(
            "ADMIN_SECRET is the insecure default '%s'. "
            "Run ./scripts/generate-env.sh to generate secure secrets, "
            "or set ADMIN_SECRET in .env.",
            _INSECURE_DEFAULT_SECRET)
        raise SystemExit(1)

    if not settings.redis_url:
        _startup_logger.warning("REDIS_URL not set — falling back to in-memory stores.")

    # Catch a common foot-gun: a developer's local .env sets BROKER_PUBLIC_URL
    # for the docker-compose nginx proxy (e.g. https://localhost:8443) and
    # then runs unit tests, which causes every authenticated test to fail
    # with "Invalid DPoP proof: htu mismatch". The conftest neutralizes this
    # via env override, but a non-test dev process will still see odd auth
    # failures if the URL does not match how clients actually reach the
    # broker. See imp/plan.md item 4 bonus 2.
    if not is_production and settings.broker_public_url:
        _startup_logger.warning(
            "BROKER_PUBLIC_URL is set to %r in development mode. "
            "Verify clients reach the broker via this exact URL — any "
            "mismatch will cause `Invalid DPoP proof: htu mismatch` 401s.",
            settings.broker_public_url,
        )

    if settings.vault_token == _INSECURE_VAULT_TOKEN:
        _startup_logger.warning("VAULT_TOKEN is the default dev token '%s'.", _INSECURE_VAULT_TOKEN)

    if settings.allowed_origins.strip() == "*":
        _startup_logger.warning("ALLOWED_ORIGINS is '*' — CORS fully open.")

    if not settings.dashboard_signing_key:
        if is_production:
            _startup_logger.critical(
                "DASHBOARD_SIGNING_KEY is not set in production. "
                "Sessions will not survive restarts or work across workers.")
            raise SystemExit(1)
        else:
            _startup_logger.warning(
                "DASHBOARD_SIGNING_KEY not set — auto-generating per-process key. "
                "Dashboard sessions will not persist across restarts.")

    _startup_logger.info(
        "Startup validation passed (environment=%s, kms_backend=%s, redis=%s).",
        settings.environment,
        settings.kms_backend,
        "configured" if settings.redis_url else "in-memory",
    )


_policy_override: bool | None = None  # None = use Settings value


def is_policy_enforced() -> bool:
    """Check whether policy enforcement is active (runtime-toggleable)."""
    if _policy_override is not None:
        return _policy_override
    return get_settings().policy_enforcement


def set_policy_enforcement(enabled: bool) -> None:
    """Toggle policy enforcement at runtime (admin dashboard use).

    In production, disabling policy enforcement is blocked to prevent
    accidental or malicious deactivation of access controls.
    """
    if not enabled and get_settings().environment == "production":
        raise ValueError("Cannot disable policy enforcement in production")
    global _policy_override
    _policy_override = enabled


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
