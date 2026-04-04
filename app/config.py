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
    allowed_origins: str = "*"

    app_version: str = "0.1.0"

    admin_secret: str = "change-me-in-production"

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

    # KMS backend — "local" (filesystem) or "vault" (HashiCorp Vault KV v2)
    kms_backend: str = "local"
    vault_addr: str = ""
    vault_token: str = ""
    vault_secret_path: str = "secret/data/broker"

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
