"""
MCP Proxy configuration — pydantic-settings with env prefix MCP_PROXY_.

All settings are read from environment variables (prefix MCP_PROXY_) or .env file.
validate_config() enforces production-safety invariants at startup.
"""
import logging
import os
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_log = logging.getLogger("mcp_proxy.startup")

_INSECURE_DEFAULT_SECRET = "change-me-in-production"


class ProxySettings(BaseSettings):
    model_config = SettingsConfigDict(env_file="proxy.env", env_prefix="MCP_PROXY_", extra="ignore")

    # Auth / Broker
    broker_jwks_url: str = ""  # e.g. "https://broker.company.com/.well-known/jwks.json"
    jwks_refresh_interval_seconds: int = 3600
    jwks_override_path: str = ""  # local file for air-gapped deploy

    proxy_public_url: str = ""  # for DPoP htu validation

    # Secrets backend
    secret_backend: str = "env"  # "env" | "vault"
    vault_addr: str = ""
    vault_token: str = ""
    vault_secret_prefix: str = "secret/data/mcp-proxy/tools"

    # Tools
    tools_config_path: str = "tools.yaml"

    # Network
    host: str = "0.0.0.0"
    port: int = 9100
    allowed_origins: str = ""
    environment: str = "development"

    # DPoP
    dpop_iat_window: int = 60
    dpop_clock_skew: int = 5

    # Dashboard
    admin_secret: str = "change-me-in-production"
    dashboard_signing_key: str = ""

    # Broker uplink (for egress)
    broker_url: str = ""
    broker_verify_tls: bool = True  # verify broker TLS cert (disable only for dev)
    org_id: str = ""
    org_secret: str = ""

    # Built-in PDP webhook URL (registered with broker during org join)
    pdp_url: str = ""

    # DB
    # Default reads from MCP_PROXY_DATABASE_URL (legacy contract).
    # PROXY_DB_URL (no prefix) takes precedence — see _apply_proxy_db_url_override.
    # ADR-001 Phase 1.3 adds PROXY_DB_URL so Helm + smoke can target Postgres
    # without touching the legacy MCP_PROXY_* surface.
    database_url: str = "sqlite+aiosqlite:///./mcp_proxy.db"

    # Rate limiting
    rate_limit_per_minute: int = 60

    # ADR-001 Phase 2 — SPIFFE routing decision.
    # trust_domain is the SPIFFE trust domain this proxy serves (matched against
    # recipient SPIFFE IDs to decide intra vs cross-org). intra_org_routing is
    # the feature flag; when false (default) behavior is unchanged and every
    # message forwards to the broker. When true, intra-org targets are
    # short-circuited with 501 until Phase 3 wires real local delivery.
    trust_domain: str = "cullis.local"
    intra_org_routing: bool = False

    # ADR-001 §10 — Transport modes + full Guardian coverage.
    # transport_intra_org selects the wire format for intra-org messages:
    #   - envelope (default): today's behavior (E2E envelope even intra-org).
    #   - mtls-only: signed-but-not-encrypted payload over mTLS, Guardian
    #     inspects in-transit at the proxy. Zero E2E overhead intra-org.
    #   - hybrid: accept both formats, prefer mtls-only when sender supports it.
    # egress_inspection_enabled toggles the POST /v1/guardian/inspect_egress
    # endpoint on the proxy. When off the endpoint returns 404 (default).
    transport_intra_org: str = "envelope"
    egress_inspection_enabled: bool = False

    # ADR-001 Phase 4c — Federation cache subscriber.
    # When enabled, a long-lived task tails the broker's federation
    # event stream and mirrors agent / policy / binding state into
    # local cache tables. Default off — flip via PROXY_FEDERATION_SYNC.
    federation_sync_enabled: bool = False

    @model_validator(mode="after")
    def _apply_proxy_db_url_override(self):
        override = os.environ.get("PROXY_DB_URL")
        if override:
            self.database_url = override
        return self

    @model_validator(mode="after")
    def _apply_routing_overrides(self):
        td = os.environ.get("PROXY_TRUST_DOMAIN")
        if td:
            self.trust_domain = td
        flag = os.environ.get("PROXY_INTRA_ORG")
        if flag is not None:
            self.intra_org_routing = flag.lower() in ("1", "true", "yes", "on")
        sync_flag = os.environ.get("PROXY_FEDERATION_SYNC")
        if sync_flag is not None:
            self.federation_sync_enabled = sync_flag.lower() in (
                "1", "true", "yes", "on",
            )
        transport = os.environ.get("PROXY_TRANSPORT_INTRA_ORG")
        if transport is not None:
            normalized = transport.strip().lower()
            if normalized not in ("envelope", "mtls-only", "hybrid"):
                raise ValueError(
                    f"PROXY_TRANSPORT_INTRA_ORG must be one of "
                    f"envelope|mtls-only|hybrid, got {transport!r}"
                )
            self.transport_intra_org = normalized
        egress_flag = os.environ.get("PROXY_EGRESS_INSPECTION_ENABLED")
        if egress_flag is not None:
            self.egress_inspection_enabled = egress_flag.lower() in (
                "1", "true", "yes", "on",
            )
        return self


def validate_config(settings: ProxySettings) -> None:
    """Validate proxy configuration at startup.

    Raises SystemExit for fatal mis-configurations in production.
    Logs warnings for non-critical issues in any mode.
    """
    is_production = settings.environment == "production"

    if is_production:
        if settings.admin_secret == _INSECURE_DEFAULT_SECRET:
            _log.critical(
                "ADMIN_SECRET is still the insecure default in production. "
                "Set MCP_PROXY_ADMIN_SECRET to a strong random value."
            )
            raise SystemExit(1)

        if not settings.broker_jwks_url:
            _log.critical(
                "BROKER_JWKS_URL is empty in production. "
                "Set MCP_PROXY_BROKER_JWKS_URL to the broker JWKS endpoint."
            )
            raise SystemExit(1)

        if settings.broker_jwks_url.startswith("http://"):
            _log.critical(
                "BROKER_JWKS_URL uses plain HTTP ('%s') in production. "
                "Use HTTPS for JWKS endpoint.", settings.broker_jwks_url
            )
            raise SystemExit(1)

    # Warnings for any environment
    if settings.admin_secret == _INSECURE_DEFAULT_SECRET:
        _log.warning(
            "ADMIN_SECRET is the insecure default '%s'. "
            "Set MCP_PROXY_ADMIN_SECRET before deploying.",
            _INSECURE_DEFAULT_SECRET,
        )

    if settings.allowed_origins.strip() == "*":
        _log.warning("ALLOWED_ORIGINS is '*' — CORS fully open.")

    if not settings.broker_jwks_url and not settings.jwks_override_path:
        _log.warning(
            "Neither BROKER_JWKS_URL nor JWKS_OVERRIDE_PATH is set. "
            "External JWT validation will not work until configured."
        )

    _log.info("Startup validation passed (environment=%s).", settings.environment)


@lru_cache
def get_settings() -> ProxySettings:
    """Return cached ProxySettings singleton."""
    return ProxySettings()
