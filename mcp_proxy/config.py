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
    # Verify Vault TLS cert (disable only for dev / self-signed sandbox).
    # When ``vault_ca_cert_path`` is set, it takes precedence: httpx will use
    # the file as the CA bundle and ignore ``vault_verify_tls``. Mirrors the
    # broker-side pattern in ``app/kms/vault.py``.
    vault_verify_tls: bool = True
    vault_ca_cert_path: str = ""

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

    # Break-glass re-enable for the local admin password sign-in path.
    # Normal state: operators flip the toggle in Settings → Sign-in methods,
    # which writes ``proxy_config.local_password_enabled`` in the DB. Setting
    # this env var to 1/true at boot forces the password form on regardless
    # of the stored flag, so an operator who has locked themselves out after
    # an IdP outage can still reach the dashboard from the host. Paired with
    # the ``cullis-proxy reset-password`` CLI. Mirror of Grafana's
    # ``GF_AUTH_DISABLE_LOGIN_FORM`` pattern (inverted).
    force_local_password: bool = False

    # Standalone mode — ship the proxy as a product on its own, without a
    # Cullis broker in front of it. When true:
    #   - BrokerBridge and the reverse-proxy httpx client are not initialized.
    #   - /readyz skips the JWKS cache check (there is no broker to fetch from).
    #   - validate_config() does not require BROKER_JWKS_URL in production.
    #   - Dashboard responses carry x-cullis-mode: standalone.
    # Intra-org flows (enrollment, /v1/egress/*, local sessions, Guardian)
    # keep working unchanged. Federation can be turned on later by flipping
    # this to false and setting broker_url/broker_jwks_url.
    standalone: bool = False

    # Broker uplink (for egress) — ignored in standalone mode.
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

    # Redis — optional. Empty = in-memory JTI store + rate limiter (single-
    # instance Mastio is fine without Redis). Multi-worker / HA deploys MUST
    # set this so the DPoP JTI store is shared across workers (audit F-B-12).
    # Accepts redis:// or rediss:// URLs.
    redis_url: str = ""

    # Egress DPoP mode — audit F-B-11 Phase 1 (#181).
    # Controls whether ``/v1/egress/*`` handlers accept a DPoP proof
    # (RFC 9449) in addition to the legacy ``X-API-Key`` bearer:
    #   off      → legacy bearer only (runtime pre-Phase 5).
    #   optional → DPoP accepted when headers are present; legacy still
    #              allowed. Grace-period stance for rolling out Phase 2
    #              enrollment + Phase 3/4 SDK updates without breaking
    #              in-flight clients. This is the default since
    #              F-B-11 Phase 5: handlers are wired to the DPoP-bound
    #              dep, so a Phase 3c-or-newer SDK has its proof
    #              validated and jkt-pinned end-to-end, while pre-Phase
    #              3c clients keep working against bare bearer. No
    #              egress call breaks on upgrade.
    #   required → DPoP proof mandatory on every egress call; legacy
    #              bare bearer rejected. Flipped in Phase 6 after every
    #              enrolled agent has registered a JWK thumbprint.
    # The DPoP-bound dep lives in ``mcp_proxy.auth.dpop_api_key``.
    egress_dpop_mode: str = "optional"

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
        # ``os.environ.get`` returns ``""`` when docker-compose passes
        # through an unset variable via ``${FOO:-}`` — same semantics
        # the operator means by "not set". Treat both as absent so we
        # don't silently clobber the model defaults (especially the
        # standalone auto-enable path below, which used to see the empty
        # string and conclude the operator had explicitly opted out).
        def _env(name: str) -> str | None:
            v = os.environ.get(name)
            return v if v else None

        td = _env("PROXY_TRUST_DOMAIN")
        if td:
            self.trust_domain = td
        flag = _env("PROXY_INTRA_ORG")
        if flag is not None:
            self.intra_org_routing = flag.lower() in ("1", "true", "yes", "on")
        sync_flag = _env("PROXY_FEDERATION_SYNC")
        if sync_flag is not None:
            self.federation_sync_enabled = sync_flag.lower() in (
                "1", "true", "yes", "on",
            )
        transport = _env("PROXY_TRANSPORT_INTRA_ORG")
        if transport is not None:
            normalized = transport.strip().lower()
            if normalized not in ("envelope", "mtls-only", "hybrid"):
                raise ValueError(
                    f"PROXY_TRANSPORT_INTRA_ORG must be one of "
                    f"envelope|mtls-only|hybrid, got {transport!r}"
                )
            self.transport_intra_org = normalized
        egress_flag = _env("PROXY_EGRESS_INSPECTION_ENABLED")
        if egress_flag is not None:
            self.egress_inspection_enabled = egress_flag.lower() in (
                "1", "true", "yes", "on",
            )
        standalone_flag = _env("MCP_PROXY_STANDALONE")
        if standalone_flag is not None:
            self.standalone = standalone_flag.lower() in (
                "1", "true", "yes", "on",
            )

        force_pwd = _env("MCP_PROXY_FORCE_LOCAL_PASSWORD")
        if force_pwd is not None:
            self.force_local_password = force_pwd.lower() in (
                "1", "true", "yes", "on",
            )

        # ADR-006 Fase 1 — standalone mode IS the mini-broker. Without
        # intra-org routing the egress endpoints fall through to a
        # non-existent BrokerBridge and 503. Flip the flag on by default
        # whenever standalone is set and the operator hasn't explicitly
        # overridden it via PROXY_INTRA_ORG. An explicit
        # PROXY_INTRA_ORG=0 still wins (useful for intentional "no
        # traffic" deployments — e.g. schema-only validation in CI).
        if self.standalone and _env("PROXY_INTRA_ORG") is None:
            self.intra_org_routing = True
        # Standalone also flips the default intra-org transport from
        # "envelope" to "mtls-only". The envelope resolve handler does
        # not populate target_cert_pem for intra-org peers, so the SDK
        # send_oneshot path fails with a misleading "cross-org one-shot
        # requires recipient public key" error on a fresh install. The
        # mtls-only path short-circuits through the proxy itself and
        # works out of the box. Operators who explicitly set
        # PROXY_TRANSPORT_INTRA_ORG keep full control.
        if self.standalone and _env("PROXY_TRANSPORT_INTRA_ORG") is None:
            self.transport_intra_org = "mtls-only"
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

        # JWKS is only required when the proxy fronts a broker. Standalone
        # deploys (no broker) have no JWKS endpoint to fetch from; enforcing
        # it would block the intended ship-on-its-own mode.
        if not settings.standalone:
            if not settings.broker_jwks_url:
                _log.critical(
                    "BROKER_JWKS_URL is empty in production. "
                    "Set MCP_PROXY_BROKER_JWKS_URL to the broker JWKS "
                    "endpoint, or set MCP_PROXY_STANDALONE=true to run "
                    "without a broker."
                )
                raise SystemExit(1)

            if settings.broker_jwks_url.startswith("http://"):
                _log.critical(
                    "BROKER_JWKS_URL uses plain HTTP ('%s') in production. "
                    "Use HTTPS for JWKS endpoint.", settings.broker_jwks_url
                )
                raise SystemExit(1)

            if not settings.broker_verify_tls:
                _log.critical(
                    "MCP_PROXY_BROKER_VERIFY_TLS is false in production. "
                    "Re-enable TLS verification for the broker uplink "
                    "(audit F-E-01)."
                )
                raise SystemExit(1)

        # Vault TLS verification is enforced whenever a Vault backend is
        # configured in production, regardless of standalone mode (the
        # standalone proxy may still use Vault to hold agent private keys).
        if settings.secret_backend == "vault" and not settings.vault_verify_tls:
            _log.critical(
                "MCP_PROXY_VAULT_VERIFY_TLS is false in production with "
                "secret_backend=vault. Re-enable TLS verification for Vault "
                "(audit F-E-02). Pin a private CA via "
                "MCP_PROXY_VAULT_CA_CERT_PATH instead if you need to trust a "
                "self-signed Vault cert."
            )
            raise SystemExit(1)

        # Audit F-E-03 (proxy analogue) — secret_backend=env keeps connector
        # and agent private keys in the proxy process environment or in the
        # local sqlite, with no audit trail on reads and no rotation story.
        # Only 'vault' is supported in production. Mirrors the broker's
        # KMS_BACKEND=vault requirement.
        if settings.secret_backend.lower() != "vault":
            _log.critical(
                "MCP_PROXY_SECRET_BACKEND=%r is not supported in production. "
                "Set MCP_PROXY_SECRET_BACKEND=vault and configure "
                "MCP_PROXY_VAULT_ADDR + MCP_PROXY_VAULT_TOKEN. 'env' keeps "
                "agent private keys at rest in the process environment — "
                "dev/test only.",
                settings.secret_backend,
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

    # Audit F-B-12 — Mastio keeps a DPoP JTI cache and per-agent rate
    # limiter in process memory by default. Single-instance deployments
    # (the current Mastio mainstream) work fine without Redis. Operators
    # running Mastio multi-worker or multi-replica (HA) MUST set
    # MCP_PROXY_REDIS_URL so the JTI store is shared — otherwise a
    # captured DPoP proof can be replayed once per worker within the iat
    # window, and the advertised per-agent rate budget multiplies by N.
    if is_production and not settings.redis_url:
        _log.warning(
            "MCP_PROXY_REDIS_URL is empty in production. Safe for "
            "single-instance Mastio; set MCP_PROXY_REDIS_URL before "
            "scaling to multiple workers or replicas (audit F-B-12: "
            "cross-worker DPoP replay + rate-limit budget multiplies)."
        )

    if not settings.broker_jwks_url and not settings.jwks_override_path:
        _log.warning(
            "Neither BROKER_JWKS_URL nor JWKS_OVERRIDE_PATH is set. "
            "External JWT validation will not work until configured."
        )

    _log.info(
        "Startup validation passed (environment=%s, secret_backend=%s, "
        "standalone=%s).",
        settings.environment,
        settings.secret_backend,
        settings.standalone,
    )


@lru_cache
def get_settings() -> ProxySettings:
    """Return cached ProxySettings singleton."""
    return ProxySettings()


def broker_tls_verify(settings: ProxySettings) -> bool | str:
    """Return the ``verify=`` value to use for broker-directed httpx calls.

    Mirrors the broker-side pattern in ``app/kms/vault.py``: a CA path wins
    over the boolean flag, otherwise the flag decides. Callers should pass
    the result straight into ``httpx.AsyncClient(verify=...)``.
    """
    # Proxy has no dedicated broker CA path today; expose the hook anyway
    # so upgrades can pin a private CA without touching every call site.
    ca_path = getattr(settings, "broker_ca_cert_path", "") or ""
    return ca_path if ca_path else settings.broker_verify_tls


def vault_tls_verify(settings: ProxySettings) -> bool | str:
    """Return the ``verify=`` value to use for Vault-directed httpx calls.

    If ``vault_ca_cert_path`` is set, httpx uses that file as the CA bundle;
    otherwise the boolean ``vault_verify_tls`` flag decides. Never returns
    ``False`` silently — operators who need to ignore TLS must set the flag
    explicitly (and production rejects that in :func:`validate_config`).
    """
    return settings.vault_ca_cert_path or settings.vault_verify_tls
