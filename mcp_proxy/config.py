"""
MCP Proxy configuration — pydantic-settings with env prefix MCP_PROXY_.

All settings are read from environment variables (prefix MCP_PROXY_) or .env file.
validate_config() enforces production-safety invariants at startup.
"""
import logging
import os
from functools import lru_cache

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_log = logging.getLogger("mcp_proxy.startup")

_INSECURE_DEFAULT_SECRET = "change-me-in-production"


class ProxySettings(BaseSettings):
    model_config = SettingsConfigDict(env_file="deploy/proxy/proxy.env", env_prefix="MCP_PROXY_", extra="ignore")

    # Auth / Broker
    broker_jwks_url: str = ""  # e.g. "https://broker.company.com/.well-known/jwks.json"
    jwks_refresh_interval_seconds: int = 3600
    jwks_override_path: str = ""  # local file for air-gapped deploy

    proxy_public_url: str = ""  # for DPoP htu validation

    # OIDC callback base URL — must be browser-reachable AND registered
    # as a redirect_uri on the IdP. Distinct from proxy_public_url
    # because that one pins the DPoP htu to the internal TLS sidecar
    # (e.g. mastio-nginx:9443) which the host browser cannot resolve
    # and which Keycloak does not have registered as a redirect_uri.
    # Falls back to proxy_public_url, then request.base_url.
    oidc_redirect_uri_base: str = ""

    # KMS backend for the Org CA (and, in follow-up, Mastio leaf keys).
    # ``local`` keeps the keys in proxy_config DB (current default,
    # works for community + small deploys). ``vault`` resolves in-tree
    # to mcp_proxy.kms.vault.VaultKMSProvider (ADR-031). Other values
    # dispatch to cullis-enterprise plugins via the ``kms_factory``
    # plugin hook — e.g. ``aws`` / ``azure`` / ``gcp`` resolve to their
    # respective cloud KMS providers when cullis-enterprise is
    # installed and the license grants the matching feature.
    kms_backend: str = "local"

    # Vault KV v2 path for the Org CA keypair (ADR-031). Used only when
    # ``kms_backend == "vault"``. Single secret per Mastio instance with
    # fields ``key_pem`` + ``cert_pem``.
    vault_org_ca_path: str = "secret/data/cullis-mastio/org-ca"

    # Vault KV v2 path for the Mastio Intermediate CA keypair
    # (three-tier hardening, audit 2026-05-18). Used only when
    # ``kms_backend == "vault"``. Empty default lets the provider
    # derive the path from ``vault_org_ca_path``'s parent + the
    # ``/intermediate-ca`` suffix (so a single env var covers both keys).
    vault_intermediate_ca_path: str = ""

    # PKI at-rest master passphrase. Required in production: the
    # ``pki_key_store`` table wraps Org Root + Intermediate private
    # keys in a Fernet envelope keyed off this value (PBKDF2-HMAC-
    # SHA256 600k iterations, salt ``b"cullis-mastio-pki-v1"``). Empty
    # in dev fails closed when ``mcp_proxy.kms.pki_at_rest`` is touched;
    # validate_config refuses to start in production when missing.
    # Aliased to ``MCP_PROXY_SECRET_ENCRYPTION_KEY_B64`` semantically
    # (both wrap sensitive at-rest material) but kept separate so an
    # operator can rotate one without touching the other.
    db_encryption_key: str = ""

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

    # ADR-014 — TLS material for the nginx sidecar that fronts the
    # Mastio. ``nginx_cert_dir`` is the path inside the Mastio
    # container where Org CA + server cert + server key are written
    # at first-boot; the sidecar mounts the same docker volume read-
    # only at ``/etc/nginx/certs``. **Empty by default** so the
    # in-process pytest lifespan doesn't try to write into
    # ``/var/lib/mastio/...`` (not writable for a non-root pytest
    # process). Compose + Helm set the real path explicitly via env /
    # ConfigMap; runtime deploys never see the empty default.
    nginx_cert_dir: str = ""
    # SAN(s) baked into the server cert. Comma-separated for multi-
    # host deployments. Default ``mastio.local`` matches the
    # docker-compose default; override with MCP_PROXY_NGINX_SAN for
    # production hostnames.
    nginx_san: str = "mastio.local"
    # Wave 2 fix 6 — runtime watcher that re-invokes
    # ``ensure_nginx_server_cert`` on a periodic tick so a container
    # up beyond ``NGINX_SERVER_CERT_VALIDITY_DAYS`` (90d) still
    # rotates the leaf before expiry. Disable only for tests or
    # one-shot debug runs; production keeps it on.
    nginx_cert_watcher_enabled: bool = True
    # Tick interval in seconds. 24h default leaves a 30-attempt retry
    # budget against the 30-day renew threshold so a transient blip on
    # a single tick is never load-bearing.
    nginx_cert_watcher_interval_seconds: int = 86400
    # Days-of-life threshold below which the watcher rewrites the
    # leaf. Matches the boot-time default in
    # ``ensure_nginx_server_cert`` for consistency between boot +
    # runtime renewal.
    nginx_cert_renew_within_days: int = 30

    # DPoP
    dpop_iat_window: int = 60
    dpop_clock_skew: int = 5

    # Dashboard
    admin_secret: str = "change-me-in-production"
    # Separate HMAC key for the dashboard session cookie. Production MUST set
    # ``MCP_PROXY_DASHBOARD_SIGNING_KEY`` — ``validate_config`` refuses to
    # start with an empty value. Development auto-generates and persists
    # the key to ``dashboard_signing_key_path`` (audit F-B-10) so multi-
    # worker deploys + restarts keep sessions intact.
    dashboard_signing_key: str = ""
    # Persisted path for the dev auto-generated signing key. Created with
    # 0600 perms on first use; reused across restarts and workers on the
    # same filesystem. Ignored when ``dashboard_signing_key`` is set.
    dashboard_signing_key_path: str = "certs/.mcp_proxy_dashboard_signing_key"

    # Optional bcrypt seed for the very first boot. When set AND no
    # ``proxy_config.admin_password_hash`` row exists yet, the lifespan
    # hashes this value and persists it so the operator can reach
    # /proxy/login without first opening /proxy/register in a browser.
    # Subsequent boots ignore this var (the existing hash wins) so a
    # rotation happens via the dashboard, not by editing the env file.
    # Empty (default) preserves the historical "browser wizard" UX.
    # Used by packaging/mastio-bundle/deploy.sh so a release tarball can
    # come up fully self-serve in CI / scripted demos / Frontdesk
    # bring-up where blocking on a browser is not acceptable.
    initial_admin_password: str = ""

    # Break-glass re-enable for the local admin password sign-in path.
    # Normal state: operators flip the toggle in Settings → Sign-in methods,
    # which writes ``proxy_config.local_password_enabled`` in the DB. Setting
    # this env var to 1/true at boot forces the password form on regardless
    # of the stored flag, so an operator who has locked themselves out after
    # an IdP outage can still reach the dashboard from the host. Paired with
    # the ``cullis-proxy reset-password`` CLI. Mirror of Grafana's
    # ``GF_AUTH_DISABLE_LOGIN_FORM`` pattern (inverted).
    force_local_password: bool = False

    # Standalone mode — the Mastio's default. ADR-006 + ADR-014 made this
    # the canonical shape: the proxy runs as a self-contained mini-broker
    # for its own org, with no Court uplink. The wizard derives org_id
    # from the auto-generated Org CA, the nginx sidecar terminates TLS,
    # and intra-org messaging works zero-config. Federation ("allaccio
    # al Court") is post-setup, opt-in via the dashboard /proxy/federation
    # page — not by flipping this flag.
    #
    # When true (default):
    #   - BrokerBridge and the reverse-proxy httpx client are not initialized.
    #   - /readyz skips the JWKS cache check (there is no broker to fetch from).
    #   - validate_config() does not require BROKER_JWKS_URL in production.
    #   - Dashboard responses carry x-cullis-mode: standalone.
    #
    # Setting false plus broker_url + broker_jwks_url at boot keeps the
    # legacy federated bring-up working — used by tests/e2e and by
    # operators who already have a Court online and want it from the
    # first boot rather than via the dashboard attach flow.
    standalone: bool = True

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

    # Rate limiting (ADR-013 layer 3 — per-agent safety net against a
    # single buggy agent stuck in a retry loop. Not the primary DoS
    # defence: coordinated compromise is addressed by layers 2/4/5/6.
    # Default relaxed from 60/min to 1800/min (≈ 30 req/s sustained) so
    # legitimate fan-out / webhook-burst patterns don't false-positive;
    # the DB pool cap in mcp_proxy.db._engine_kwargs is the real floor
    # that keeps the system responsive.)
    rate_limit_per_minute: int = 1800

    # Phase A.3 — per-principal token budget on /v1/chat/completions.
    # Sliding-window sum of (prompt_tokens + completion_tokens) over the
    # last 60s, keyed on principal_id. Exhausted budget → 429 before the
    # request reaches the upstream provider. Default 100k tok/min is
    # generous for interactive use and modest for batch; tune per
    # deployment via MCP_PROXY_LLM_TOKENS_PER_MINUTE.
    llm_tokens_per_minute: int = 100_000

    # Shared secret the proxy uses to verify the X-ATN-Signature HMAC
    # on inbound /pdp/policy webhook calls (audit 2026-04-30 lane 3 H3).
    # When set, every POST to /pdp/policy must carry a valid
    # HMAC-SHA256 over the raw request body, keyed with this secret.
    # When unset, the endpoint logs a warning at startup but still
    # accepts unsigned calls — eases mid-rollout while operators
    # configure the secret on both sides. Set the matching value on
    # the broker via ``POLICY_WEBHOOK_HMAC_SECRET`` to enable.
    pdp_webhook_hmac_secret: str = ""

    # ADR-029 Phase C, tool-level PDP gate. When true, exposes the
    # POST /v1/policy/tool-call endpoint that the Connector ambassador
    # calls before executing each MCP tool the model emits in a chat
    # completion. Default false so existing deployments keep working
    # untouched until they explicitly enable the gate. Phase D wires
    # the cross-org federation for tool-call decisions.
    tool_pdp_enabled: bool = False

    # ADR-029 Phase D-2, cross-org federation map for tool-call PDP.
    # When the Connector asks /v1/policy/tool-call with a `target.org`
    # different from this Mastio's `org_id`, the local decision is
    # intersected with a federated call to the target org's Mastio.
    # The map keys are remote org_ids; values are the full URL of that
    # org's POST /v1/policy/tool-call endpoint, e.g.
    # ``{"competitor": "https://mastio.competitor.local/v1/policy/tool-call"}``.
    # Default-deny when an entry is missing for the target org (better
    # to refuse a cross-org tool until federation is wired explicitly).
    # The shared HMAC secret (``MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET``) is
    # reused to sign the outbound federation calls when set.
    tool_pdp_federation_urls: dict[str, str] = {}

    # ADR-013 layer 2 — global Mastio rate limit. Token bucket shared
    # across every request (not per-agent), so coordinated compromise
    # across many stolen credentials cannot outrun the aggregate cap.
    # The ``burst`` window swallows legitimate spikes (fan-out, retry
    # storm after a hiccup); the ``rps`` sets the sustained ceiling.
    # Over-limit requests get ``503`` + ``Retry-After: 1``. In-memory
    # only for now — multi-worker deployments effectively get N × the
    # advertised rate, matching the per-agent limiter degradation when
    # Redis is unavailable. A Redis-backed backend is phase 2.1.
    global_rate_limit_rps: float = 500.0
    global_rate_limit_burst: int = 1000

    # ADR-013 layer 6 — DB latency circuit breaker. Sheds a fraction
    # of requests while DB p99 sits above the activation threshold,
    # so the Mastio stays responsive as the pool recovers rather
    # than piling new work onto connections that never free up.
    # Hysteresis between activation and deactivation prevents
    # flapping at the boundary. Lerp from 10 % at activation up to
    # max_shed_fraction at 3× activation. See ADR-013 §Phase 3.
    cb_db_latency_activation_ms: float = 500.0
    cb_db_latency_deactivation_ms: float = 350.0
    cb_db_latency_max_shed_fraction: float = 0.95
    cb_db_latency_probe_interval_s: float = 1.0
    cb_db_latency_probe_timeout_s: float = 2.0
    cb_db_latency_window_s: float = 5.0

    # ADR-013 Phase 4 — single-agent anomaly detection. Detects
    # credential-compromise-shaped traffic anomalies that stay under
    # the aggregate volume defences (Phases 1-6). See
    # imp/adr_013_phase4_design.md.
    #
    # ``anomaly_quarantine_mode`` is the master switch. Values:
    #   shadow  — detector runs, emits structured logs + DB audit
    #             rows for would-be quarantines, does NOT flip
    #             is_active=0. **Default on every deployment.** The
    #             ADR safeguard §3.1 mandates shadow as the arrival
    #             state for any new deployment, never auto-flipping.
    #   enforce — detector acts on decisions: is_active=0 + hard-
    #             delete after ``quarantine_ttl_hours``.
    #   off     — evaluator task is not started.
    #
    # The ADR's 4-week-shadow invariant is advisory in code (an env-
    # gated override exists for verified-safe deployments). Operators
    # are expected to honour it; future work wires a runtime check.
    anomaly_quarantine_mode: str = "shadow"

    anomaly_ratio_threshold: float = 10.0
    anomaly_absolute_threshold_rps: float = 100.0
    # Soft absolute threshold — the minimum absolute rate a mature
    # agent must exceed for the ratio path to trigger. Keeps low-
    # volume bursts (fan-out, retry storms) from false-positiving
    # while baseline-vs-current ratio is dramatic.
    anomaly_absolute_threshold_rps_soft: float = 5.0
    # 30 s tick. Lower makes detection latency better but increases
    # DB read load; higher smooths across bursts that should fire.
    anomaly_evaluation_interval_s: float = 30.0
    # 3 ticks × 30 s = 90 s sustained — single transient spikes never
    # quarantine. Design doc §2.2.
    anomaly_sustained_ticks_required: int = 3
    anomaly_quarantine_ttl_hours: int = 24
    # Cycle-level fail-closed ceiling. ``3/min`` means detector does
    # zero harm on any infra event that trips > 3 agents in a minute,
    # only reports via aggregate alert. Tuning up requires redeploy
    # (not runtime-settable) so a compromised admin API cannot raise
    # the ceiling. Design doc §3.4.
    anomaly_ceiling_per_min: int = 3
    anomaly_baseline_min_days: int = 7
    # Minimum shadow period before operator flip to enforce is
    # allowed. Honour in operator runbook; runtime check is advisory
    # follow-up.
    anomaly_enforce_min_shadow_days: int = 28

    # Redis — optional. Empty = in-memory JTI store + rate limiter (single-
    # instance Mastio is fine without Redis). Multi-worker / HA deploys MUST
    # set this so the DPoP JTI store is shared across workers (audit F-B-12).
    # Accepts redis:// or rediss:// URLs.
    redis_url: str = ""

    # H3 P0.3 — audit-fail-deny mode (CISO due-diligence claim).
    # Controls what happens when ``log_audit`` cannot persist a row
    # (DB down, disk full, integrity-error retry budget exhausted):
    #   true  → log critical + re-raise; the caller surfaces 500 to
    #           the client. No untraceable side effects ever land.
    #   false → log critical + swallow; the request returns normally
    #           with a warning in the proxy log. Useful only when an
    #           operator explicitly wants availability over forensic
    #           completeness (audit log re-buildable from upstream
    #           sinks such as S3 / Datadog plugins). Default-true is
    #           the production-correct stance and matches the threat-
    #           model claim ``operate/security/threat-model.md`` MCP
    #           proxy section, Repudiation row.
    audit_fail_deny: bool = True

    # F0.4 / ADR-033 batched audit chain — Tier 2 throughput unlock.
    # The legacy per-row chain (log_audit acquires an asyncio.Lock,
    # SELECT MAX, INSERT, fsync inside the lock) is the dominant
    # bottleneck above ~200 RPS sustained. The batched chain coalesces
    # N rows under a single head fetch + INSERT, trading per-row
    # immutability proof for per-batch (~1s at sustained Tier 2).
    #
    #   audit_chain_batch_size       — rows per flush burst (size trigger)
    #   audit_chain_flush_interval_s — wall-clock cap between flushes
    #                                  (time trigger, drains low-RPS queues)
    #   audit_chain_disabled         — emergency opt-out; routes log_audit
    #                                  via the legacy per-row path (same
    #                                  semantics as batch_size=1 but skips
    #                                  the queue + background task spawn
    #                                  entirely). Compliance customers that
    #                                  insist on per-row durability under
    #                                  fail-deny=True must keep this true.
    #
    # See enterprise-kit/compliance-posture.md for the trade-off matrix.
    audit_chain_batch_size: int = 100
    audit_chain_flush_interval_s: float = 1.0
    audit_chain_disabled: bool = False

    # Audit L1-H1 / Ultra U-DD-1: in production the DPoP JTI store and the
    # login-challenge nonce store both refuse to fall back to in-memory
    # when Redis is unavailable, because a multi-worker deploy without a
    # shared store silently allows replay across workers (RFC 9449
    # violation). Single-instance / single-worker production deployments
    # that genuinely don't need Redis can opt out by setting this flag to
    # true; the existing warning is then preserved. Default: secure
    # (refuse). Mirrors the Court's hard-raise but keeps the legitimate
    # single-instance Mastio path explicit rather than implicit.
    allow_inmemory_security_stores: bool = False

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

    # ADR-012 Phase 2 — local /v1/auth/token issuance. When true the
    # Mastio's LocalIssuer signs session tokens in-process for intra-org
    # operations and the Court is never contacted for login traffic.
    # Default off so the existing reverse-proxy behavior is preserved —
    # operators opt in after migrating clients to accept Bearer tokens
    # scoped to ``local``. Flip via MCP_PROXY_LOCAL_AUTH_ENABLED /
    # PROXY_LOCAL_AUTH.
    local_auth_enabled: bool = False

    # Wave B C1 (audit 2026-05-11) — bind LOCAL_TOKEN to a DPoP key.
    # When the SDK calls ``POST /v1/auth/token`` with a ``DPoP`` proof
    # header the Mastio extracts the proof's jkt and stamps it into the
    # token's ``cnf.jkt`` claim. Subsequent requests carrying the
    # LOCAL_TOKEN must present a fresh DPoP proof signed by the same
    # key — replay of an exfiltrated token alone is rejected.
    #
    # ``local_token_require_dpop`` controls strict mode:
    #   * False (default): tokens minted without ``cnf.jkt`` (legacy)
    #     still validate as plain Bearer with a WARN log. New tokens
    #     get the binding; old ones expire within ``local_auth_token_
    #     ttl_seconds`` (15 min default) and fall out naturally.
    #   * True: any LOCAL_TOKEN without ``cnf.jkt`` is rejected at
    #     mint AND at validation. Use after the SDK has rolled out and
    #     the existing token TTL has fully expired.
    local_token_require_dpop: bool = False

    # ADR-032 Layer 2 — Connector OIDC login session TTL in seconds.
    # Default 1h aligns with ADR-032 decision D (banking-grade idle).
    # Operators tune via ``MCP_PROXY_USER_SESSION_TTL_SECONDS``.
    user_session_ttl_seconds: int = 3600

    # ADR-033 Phase 1 — Frontdesk shared-mode audit warning.
    # When true (default), ``maybe_stamp_user_session`` emits a
    # WARNING log entry and an audit chain row of type
    # ``frontdesk_shared_unauthenticated_user_session_warning``
    # whenever a Connector presents a session token that lacks a
    # ``user_signed_assertion`` field (i.e. no cryptographic proof
    # that the user authorised this specific session). This is every
    # session today because Phase 2 (WebAuthn-bound session tokens)
    # is not yet implemented.
    # Set to false only in dev/test environments where the warning
    # volume would obscure other signal. Never disable in production.
    frontdesk_audit_warning_enabled: bool = True

    # ADR-033 Phase 2 — WebAuthn-bound user session tokens.
    # The Connector posts a WebAuthn assertion alongside the session
    # request; the Mastio verifies the assertion against a credential
    # registered earlier by the user (Touch ID, YubiKey, Windows Hello,
    # passkey). Without a valid assertion the path either warns (Phase 1
    # carry-over) or hard-fails (target steady state), gated by
    # ``webauthn_enforcement``.
    #
    # Relying Party identifiers (rp.id, rp.name) are baked into every
    # registration / authentication option blob. rp.id must match the
    # DNS suffix the browser sees when invoking ``navigator.credentials``.
    # For a Connector dashboard reaching the Mastio via the local TLS
    # sidecar the rp.id is the Mastio host (default ``mastio.local`` for
    # the Frontdesk bundle); customers running a custom DNS name override
    # via ``MCP_PROXY_WEBAUTHN_RP_ID``.
    webauthn_rp_id: str = "mastio.local"
    webauthn_rp_name: str = "Cullis Mastio"

    # Enforcement gate. Three modes:
    #   * "off"      — accept session emissions without an assertion,
    #                  no warning. Use only during a developer setup
    #                  where the operator already accepts the Phase 1
    #                  threat model (Connector signs for the user).
    #   * "warn"     — default. The legacy Phase 1 warning path keeps
    #                  firing when the assertion is missing; when an
    #                  assertion is present it is verified and stored,
    #                  but a verification failure is logged not raised.
    #                  Used during migration from Phase 1.
    #   * "required" — production target. Missing or invalid assertion
    #                  raises HTTP 401 at session emission and at every
    #                  session-stamped request. Mastio refuses to start
    #                  if the ``webauthn`` Python package is not
    #                  importable.
    webauthn_enforcement: str = "warn"

    # TTL of the registration / authentication challenge nonce. py_webauthn
    # ships its own time-skew tolerance on the assertion side, this value
    # bounds how long a generated options blob remains spendable.
    webauthn_challenge_ttl_seconds: int = 300

    # Expected ``Origin`` header the browser will set on the WebAuthn
    # ceremony. Empty defaults to ``https://<rp_id>``; multiple origins
    # can be supplied comma-separated (e.g. dashboard URL + Frontdesk
    # TLS sidecar URL) when the same RP id is reachable through more
    # than one entry point. Verification rejects any origin not in this
    # allow-list — narrow this in production.
    webauthn_expected_origin: str = ""

    # ADR-017 native AI gateway on Mastio. When the Mastio runs litellm
    # in-process (default: ``litellm_embedded``), every chat completion
    # is dispatched without a Court round trip. Set ``backend=portkey``
    # to delegate to a Portkey gateway sidecar instead.
    anthropic_api_key: str = ""
    ai_gateway_backend: str = "litellm_embedded"  # litellm_embedded | portkey
    ai_gateway_provider: str = "anthropic"
    ai_gateway_url: str = "http://localhost:8787"  # Portkey sidecar URL
    ai_gateway_request_timeout_s: float = 30.0

    # ADR-021 PR4d — auto-create + auto-approve a baseline binding on
    # the Court for ``connector``-method enrollments so the agent can
    # pass ``login_via_proxy_with_local_key`` without a manual
    # ``POST /v1/registry/bindings`` step. Default on; flip off when
    # the org wants explicit per-agent binding decisions.
    auto_baseline_binding: bool = True

    # ADR-016 Guardian (Phase 1 foundation). The ticket key is the
    # HMAC secret Mastio uses to sign every guardian decision; agent
    # runtimes verify the signature before delivering a message.
    # Empty key disables the endpoint (returns 503) — Phase 1 plugin
    # authors can still develop against the contract by setting any
    # 32-byte hex value here. Distribution to agent runtimes piggybacks
    # on the org CA bundle refresh (rollout plan Q2).
    guardian_ticket_key: str = ""
    guardian_ticket_ttl_s: int = 30

    # Frontdesk Ambassador admin API target. The Mastio dashboard is
    # the control plane: when an admin creates/resets/deletes a user
    # principal from /proxy/users, the Mastio forwards the lifecycle
    # call to the Frontdesk Ambassador running on this URL, which is
    # the data plane for password storage (users.db, bcrypt). The
    # secret is the same value the Frontdesk has under
    # CULLIS_CONNECTOR_ADMIN_SECRET. Empty defaults keep the dashboard
    # page read-only (legacy behaviour).
    frontdesk_ambassador_url: str = ""
    frontdesk_admin_secret: str = ""
    # When the Frontdesk Ambassador is reached over HTTPS with a
    # self-signed TLS cert (the bundle's built-in sidecar, default),
    # the Mastio cannot validate the leaf against any CA it knows.
    # Two ways to bridge:
    #   * ``frontdesk_verify_tls=false`` — skip verification entirely.
    #     Cheap dogfood / dev path; fine inside a private libvirt
    #     network where the only reason the leaf is unverifiable is
    #     that the sidecar minted it locally.
    #   * ``frontdesk_ca_bundle`` — path to the Frontdesk CA chain
    #     (e.g. ``./frontdesk-ca.crt`` copied from the bundle's
    #     ``tls/`` dir at deploy time). Use in production so the
    #     Mastio still validates the leaf.
    # If both are set the explicit CA bundle wins. Empty + verify=true
    # (the default) means: standard system trust store, which is the
    # right shape when the Frontdesk is terminated by a corporate
    # ingress / oauth2-proxy fronting a real CA cert.
    frontdesk_verify_tls: bool = True
    frontdesk_ca_bundle: str = ""

    # ADR-032 Layer 1 (F2 spike) — Intune device attestation polling.
    # ``mdm_intune_enabled=false`` keeps the polling task off so
    # customers who haven't completed the Entra app registration
    # don't see lifespan warnings on every start. The tenant /
    # client / secret triple is the customer's app registration
    # (see ``enterprise-kit/intune-setup.md``). Empty values are
    # tolerated so the field can be wired through the bundle's
    # compose ``environment:`` block without crashing when the
    # operator hasn't filled them in yet.
    mdm_intune_enabled: bool = False
    mdm_intune_tenant_id: str = ""
    mdm_intune_client_id: str = ""
    mdm_intune_client_secret: str = ""
    # Microsoft documents Intune compliance state freshness on the
    # order of 5-15 minutes; polling faster does not produce fresher
    # data and only increases throttling risk. The bound of 60s is
    # defensive for tests that want a tight loop.
    mdm_intune_poll_interval_seconds: int = 600

    # Stale window after which a cached device's compliance is
    # downgraded to ``unknown`` (schema sez. 5). Default 900s = 15
    # minutes, matching the upper bound of Intune's freshness window
    # so we don't keep treating a device as compliant while it has
    # actually drifted in the upstream.
    attestation_stale_threshold_seconds: int = 900

    # ADR-032 F6 — stale-watcher daemon. When enabled, a background
    # task scans ``internal_agents.last_attestation`` once per minute
    # and emits a ``device_attestation`` audit row of subtype
    # ``stale`` the first time an agent crosses the staleness
    # threshold. Dedupe uses ``internal_agents.last_stale_event_at``
    # so the same agent does not flood the chain on every tick.
    # Default on; turn off in tests / single-shot scripts.
    attestation_stale_watcher_enabled: bool = True
    attestation_stale_watcher_interval_seconds: int = 60

    # Wave 2 fix 5 — cert expiry watcher daemon. Background tick that
    # iterates the PKI fleet (Org Root, Intermediate, Mastio leaf,
    # agent leaves, nginx server) and emits warning logs + audit rows
    # when a cert enters its per-tier threshold. Visibility only, no
    # auto-rotation (the primary Intermediate watcher handles that for
    # its tier; the other tiers need a human in the loop or sit behind
    # a different rotation path, e.g. Wave 2 fix 6 for nginx).
    #
    # Defaults:
    #   - interval: 24h (the warning is informational, no need to
    #     poll faster than once per day)
    #   - Org Root threshold: 5y (cert is 15y, so >10y silent)
    #   - Intermediate threshold: 2y (fallback only, primary watcher
    #     handles 180d/60d/30d)
    #   - Mastio leaf threshold: 90d (Court ACK round-trip = lead time)
    #   - Agent cert threshold: 90d (Connector re-enrollment lead time)
    #   - nginx server cert threshold: 30d (matches
    #     ``ensure_nginx_server_cert`` renew_within_days)
    cert_expiry_watcher_enabled: bool = True
    cert_expiry_watcher_interval_seconds: int = 86400
    cert_expiry_warn_days_org_root: int = 1825
    cert_expiry_warn_days_intermediate: int = 730
    cert_expiry_warn_days_mastio_leaf: int = 90
    cert_expiry_warn_days_agent: int = 90
    cert_expiry_warn_days_nginx: int = 30

    # Wave 2 fix 7+8. Agent leaf cert rotation grace period. When the
    # re-enrollment flow or the admin DPoP endpoint rotates
    # ``internal_agents.cert_pem`` / ``dpop_jkt``, the previous values
    # stay valid for ``agent_cert_grace_period_hours`` hours so
    # mid-flight requests signed with the OLD keypair don't 401 at the
    # instant the row flips. After expiry the cleanup task sweeps the
    # row back to a single-pin state. 48h matches the typical SDK retry
    # / Connector re-enroll-on-401 budget; tighten to 1h+ for
    # short-window operators, widen for batch workloads with multi-day
    # checkpoints.
    agent_cert_grace_period_hours: int = 48
    # Tick cadence for the grace-period cleanup loop. Default 1h gives
    # the operator a worst-case "old pin valid up to grace + 1h"
    # surface, which keeps the bounded window predictable without
    # burning sleeping wakeups on a typical fleet.
    agent_cert_grace_cleanup_interval_seconds: int = 3600
    agent_cert_grace_cleanup_enabled: bool = True

    # Docker compose ``${VAR:-}`` substitutes to the empty string when
    # the operator has not set the var in proxy.env. Pydantic v2's bool
    # parser rejects "" with ``bool_parsing`` ValidationError, which
    # crashes the container at startup and surfaces in CI as
    # "mcp-proxy is unhealthy". For the bool flags that are wired into
    # the bundle compose's ``environment:`` block, treat "" as
    # "operator didn't set" → fall back to the field default. The
    # subsequent ``_apply_routing_overrides`` model-validator re-reads
    # via ``_env()`` (which also maps "" → None) so the standalone
    # auto-flip for ``local_auth_enabled`` keeps working unchanged.
    @field_validator(
        "tool_pdp_enabled",
        "force_local_password",
        "local_auth_enabled",
        "mdm_intune_enabled",
        mode="before",
    )
    @classmethod
    def _empty_bool_str_to_false(cls, v):
        # Targeted to the three bool flags the customer bundle compose
        # exposes via ``${VAR:-}``. Each has ``default=False`` on the
        # model, so returning False for the empty string preserves the
        # "operator hasn't set this" intent. The
        # ``_apply_routing_overrides`` model-validator re-reads
        # ``MCP_PROXY_LOCAL_AUTH_ENABLED`` via ``_env()`` (which also
        # maps "" → None) so the standalone auto-flip keeps firing.
        if isinstance(v, str) and v.strip() == "":
            return False
        return v

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

        local_auth_flag = _env("MCP_PROXY_LOCAL_AUTH_ENABLED") or _env("PROXY_LOCAL_AUTH")
        if local_auth_flag is not None:
            self.local_auth_enabled = local_auth_flag.lower() in (
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
        # ADR-012 — local-first auth: in standalone mode the Mastio is the
        # only token issuer (there's no Court to forward ``/v1/auth/token``
        # to). Without ``local_auth_enabled`` the agent-side
        # ``login_via_proxy_with_local_key`` flow 503s on ``broker_url
        # missing``. Flip the default on whenever standalone is set and
        # the operator hasn't explicitly overridden ``MCP_PROXY_LOCAL_AUTH_ENABLED``.
        if (
            self.standalone
            and _env("MCP_PROXY_LOCAL_AUTH_ENABLED") is None
            and _env("PROXY_LOCAL_AUTH") is None
        ):
            self.local_auth_enabled = True
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

        # Audit F-B-10 — dashboard signing key must be explicitly set in
        # production. The dev fallback is file-backed, which is fine for
        # single-host docker-compose but brittle in Helm / multi-replica
        # (each replica writes its own file, sessions break on worker
        # hop). Mirrors the broker-side refusal in app.config.
        if not settings.dashboard_signing_key:
            _log.critical(
                "MCP_PROXY_DASHBOARD_SIGNING_KEY is not set in production. "
                "Sessions will not survive restarts or work across workers "
                "(audit F-B-10). Set it to a strong random value (e.g. "
                "openssl rand -hex 32).",
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
                "agent private keys at rest in the process environment, "
                "dev/test only.",
                settings.secret_backend,
            )
            raise SystemExit(1)

        # H3 P0.1 — kms_backend=local stores the Org CA private key in the
        # Mastio's own database (proxy_config table). A host compromise
        # that reaches the DB file recovers the key material directly. In
        # production we require a vault-backed or HSM-backed KMS so the
        # key never lives on disk in cleartext. Closes the gap surfaced by
        # the 2026-05-15 threat-model verification pass: the old code
        # refused secret_backend=env but silently accepted kms_backend=
        # local, contradicting the threat-model claim of "production
        # refuses local KMS backend".
        if settings.kms_backend.lower() == "local":
            _log.critical(
                "MCP_PROXY_KMS_BACKEND=%r is not supported in production. "
                "Set MCP_PROXY_KMS_BACKEND=vault (open-core, see "
                "operate/vault-org-ca.md) or one of the enterprise cloud "
                "KMS plugins (aws/azure/gcp). 'local' keeps the Org CA "
                "private key in the Mastio database, with no HSM-grade "
                "protection (dev/test only).",
                settings.kms_backend,
            )
            raise SystemExit(1)

        # Three-tier PKI hardening (audit 2026-05-18). The
        # ``pki_key_store`` table wraps Org Root + Mastio Intermediate
        # private keys in a Fernet envelope. The master passphrase
        # ``MCP_PROXY_DB_ENCRYPTION_KEY`` is operator-supplied and must
        # be set in production. Length floor 32 chars matches the
        # ``openssl rand -hex 48`` operator runbook recommendation.
        # Without it, a DB-only leak surrenders the root-of-trust.
        db_enc_key = (settings.db_encryption_key or "").strip()
        if not db_enc_key:
            _log.critical(
                "MCP_PROXY_DB_ENCRYPTION_KEY is not set in production. "
                "The pki_key_store at-rest envelope cannot operate "
                "without it: a DB leak would surrender the Org Root + "
                "Mastio Intermediate private keys. Set it to a strong "
                "random value (e.g. ``openssl rand -hex 48``).",
            )
            raise SystemExit(1)
        if len(db_enc_key) < 32:
            _log.critical(
                "MCP_PROXY_DB_ENCRYPTION_KEY is too short (got %d chars, "
                "need >= 32) in production. Generate one with "
                "``openssl rand -hex 48`` (96 hex chars = 48 bytes of "
                "entropy after PBKDF2). Refusing to start.",
                len(db_enc_key),
            )
            raise SystemExit(1)

        # ADR-033 Phase 2. When enforcement is "required" the WebAuthn
        # verification path is on the critical path of every session
        # emission. Failing to import the ``webauthn`` library here means
        # the Mastio would 500 every login the moment a user tries it.
        # Refuse to start instead, so the deploy script can catch the
        # misconfigured bundle (missing ``[webauthn]`` extra) before
        # users see it.
        enforcement = (settings.webauthn_enforcement or "").lower()
        if enforcement not in {"off", "warn", "required"}:
            _log.critical(
                "MCP_PROXY_WEBAUTHN_ENFORCEMENT=%r is not a recognised "
                "value. Use one of: off, warn, required.",
                settings.webauthn_enforcement,
            )
            raise SystemExit(1)
        if enforcement == "required":
            try:
                import webauthn  # noqa: F401
            except ImportError:
                _log.critical(
                    "MCP_PROXY_WEBAUTHN_ENFORCEMENT=required but the "
                    "``webauthn`` Python package is not importable. "
                    "Install with the `[webauthn]` extra "
                    "(pip install 'cullis-agent-sdk[webauthn]') or "
                    "lower enforcement to 'warn' during the Phase 1 "
                    "to Phase 2 migration window."
                )
                raise SystemExit(1)
            if not settings.webauthn_rp_id:
                _log.critical(
                    "MCP_PROXY_WEBAUTHN_RP_ID is empty but enforcement is "
                    "'required'. Set it to the DNS suffix the browser sees "
                    "when invoking navigator.credentials (typically the "
                    "Mastio host name)."
                )
                raise SystemExit(1)

        # F-A-205 (audit 2026-05-20). ADR-033 Phase 1 shipped webauthn
        # enforcement="warn" as the default for migration grace. In that
        # mode the X-Cullis-On-Behalf-Of-User header attribution rests
        # only on the bearer session_token (no user cryptographic
        # assertion required), so any session-token theft (XSS, log
        # scrape, container fs read) lets the attacker emit egress
        # calls attributed to the victim user. Production must enforce
        # WebAuthn or explicitly accept the risk via opt-in flag.
        if enforcement in {"warn", "off"}:
            insecure_ok = (
                os.environ.get("MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK", "")
                .strip()
                .lower()
            ) in {"1", "true", "yes"}
            if not insecure_ok:
                _log.critical(
                    "MCP_PROXY_WEBAUTHN_ENFORCEMENT=%r is not permitted "
                    "in production: on-behalf-of attribution is "
                    "forgeable on bearer session_token theft alone. "
                    "Set MCP_PROXY_WEBAUTHN_ENFORCEMENT=required (ADR-033 "
                    "Phase 2) or, for the legacy migration window, "
                    "explicitly opt in via "
                    "MCP_PROXY_WEBAUTHN_WARN_INSECURE_OK=true and track "
                    "a sunset date (F-A-205).",
                    enforcement,
                )
                raise SystemExit(1)

        # F-A-202 (audit 2026-05-20). PDP webhook HMAC secret protects
        # /pdp/policy + /v1/policy/tool-call inbound calls with
        # X-ATN-Signature (audit 2026-04-30 lane 3 H3). Empty secret
        # in production skips the HMAC check entirely and accepts
        # any POST body from any caller that can reach the endpoint.
        if not (settings.pdp_webhook_hmac_secret or "").strip():
            _log.critical(
                "MCP_PROXY_PDP_WEBHOOK_HMAC_SECRET is empty in "
                "production. Inbound PDP webhook calls are accepted "
                "without X-ATN-Signature verification (audit "
                "2026-04-30 lane 3 H3). Set the shared secret matching "
                "the broker POLICY_WEBHOOK_HMAC_SECRET (F-A-202)."
            )
            raise SystemExit(1)

        # F-A-501 (audit 2026-05-20). MCP_PROXY_AUDIT_FAIL_DENY=false
        # silently swallows audit-log persistence failures while
        # verify_audit_chain still passes on the surviving rows.
        # Threat-model claim in enterprise-kit/compliance-posture.md
        # advertises tamper-evident append-only audit; allowing the
        # operator-side flip to false in production turns that claim
        # silently false without any startup signal.
        if not settings.audit_fail_deny:
            _log.critical(
                "MCP_PROXY_AUDIT_FAIL_DENY=false is not permitted in "
                "production. Threat-model claim (compliance-posture.md) "
                "requires audit-log fail-deny semantics: silent row "
                "drops contradict the CISO-facing 'tamper-evident' "
                "posture. Set MCP_PROXY_AUDIT_FAIL_DENY=true (the "
                "default) or refuse to deploy (F-A-501)."
            )
            raise SystemExit(1)

        # F-A-502 (audit 2026-05-20). allow_inmemory_security_stores=true
        # in production allows per-process DPoP JTI + login challenge
        # nonce stores. Single-worker deploys can opt in safely, but
        # the multi-worker default (4 workers in the Mastio bundle
        # compose) gives RFC 9449 replay up to N times silently.
        # Refuse outright in production; single-worker deploys declare
        # intent via MCP_PROXY_DEPLOYMENT_TOPOLOGY=single-worker-vertical
        # (mirrors the explicit POLICY_DEFAULT_DECISION pattern in
        # app/config.py).
        if settings.allow_inmemory_security_stores:
            topology = (
                os.environ.get("MCP_PROXY_DEPLOYMENT_TOPOLOGY", "")
                .strip()
                .lower()
            )
            if topology != "single-worker-vertical":
                _log.critical(
                    "MCP_PROXY_ALLOW_INMEMORY_SECURITY_STORES=true is "
                    "not permitted in production unless "
                    "MCP_PROXY_DEPLOYMENT_TOPOLOGY=single-worker-vertical "
                    "is also declared. Multi-worker deploys without a "
                    "shared Redis allow DPoP replay up to N times per "
                    "worker (RFC 9449 violation) and silently multiply "
                    "the advertised per-agent rate budget. Set "
                    "MCP_PROXY_REDIS_URL or declare single-worker "
                    "topology explicitly (F-A-502)."
                )
                raise SystemExit(1)

    # Warnings for any environment
    if settings.admin_secret == _INSECURE_DEFAULT_SECRET:
        _log.warning(
            "ADMIN_SECRET is the insecure default '%s'. "
            "Set MCP_PROXY_ADMIN_SECRET before deploying.",
            _INSECURE_DEFAULT_SECRET,
        )

    # Audit F-B-13 — wildcard origin is never safe in production and is
    # always rejected on the WebSocket upgrade path. The dashboard and
    # reverse-proxy WS endpoints are gated the same way as the broker.
    _origins_list = [
        o.strip() for o in settings.allowed_origins.split(",") if o.strip()
    ]
    if "*" in _origins_list:
        if is_production:
            _log.critical(
                "MCP_PROXY_ALLOWED_ORIGINS contains '*' in production. "
                "Wildcard disables CORS credentials and is rejected on "
                "the WebSocket upgrade (audit F-B-13). Enumerate origins "
                "explicitly.",
            )
            raise SystemExit(1)
        _log.warning(
            "MCP_PROXY_ALLOWED_ORIGINS is '*' — CORS fully open (dev only).",
        )

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

    # Audit F-B-10 — surface which signing key source is in use so operators
    # can tell env vs persisted file apart from the logs.
    if settings.dashboard_signing_key:
        _log.info("Dashboard signing key loaded from MCP_PROXY_DASHBOARD_SIGNING_KEY env.")
    elif not is_production:
        _log.info(
            "MCP_PROXY_DASHBOARD_SIGNING_KEY not set — persisting auto-generated "
            "key at %s (audit F-B-10). Set the env var to override, or back up "
            "the file to keep sessions across container rebuilds.",
            settings.dashboard_signing_key_path,
        )

    _log.info(
        "Startup validation passed (environment=%s, secret_backend=%s, "
        "kms_backend=%s, standalone=%s).",
        settings.environment,
        settings.secret_backend,
        settings.kms_backend,
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
