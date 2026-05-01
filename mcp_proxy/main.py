"""
MCP Proxy — FastAPI application.

Org-level gateway between internal AI agents and the Cullis trust broker.
Standalone component with ZERO imports from app/.

Lifespan: validate_config -> init_db -> JWKS fetch -> yield -> cleanup
"""
import asyncio
import logging
import os
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

    # 2b. Initialize the shared Redis client (audit F-B-12).
    # Empty REDIS_URL is a supported single-instance configuration —
    # ``init_redis`` is a no-op, and callers (JTI store, rate limiter)
    # fall back to in-memory. Operators running multi-worker/HA MUST
    # configure ``MCP_PROXY_REDIS_URL``; ``validate_config`` warns when
    # that condition is missed in production.
    from mcp_proxy.redis.pool import init_redis
    await init_redis(settings.redis_url)

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

    # 5. Initialize AgentManager + BrokerBridge.
    # AgentManager is always needed (it owns the Org CA used to mint internal
    # agent certs, regardless of whether the proxy federates with a broker).
    # BrokerBridge + reverse-proxy client are only initialized when federating.
    from mcp_proxy.db import get_config
    from mcp_proxy.egress.agent_manager import AgentManager

    if settings.standalone:
        broker_url = ""
        # Same precedence as the federated branch below: the operator's
        # env/config pin wins, then whatever was persisted at first-boot
        # (ADR-006 §2.2 derived id), then the default. Without the DB
        # fall-through every restart in standalone drops org_id back to
        # "" and decide_route mislabels every intra-org send as cross-org.
        org_id = settings.org_id or await get_config("org_id") or ""
        app.state.reverse_proxy_broker_url = None
        app.state.reverse_proxy_client = None
        # Explicit reset: the singleton ``app`` survives across test
        # fixtures and background federation contexts, so standalone
        # startup must actively clear a stale BrokerBridge left over
        # from a previous federated run. Without this, /v1/egress/*
        # routes fall through to a live bridge instead of the standalone
        # 400 path (ADR-006 Fase 1 invariant).
        app.state.broker_bridge = None
        _log.info("Standalone mode — broker uplink skipped.")
    else:
        broker_url = await get_config("broker_url") or settings.broker_url
        org_id = await get_config("org_id") or settings.org_id

        # ADR-004 PR A — reverse-proxy httpx client. One shared AsyncClient
        # so the forwarder re-uses HTTP/2 connections across requests.
        import httpx as _httpx
        app.state.reverse_proxy_broker_url = broker_url
        app.state.reverse_proxy_client = _httpx.AsyncClient(
            timeout=30.0,
            verify=settings.broker_verify_tls,
            follow_redirects=False,
        )

    agent_mgr = AgentManager(org_id=org_id, trust_domain=settings.trust_domain)
    await agent_mgr.load_org_ca_from_config()

    # #115 — standalone first-boot: generate a fresh self-signed Org CA when
    # no CA has been attached (no attach-ca invite ever consumed) and no
    # broker is configured. Gated on standalone=true so federation deploys
    # keep the attach-ca flow unchanged.
    #
    # ADR-006 §2.2 — when the operator hasn't pinned an ``org_id`` via env
    # or config, derive one deterministically from the CA public key. The
    # admin then copies this value into the broker's attach-ca invite so
    # future uplinks pin the same identity across proxy restarts.
    if settings.standalone and not agent_mgr.ca_loaded:
        derive = not org_id  # derive only when the operator didn't pick one
        await agent_mgr.generate_org_ca(derive_org_id=derive)
        if derive:
            org_id = agent_mgr.org_id

    # ``get_settings`` is lru_cached so mutating the shared instance
    # propagates the resolved id to every call-site (decide_route,
    # reach_guard, oneshot router, dashboard fallbacks). Without this,
    # anything that reads ``get_settings().org_id`` keeps seeing the
    # default ``""`` and classifies intra-org traffic as cross-org.
    if settings.standalone and org_id and not settings.org_id:
        settings.org_id = org_id

    # ADR-009 Phase 1 — derive/persist the Mastio CA + leaf so the proxy can
    # counter-sign Court requests. Only possible once the Org CA is loaded;
    # attached-CA deploys that haven't consumed the invite yet will pick this
    # up on the next boot after attach.
    if agent_mgr.ca_loaded:
        try:
            await agent_mgr.ensure_mastio_identity()
        except Exception as exc:  # defensive — never block lifespan on this
            _log.warning("Mastio identity bootstrap failed: %s", exc)

        # ADR-014 — emit the TLS server cert that the nginx sidecar
        # serves on 9443. The CA bundle (public Org CA cert) goes
        # alongside so nginx can verify Connector certs at the TLS
        # handshake. Idempotent across boots; only mints fresh
        # material when the existing pair is missing, expired, or
        # SAN-mismatched against the configured value.
        if settings.nginx_cert_dir:
            try:
                sans = [
                    s.strip()
                    for s in (settings.nginx_san or "mastio.local").split(",")
                    if s.strip()
                ]
                await agent_mgr.ensure_nginx_server_cert(
                    out_dir=settings.nginx_cert_dir,
                    sans=sans,
                )
                _log.info("ADR-014 nginx cert provisioning complete")
            except Exception as exc:  # don't block lifespan on cert write
                _log.warning(
                    "ADR-014 nginx server cert provisioning failed: %s — "
                    "the sidecar will fail readiness until this is resolved",
                    exc,
                )

    app.state.agent_manager = agent_mgr
    app.state.org_id = org_id
    _log.info("Lifespan: agent_manager + org_id wired (org_id=%s)", org_id)

    # Federation update framework (imp/federation_hardening_plan.md
    # Parte 1, PR 2). Must run BEFORE ``LocalIssuer`` construction so a
    # critical-pending migration affecting this proxy's enrollments can
    # engage sign-halt and the issuer-skip branch below picks it up.
    # Defensive try/except so a malformed migration never blocks boot.
    try:
        from mcp_proxy.updates.boot import detect_pending_migrations
        await detect_pending_migrations(agent_mgr)
    except Exception as exc:
        _log.warning(
            "updates.boot: detect_pending_migrations raised at startup: %s "
            "— continuing without a fresh scan (dashboard may show stale "
            "state until next restart)", exc,
        )

    # ADR-012 Phase 2.0 — keystore + issuer. The keystore is always
    # available (pure DB read view), the issuer requires that the Mastio
    # identity has loaded a current signer. The validator dependency
    # expects both on ``app.state``, so we publish them together and
    # degrade soft (both None) if identity bootstrap failed above.
    from mcp_proxy.auth.local_keystore import LocalKeyStore
    app.state.local_keystore = LocalKeyStore()
    app.state.local_issuer = None
    if getattr(agent_mgr, "mastio_loaded", False) and org_id:
        if getattr(agent_mgr, "is_sign_halted", False):
            # Sign-halt engaged — either #281 staged rotation row or a
            # PR 2 federation-update critical migration. Leaving
            # ``local_issuer`` as None causes the ``_maybe_local_token``
            # dep to short-circuit with ``return None`` and fall through
            # to DPoP, keeping the failure surface consistent with the
            # counter-sign halt that ``AgentManager.countersign`` emits.
            _log.error(
                "LocalIssuer NOT initialized — sign-halted. staged_kid=%s, "
                "reason=%s",
                getattr(agent_mgr, "staged_kid", None),
                getattr(agent_mgr, "sign_halt_reason", None),
            )
        else:
            try:
                from mcp_proxy.auth.local_issuer import build_from_keystore
                app.state.local_issuer = await build_from_keystore(
                    org_id, app.state.local_keystore,
                )
                _log.info(
                    "LocalIssuer initialized (kid=%s, iss=%s)",
                    app.state.local_issuer.kid, app.state.local_issuer.issuer,
                )
            except Exception as exc:
                _log.warning("LocalIssuer init failed: %s", exc)

    # ADR-007 Phase 1 PR #3 — SecretProvider is consumed by the MCP
    # resource forwarder (env:// / vault:// refs). Same instance used by
    # /v1/ingress/execute via the executor, now also exposed on state so
    # the aggregator can pass it down to ToolContext.
    from mcp_proxy.tools.secrets import get_secret_provider
    app.state.secret_provider = get_secret_provider(settings)

    if broker_url:
        from mcp_proxy.egress.broker_bridge import BrokerBridge
        bridge = BrokerBridge(
            broker_url=broker_url,
            org_id=org_id,
            agent_manager=agent_mgr,
            verify_tls=settings.broker_verify_tls,
            trust_domain=settings.trust_domain,
            intra_org_routing=settings.intra_org_routing,
        )
        app.state.broker_bridge = bridge
        _log.info(
            "BrokerBridge initialized (broker=%s, org=%s, trust_domain=%s, intra_org=%s)",
            broker_url, org_id, settings.trust_domain, settings.intra_org_routing,
        )
    else:
        app.state.broker_bridge = None
        _log.warning("No broker_url configured — egress endpoints will return 503")

    # ADR-001 Phase 3a — local session store (intra-org mini-broker).
    # Instantiated regardless of the feature flag so the DB schema is always
    # readable; the egress router only dispatches into it when the flag is on
    # and the routing decision returns "intra".
    from mcp_proxy.local.persistence import restore_sessions
    from mcp_proxy.local.session import LocalSessionStore
    from mcp_proxy.local.ws_manager import LocalConnectionManager
    local_store = LocalSessionStore()
    try:
        await restore_sessions(local_store)
    except Exception as exc:
        _log.warning("Failed to restore local sessions from DB: %s", exc)
    app.state.local_session_store = local_store

    # ADR-007 Phase 1 PR #2 — load MCP resources from local_mcp_resources
    # into the tool registry. Discovery and forwarding land in PR #3;
    # here we only populate the registry so subsequent PRs can rely on
    # the data being present at startup. Failures degrade soft — the
    # proxy still serves builtin tools if the DB read blows up.
    from mcp_proxy.tools.registry import tool_registry
    from mcp_proxy.tools.resource_loader import load_resources_into_registry
    try:
        loaded = await load_resources_into_registry(tool_registry)
        _log.info("MCP resource registry populated (count=%d)", loaded)
    except Exception as exc:
        _log.warning(
            "Failed to load MCP resources from DB — continuing with "
            "builtin tools only: %s",
            exc,
        )

    # Phase 3b — local WS manager. Phase 3c will plug this into message
    # delivery (push-vs-queue decision). Today the endpoint accepts
    # connections so SDKs can start depending on it behind the same
    # PROXY_INTRA_ORG flag.
    app.state.local_ws_manager = LocalConnectionManager()

    # Phase 3d — sweeper. Closes idle/TTL-expired local sessions and
    # expires pending messages whose TTL lapsed, best-effort notifying
    # peers. Only spawned when PROXY_INTRA_ORG is on (otherwise no
    # intra-org traffic ever lands in local_* tables, so there's
    # nothing to sweep). Also explicitly skippable via
    # PROXY_LOCAL_SWEEPER_DISABLED=1 for deterministic tests.
    if settings.intra_org_routing and os.environ.get("PROXY_LOCAL_SWEEPER_DISABLED") != "1":
        from mcp_proxy.local.sweeper import sweeper_loop as _local_sweeper_loop
        stop_event = asyncio.Event()
        sweeper_task = asyncio.create_task(
            _local_sweeper_loop(
                local_store,
                app.state.local_ws_manager,
                stop_event=stop_event,
            ),
            name="local_sweeper",
        )
        app.state.local_sweeper_stop = stop_event
        app.state.local_sweeper_task = sweeper_task

    # Phase 4c — federation SSE subscriber. Wires the Phase 4b cache
    # to the live broker stream. Off by default; flip via
    # PROXY_FEDERATION_SYNC=true. The auth surface (DPoP / mTLS / SPIFFE)
    # is delegated to an externally-provided client factory set on
    # `app.state.federation_subscriber_factory`. Wiring an actual
    # credential is a follow-up — keeping the factory injectable lets
    # deployments pick the auth flavor without forking this module.
    if settings.federation_sync_enabled and broker_url and org_id:
        factory = getattr(app.state, "federation_subscriber_factory", None)
        if factory is None:
            _log.warning(
                "PROXY_FEDERATION_SYNC=on but no "
                "federation_subscriber_factory registered on app.state "
                "— subscriber not started. Set one before app startup.",
            )
        else:
            from mcp_proxy.sync.subscriber import (
                SubscriberConfig,
                run_subscriber,
            )
            sub_cfg = SubscriberConfig(
                broker_url=broker_url,
                org_id=org_id,
                client_factory=factory,
            )
            sub_stop = asyncio.Event()
            sub_task = asyncio.create_task(
                run_subscriber(sub_cfg, stop_event=sub_stop),
                name="federation_subscriber",
            )
            app.state.federation_subscriber_stop = sub_stop
            app.state.federation_subscriber_task = sub_task
            app.state.federation_subscriber_stats = sub_cfg.stats
            _log.info("federation subscriber started (org=%s)", org_id)

    # ADR-010 Phase 3 — federation publisher loop. Only makes sense when
    # the proxy is federated (broker_url set) and the mastio identity
    # is loaded (pubkey pinned at the Court so counter-sig verification
    # succeeds). Standalone proxies skip entirely.
    if broker_url and getattr(agent_mgr, "mastio_loaded", False):
        from mcp_proxy.federation.publisher import run_publisher, run_stats_publisher
        pub_stop = asyncio.Event()
        pub_task = asyncio.create_task(
            run_publisher(app.state, stop_event=pub_stop),
            name="federation_publisher",
        )
        app.state.federation_publisher_stop = pub_stop
        app.state.federation_publisher_task = pub_task
        _log.info("federation publisher started (org=%s)", org_id)

        # Aggregate-stats publisher — fleet-size counters for the Court
        # dashboard. Separate task so a slow stats push never delays the
        # per-agent revision loop above.
        stats_stop = asyncio.Event()
        stats_task = asyncio.create_task(
            run_stats_publisher(app.state, stop_event=stats_stop),
            name="federation_stats_publisher",
        )
        app.state.federation_stats_stop = stats_stop
        app.state.federation_stats_task = stats_task
        _log.info("federation stats publisher started (org=%s)", org_id)

    # ADR-013 layer 6 — DB latency tracker + circuit breaker state.
    # Started after init_db (need the engine) and after the federation
    # task, so the probe's first ``SELECT 1`` runs against a fully
    # initialized pool. The middleware reads these off app.state at
    # request time; see mcp_proxy.middleware.db_latency_circuit_breaker.
    from mcp_proxy.db import _require_engine
    from mcp_proxy.middleware.db_latency_circuit_breaker import (
        CircuitBreakerState,
    )
    from mcp_proxy.observability.db_latency import DbLatencyTracker

    db_latency_tracker = DbLatencyTracker(
        _require_engine(),
        window_s=settings.cb_db_latency_window_s,
        probe_interval_s=settings.cb_db_latency_probe_interval_s,
        probe_timeout_s=settings.cb_db_latency_probe_timeout_s,
    )
    await db_latency_tracker.start()
    app.state.db_latency_tracker = db_latency_tracker
    app.state.db_latency_cb_state = CircuitBreakerState(
        activation_ms=settings.cb_db_latency_activation_ms,
        deactivation_ms=settings.cb_db_latency_deactivation_ms,
        max_shed_fraction=settings.cb_db_latency_max_shed_fraction,
    )
    _log.info(
        "DB latency circuit breaker: activation=%.0fms deactivation=%.0fms "
        "max_shed=%.2f (ADR-013 layer 6)",
        settings.cb_db_latency_activation_ms,
        settings.cb_db_latency_deactivation_ms,
        settings.cb_db_latency_max_shed_fraction,
    )

    # ADR-013 Phase 4 — single-agent anomaly detector. Four cooperating
    # components share ``_require_engine()``:
    #   * TrafficRecorder       — in-memory counter, 30 s flush.
    #     Auth deps call ``record_agent_request`` post-auth.
    #   * BaselineRollupScheduler — daily 04:00 UTC cron.
    #   * AnomalyEvaluator      — 30 s tick, dual-signal detection +
    #     cycle-level fail-closed meta-circuit-breaker.
    #   * QuarantineExpiryScheduler — hourly hard-delete of expired
    #     enforce-mode rows.
    # All four are gated on the master switch
    # ``settings.anomaly_quarantine_mode``: "off" skips startup
    # entirely; "shadow" (default) and "enforce" bring up the stack.
    from mcp_proxy.observability.anomaly_evaluator import AnomalyEvaluator
    from mcp_proxy.observability.baseline_rollup import BaselineRollupScheduler
    from mcp_proxy.observability.quarantine import (
        QuarantineExpiryScheduler,
        make_quarantine_apply_hook,
    )
    from mcp_proxy.observability.traffic_recorder import TrafficRecorder

    if settings.anomaly_quarantine_mode != "off":
        engine = _require_engine()

        traffic_recorder = TrafficRecorder(engine)
        await traffic_recorder.start()
        app.state.traffic_recorder = traffic_recorder

        baseline_rollup = BaselineRollupScheduler(
            engine,
            min_baseline_days=settings.anomaly_baseline_min_days,
        )
        await baseline_rollup.start()
        app.state.baseline_rollup = baseline_rollup

        anomaly_evaluator = AnomalyEvaluator(
            engine,
            mode=settings.anomaly_quarantine_mode,
            ratio_threshold=settings.anomaly_ratio_threshold,
            abs_threshold_rps=settings.anomaly_absolute_threshold_rps,
            abs_threshold_rps_soft=settings.anomaly_absolute_threshold_rps_soft,
            sustained_ticks_required=settings.anomaly_sustained_ticks_required,
            interval_s=settings.anomaly_evaluation_interval_s,
            ceiling_per_min=settings.anomaly_ceiling_per_min,
            baseline_min_days=settings.anomaly_baseline_min_days,
            apply_hook=make_quarantine_apply_hook(
                engine, ttl_hours=settings.anomaly_quarantine_ttl_hours
            ),
        )
        await anomaly_evaluator.start()
        app.state.anomaly_evaluator = anomaly_evaluator

        quarantine_expiry = QuarantineExpiryScheduler(engine)
        await quarantine_expiry.start()
        app.state.quarantine_expiry = quarantine_expiry

        _log.info(
            "anomaly detector: mode=%s ratio>%.1fx abs>%.0frps "
            "sustained=%ds ceiling=%d/min ttl=%dh (ADR-013 Phase 4)",
            settings.anomaly_quarantine_mode,
            settings.anomaly_ratio_threshold,
            settings.anomaly_absolute_threshold_rps,
            settings.anomaly_sustained_ticks_required * int(
                settings.anomaly_evaluation_interval_s
            ),
            settings.anomaly_ceiling_per_min,
            settings.anomaly_quarantine_ttl_hours,
        )
    else:
        _log.info("anomaly detector disabled (mode=off)")

    # Enterprise plugin startup hooks. Discovered + license-filtered at
    # module import; here we let each plugin allocate its own resources
    # (e.g. SAML SP keypair load, audit-export S3 client). Failures are
    # logged inside the registry and never block core boot.
    from mcp_proxy.plugins import get_registry as _get_plugin_registry
    await _get_plugin_registry().run_startup(app)

    _log.info(
        "MCP Proxy started (host=%s, port=%d, env=%s)",
        settings.host, settings.port, settings.environment,
    )

    yield

    # Stop enterprise plugins before tearing down core services so
    # they can flush state (audit watermarks, SAML sessions) while
    # engine + redis are still up.
    await _get_plugin_registry().run_shutdown(app)

    # Cleanup — stop the latency tracker first so the background probe
    # doesn't race with engine dispose.
    tracker = getattr(app.state, "db_latency_tracker", None)
    if tracker is not None:
        try:
            await tracker.stop()
        except Exception as exc:  # noqa: BLE001
            _log.warning("db_latency_tracker.stop raised: %s", exc)

    # ADR-013 Phase 4 — stop anomaly pipeline before engine dispose.
    # Order matters: evaluator + recorder do DB work on stop (final
    # flush for the recorder), so they must finish before the engine
    # tears down. Expiry scheduler is cancel-safe. We also delattr
    # after stop so a subsequent lifespan (common in tests that reuse
    # the module-level app) doesn't see zombie components.
    for attr_name in (
        "quarantine_expiry",
        "anomaly_evaluator",
        "baseline_rollup",
        "traffic_recorder",
    ):
        component = getattr(app.state, attr_name, None)
        if component is not None:
            try:
                await component.stop()
            except Exception as exc:  # noqa: BLE001
                _log.warning("%s.stop raised: %s", attr_name, exc)
            try:
                delattr(app.state, attr_name)
            except AttributeError:
                pass

    stop_event = getattr(app.state, "local_sweeper_stop", None)
    sweeper_task = getattr(app.state, "local_sweeper_task", None)
    if stop_event is not None:
        stop_event.set()
    if sweeper_task is not None:
        try:
            await asyncio.wait_for(sweeper_task, timeout=5.0)
        except asyncio.TimeoutError:
            sweeper_task.cancel()
            try:
                await sweeper_task
            except (asyncio.CancelledError, Exception):
                pass
        except ValueError as exc:
            # pytest-xdist runs lifespan teardown in a different event
            # loop than startup; ``wait_for`` rejects the cross-loop
            # task with ``ValueError``. Standalone is the default after
            # PR-D, the sweeper auto-starts, and the symptom downstream
            # is fixture corruption + cascading "different loop" errors
            # on every subsequent asyncio test. Tolerate it here — the
            # task will be GC'd at process exit.
            _log.debug("local sweeper teardown loop mismatch (xdist): %s", exc)

    sub_stop = getattr(app.state, "federation_subscriber_stop", None)
    sub_task = getattr(app.state, "federation_subscriber_task", None)
    if sub_stop is not None:
        sub_stop.set()
    if sub_task is not None:
        try:
            await asyncio.wait_for(sub_task, timeout=5.0)
        except asyncio.TimeoutError:
            sub_task.cancel()
            try:
                await sub_task
            except (asyncio.CancelledError, Exception):
                pass
        except ValueError as exc:
            _log.debug("federation subscriber teardown loop mismatch (xdist): %s", exc)

    stats_stop = getattr(app.state, "federation_stats_stop", None)
    stats_task = getattr(app.state, "federation_stats_task", None)
    if stats_stop is not None:
        stats_stop.set()
    if stats_task is not None:
        try:
            await asyncio.wait_for(stats_task, timeout=5.0)
        except asyncio.TimeoutError:
            stats_task.cancel()
            try:
                await stats_task
            except (asyncio.CancelledError, Exception):
                pass
        except ValueError as exc:
            _log.debug("federation stats teardown loop mismatch (xdist): %s", exc)

    pub_stop = getattr(app.state, "federation_publisher_stop", None)
    pub_task = getattr(app.state, "federation_publisher_task", None)
    if pub_stop is not None:
        pub_stop.set()
    if pub_task is not None:
        try:
            await asyncio.wait_for(pub_task, timeout=5.0)
        except asyncio.TimeoutError:
            pub_task.cancel()
            try:
                await pub_task
            except (asyncio.CancelledError, Exception):
                pass
        except ValueError as exc:
            _log.debug("federation publisher teardown loop mismatch (xdist): %s", exc)

    ws_manager = getattr(app.state, "local_ws_manager", None)
    if ws_manager is not None:
        await ws_manager.shutdown()
    bridge = getattr(app.state, "broker_bridge", None)
    if bridge is not None:
        await bridge.shutdown()
    rp_client = getattr(app.state, "reverse_proxy_client", None)
    if rp_client is not None:
        await rp_client.aclose()
    if _jwks_client:
        await _jwks_client.close()
    from mcp_proxy.redis.pool import close_redis
    await close_redis()
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
        allow_headers=["Authorization", "Content-Type", "DPoP"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Security headers middleware
# ─────────────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Let operators tell at a glance whether this proxy is running
    # standalone or fronting a Cullis broker.
    response.headers.setdefault(
        "x-cullis-mode",
        "standalone" if get_settings().standalone else "federation",
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # ``setdefault`` so individual handlers can opt into edge caching
    # (``/.well-known/jwks-local.json`` flips to ``public, max-age=60``
    # — the key list turns over on rotation grace-window scales, days,
    # so 60s staleness is negligible and lets a CDN / reverse-proxy
    # absorb the broadcast load, see #282). Handlers that don't set
    # Cache-Control get the conservative ``no-store`` default.
    response.headers.setdefault("Cache-Control", "no-store")

    # DPoP-Nonce on API responses only (not on dashboard/health routes, and
    # not on ADR-004 reverse-proxied paths — those carry the broker's own
    # DPoP-Nonce header verbatim; overriding it here would break the SDK's
    # use_dpop_nonce retry loop).
    from mcp_proxy.reverse_proxy import FORWARDED_PREFIXES as _RP_PREFIXES
    _no_dpop_nonce = ("/proxy/", "/health", "/healthz", "/readyz") + _RP_PREFIXES
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
# DB latency circuit breaker (ADR-013 layer 6)
#
# Registered *before* the global rate limit in the code, so Starlette's LIFO
# execution order runs the circuit breaker AFTER the global bucket: a burst
# big enough to saturate the DB gets shed by the global bucket first,
# leaving only the residue for the breaker to evaluate. Reads its tracker +
# state off app.state at request time (wired by the lifespan hook above)
# so the middleware can be registered at module-import time before the
# engine exists.
# ─────────────────────────────────────────────────────────────────────────────

from mcp_proxy.middleware.db_latency_circuit_breaker import (
    DbLatencyCircuitBreakerMiddleware,
)

app.add_middleware(DbLatencyCircuitBreakerMiddleware)
_log.info(
    "DB latency circuit breaker middleware registered (ADR-013 layer 6)"
)


# ─────────────────────────────────────────────────────────────────────────────
# Global rate limit (ADR-013 layer 2)
#
# Registered last among the middlewares so Starlette's LIFO execution order
# runs it *first* on every inbound request — before auth deps, before any
# handler that would consume state (DPoP nonce, session row, DB write). A
# shed returns 503 + Retry-After immediately; bypasses /health, /metrics,
# and /.well-known/ so observability never hides under load.
# ─────────────────────────────────────────────────────────────────────────────

# Enterprise plugin middlewares. Registered before the global rate
# limit so Starlette's LIFO order runs the rate limiter FIRST on every
# inbound request — plugin middlewares only see traffic that already
# passed admission control.
from mcp_proxy.plugins import get_registry as _get_plugin_registry_for_middlewares

_plugin_registry = _get_plugin_registry_for_middlewares()
_plugin_registry.add_middlewares(app)
if _plugin_registry.plugins:
    _log.info(
        "enterprise middlewares registered: %s",
        [p.name for p in _plugin_registry.plugins],
    )

from mcp_proxy.middleware.global_rate_limit import (
    GlobalRateLimitMiddleware,
    TokenBucket,
)

_global_rate_bucket = TokenBucket(
    rate_per_sec=settings.global_rate_limit_rps,
    burst=settings.global_rate_limit_burst,
)
# Expose the bucket on app.state so tests + future /metrics handlers can
# read available tokens / shed counts without rebuilding the instance.
app.state.global_rate_bucket = _global_rate_bucket
app.add_middleware(GlobalRateLimitMiddleware, bucket=_global_rate_bucket)
_log.info(
    "Global rate limit: rps=%.1f burst=%d (ADR-013 layer 2)",
    settings.global_rate_limit_rps,
    settings.global_rate_limit_burst,
)


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
    import hashlib
    import hmac
    import json as _json
    from fastapi import HTTPException
    from mcp_proxy.db import get_config

    # Audit 2026-04-30 lane 3 H3 — verify the X-ATN-Signature HMAC over
    # the raw body. Without this, any host that can reach the proxy on
    # the PDP plane could (a) probe ``policy_rules`` via differential
    # responses (which agents are blocked, allowed orgs, allowed caps)
    # and (b) inject log lines via attacker-controlled
    # ``initiator``/``target``/``context`` strings.
    raw_body = await request.body()
    expected_secret = settings.pdp_webhook_hmac_secret
    if expected_secret:
        provided = request.headers.get("x-atn-signature", "")
        expected = hmac.new(
            expected_secret.encode(), raw_body, hashlib.sha256,
        ).hexdigest()
        if not provided or not hmac.compare_digest(provided, expected):
            _log.warning("pdp /policy rejected: bad or missing X-ATN-Signature")
            raise HTTPException(status_code=401, detail="invalid signature")

    body = _json.loads(raw_body)
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


# ADR-004 PR D — proxy-native /v1/auth/sign-assertion. Must precede the
# reverse-proxy catch-all so the sign endpoint wins route matching.
from mcp_proxy.auth.sign_assertion import router as sign_assertion_router
app.include_router(sign_assertion_router)

# Tech-debt #2 — /v1/auth/login-challenge + /v1/auth/sign-challenged-assertion,
# the client-holds-the-key counterpart to sign-assertion. Routed here for
# the same reason: before the reverse-proxy catch-all.
from mcp_proxy.auth.challenge_response import router as challenge_response_router
app.include_router(challenge_response_router)

# ADR-012 Phase 1 — JWKS for the Mastio local issuer. Published at
# /.well-known/jwks-local.json; paths under /.well-known are not
# reverse-proxied so the registration order vs forwarder is moot.
from mcp_proxy.auth.jwks_local import router as jwks_local_router
app.include_router(jwks_local_router)

# Anonymous Org CA download for TOFU pinning during Connector first-contact
# (Finding #3 / dogfood 2026-04-29). Path is /pki/ca.crt — outside any
# reverse-proxied prefix, so registration order vs the forwarder is moot.
from mcp_proxy.pki.public import router as pki_public_router
app.include_router(pki_public_router)

# ADR-012 Phase 2 — proxy-native /v1/auth/token. Gated behind
# ``settings.local_auth_enabled`` so the reverse-proxy path remains the
# default. MUST be registered before ``build_reverse_proxy_router()`` so
# it wins route matching against the ``/v1/auth/*`` catch-all when the
# flag is on.
if get_settings().local_auth_enabled:
    from mcp_proxy.auth.local_token import router as local_token_router
    app.include_router(local_token_router)
    _log.info("ADR-012 local /v1/auth/token handler ENABLED")

# ADR-009 Phase 2 — /v1/admin/mastio-pubkey for bootstrap automation.
from mcp_proxy.admin.info import router as admin_info_router
app.include_router(admin_info_router)

# ADR-013 layer 6 — /v1/admin/observability/circuit-breaker.
from mcp_proxy.admin.observability import router as admin_observability_router
app.include_router(admin_observability_router)

# ADR-009 sandbox — Connector JSON API for MCP resources + bindings.
from mcp_proxy.admin.mcp_resources import router as admin_mcp_resources_router
app.include_router(admin_mcp_resources_router)

# ADR-010 Phase 2 — Mastio-authoritative agent registry admin API.
from mcp_proxy.admin.agents import router as admin_agents_router
app.include_router(admin_agents_router)

# ADR-011 Phase 1b — BYOCA enrollment endpoint. ``/v1/admin/agents/enroll/byoca``
# takes a caller-supplied cert/key pair, verifies the chain to the Mastio's
# Org CA, and emits an API key + optional DPoP binding. Registered here,
# not inside the CRUD router, so the two concerns (admin CRUD vs verified
# enrollment) stay separable as Phase 1c adds the SPIFFE variant.
from mcp_proxy.admin.enroll import router as admin_enroll_router
app.include_router(admin_enroll_router)

# ADR-006 Fase 1 / PR #3 — proxy-native discovery + public-key endpoints.
# Must precede the reverse-proxy catch-all: /v1/federation/agents/{id}/
# public-key would otherwise fall into the `/v1/federation/*` forward
# prefix (when added) and never reach the local handler. /v1/agents/*
# is not forwarded, but we keep the ordering uniform for clarity.
from mcp_proxy.agents.router import router as agents_router
app.include_router(agents_router)
from mcp_proxy.registry.public_key import (
    federation_router as federation_public_key_router,
)
# ADR-010 Phase 6a-2/4 — proxy-native (local-first) public-key lookup
# under /v1/federation/. The former /v1/registry/ mirror was dropped
# alongside the Court's legacy registry endpoints.
app.include_router(federation_public_key_router)

# ADR-004 PR A — reverse-proxy router for /v1/broker/*, /v1/auth/*,
# /v1/registry/*. Registered before local handlers so the proxy owns these
# paths by default; local endpoints live under /v1/egress/* and /v1/ingress/*.
from mcp_proxy.reverse_proxy import build_reverse_proxy_router
app.include_router(build_reverse_proxy_router())

# ADR-006 Fase 2 / PR #8 — WebSocket reverse-proxy for /v1/broker/*. The
# HTTP forwarder above uses httpx.request which rejects the Upgrade
# handshake; SDKs hitting /v1/broker/sessions/{id}/messages/stream need
# this router to survive the upgrade.
from mcp_proxy.reverse_proxy.websocket import build_websocket_reverse_proxy_router
app.include_router(build_websocket_reverse_proxy_router())

from mcp_proxy.ingress.router import router as ingress_router
app.include_router(ingress_router)

# ADR-007 Phase 1 PR #3 — aggregated MCP endpoint (/v1/mcp JSON-RPC 2.0).
from mcp_proxy.ingress.mcp_aggregator import router as mcp_aggregator_router
app.include_router(mcp_aggregator_router)

from mcp_proxy.egress.router import router as egress_router
app.include_router(egress_router)

# ADR-008 Phase 1 PR #1 — sessionless one-shot endpoints.
from mcp_proxy.egress.oneshot import router as oneshot_router
app.include_router(oneshot_router)

# ADR-014 PR-C: the legacy /v1/local/ws endpoint relied on api_key
# query-param auth, which is gone. The local_ws_manager itself stays
# (push fan-out by agent_id) — it's used by the egress router to deliver
# messages to whatever delivery channel ships next. A cert-authenticated
# replacement is deferred.

from mcp_proxy.enrollment.router import router as enrollment_router
app.include_router(enrollment_router)

from mcp_proxy.audit.router import router as audit_router
app.include_router(audit_router)

from mcp_proxy.dashboard.router import router as dashboard_router
app.include_router(dashboard_router)

# ADR-006 Fase 2 / PR #6 — runtime uplink endpoint (`POST /v1/admin/link-broker`)
# + dashboard form (`/proxy/link-broker`). Hot-swaps the BrokerBridge without
# restarting the pod, so flipping an installed standalone proxy into
# federated mode is a 3-click dashboard action instead of a redeploy.
from mcp_proxy.dashboard.link_broker import (
    admin_router as link_broker_admin_router,
    dashboard_router as link_broker_dashboard_router,
)
app.include_router(link_broker_dashboard_router)
app.include_router(link_broker_admin_router)

# ADR-006 PR #2b — dashboard CRUD for intra-org policies. The engine
# landed in #126; this gives operators a UI instead of raw SQL.
from mcp_proxy.dashboard.policies_local import router as local_policies_router
app.include_router(local_policies_router)

# Mounted under /proxy/backends; /proxy/mcp-resources is redirected via a
# small legacy router in the same module (compat for old bookmarks).
from mcp_proxy.dashboard.mcp_resources import (
    router as mcp_resources_dashboard_router,
    _legacy_router as mcp_resources_legacy_router,
)
app.include_router(mcp_resources_dashboard_router)
app.include_router(mcp_resources_legacy_router)

from mcp_proxy.dashboard.downloads import router as downloads_router
app.include_router(downloads_router)

# Federation update framework (PR 4 of imp/federation_hardening_plan.md
# Parte 1) — admin list / apply / rollback under /proxy/updates.
from mcp_proxy.dashboard.updates_router import router as updates_router
app.include_router(updates_router)

# Enterprise plugin routers. Mounted after every core router so a
# plugin can never shadow a core endpoint by registering a conflicting
# path; FastAPI keeps registration order on routing.
_plugin_registry.mount_routers(app)
if _plugin_registry.plugins:
    _log.info(
        "enterprise routers mounted from plugins: %s",
        [p.name for p in _plugin_registry.plugins],
    )

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
async def health(request: Request):
    """Basic health check — always 200 if the process is running.

    Surfaces operator-visible warnings in a ``warnings`` array when
    present (omitted entirely when clean so existing consumers that
    just assert ``status == "ok"`` stay green). Current warnings:

      - ``org_ca_legacy_pathlen_zero`` — #285, the proxy booted with
        an Org CA that has pathLen=0 but mints a Mastio intermediate
        underneath. Stdlib-verifier cross-org federation silently
        401s; remediation is ``POST /pki/rotate-ca``.
    """
    body: dict = {"status": "ok", "version": "0.1.0"}
    warnings: list[str] = []
    agent_mgr = getattr(request.app.state, "agent_manager", None)
    if agent_mgr is not None and getattr(
        agent_mgr, "has_legacy_ca_pathlen_zero", False,
    ):
        warnings.append("org_ca_legacy_pathlen_zero")
    if warnings:
        body["warnings"] = warnings
    return body


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

    # Standalone deploys have no broker, so no JWKS to check — skip.
    if get_settings().standalone:
        checks["jwks_cache"] = "standalone"
        return {"status": "ready", "checks": checks}

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
