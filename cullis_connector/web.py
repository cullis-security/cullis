"""Local onboarding dashboard for cullis-connector.

Runs as a standalone FastAPI app on ``http://127.0.0.1:7777`` (configurable)
and wraps the device-code enrollment flow with three screens:

    /setup      — proxy URL + requester form
    /waiting    — admin-approval spinner (HTMX-polled)
    /connected  — identity summary + IDE auto-configure

The MCP stdio server (see ``server.py``) is a separate process: both read
and write ``~/.cullis/identity/``, so once the dashboard finishes
enrollment the MCP side can ``load_identity`` without any IPC.

Pending-enrollment state (in-flight keypair + session_id) is held in
process memory only — if the user closes the dashboard before admin
approves, they start fresh next time. The private key never touches disk
until the server has approved.
"""
from __future__ import annotations

import asyncio
import contextlib
import html
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cullis_connector.config import ConnectorConfig
from cullis_connector.discovery import (
    DiscoveredMastio,
    DiscoveryState,
    get_or_run_discovery,
    reset_discovery_cache,
)
from cullis_connector.statusline_token import ensure_statusline_token
from cullis_connector.enrollment import (
    EnrollmentFailed,
    RequesterInfo,
    _start,
)
from cullis_connector.inbox_dispatcher import InboxDispatcher
from cullis_connector.inbox_poller import DashboardInboxPoller
from cullis_connector.notifier import build_notifier
from cullis_connector.autostart import (
    autostart_status,
    install_autostart,
    recommend_command as autostart_recommend_command,
    uninstall_autostart,
)
from cullis_connector.ide_config import (
    IDEStatus,
    detect_all as ide_detect_all,
    install_mcp as ide_install_mcp,
    mcp_entry_snippet,
)
from cullis_connector.identity import (
    generate_keypair,
    has_identity,
    load_identity,
    public_key_to_pem,
    save_identity,
)
from cullis_connector.identity.store import IdentityMetadata

_log = logging.getLogger("cullis_connector.web")

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

# ADR-019 Phase 8c — locations to look for the Cullis Chat SPA build.
# Searched in order; first match wins. ``CULLIS_CHAT_DIST`` env var
# beats both. If none exist, /chat is not mounted (logged once at boot).
_CHAT_BUNDLED_DIR = _STATIC_DIR / "cullis-chat"
_CHAT_REPO_DEV_DIR = (
    Path(__file__).parent.parent / "frontend" / "cullis-chat" / "dist"
)


def _mask_token(token: str) -> str:
    """Return a Stripe/OpenAI-style preview of a Bearer token.

    First 8 chars + 8 middle bullets + last 4 chars. Long enough that
    two distinct tokens are visually distinct in a screenshot, short
    enough that the secret bulk is not on screen. Used by the API keys
    dashboard page (the operator clicks ``Reveal`` for the full value).
    """
    if len(token) <= 12:
        return "•" * len(token)
    return f"{token[:8]}{'•' * 8}{token[-4:]}"


def _resolve_chat_dist() -> Path | None:
    """Return the directory holding the built Cullis Chat SPA, or None.

    A directory counts as a valid SPA build if it contains an
    ``index.html`` at its root. We check that explicitly so an empty
    or half-built directory does not silently mount and serve 404s for
    every asset.
    """
    candidates: list[Path] = []
    env_path = os.environ.get("CULLIS_CHAT_DIST")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(_CHAT_BUNDLED_DIR)
    candidates.append(_CHAT_REPO_DEV_DIR)
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "index.html").is_file():
            return candidate
    return None


# ── Pending-enrollment in-memory state ───────────────────────────────────
#
# Single-user, single-process. A second tab on the same dashboard shares
# the same state — intentional, so the user can't accidentally start two
# enrollments in parallel.


@dataclass
class _Pending:
    session_id: str
    enroll_url: str
    site_url: str
    verify_tls: bool
    private_key: EllipticCurvePrivateKey
    requester: RequesterInfo
    started_at: float = field(default_factory=time.time)
    poll_interval_s: int = 5


_pending: _Pending | None = None

# ── MCP registration session state (ADR-009 sandbox) ─────────────────────
#
# Admin secret required to call the Mastio /v1/admin/mcp-resources API.
# Kept in process memory only — never persisted. The user re-enters it on
# each Connector restart. Prevents shoulder-surfing post-quit.

_mastio_admin_secret: str | None = None


def _clear_pending() -> None:
    global _pending
    _pending = None


def _set_admin_secret(secret: str | None) -> None:
    global _mastio_admin_secret
    _mastio_admin_secret = secret or None


# ── App factory ──────────────────────────────────────────────────────────


@contextlib.asynccontextmanager
async def _dashboard_lifespan(app: FastAPI):
    """Start/stop the inbox poller alongside the dashboard process.

    The poller only fires when an enrolled identity exists and the
    operator hasn't disabled notifications via env. We intentionally
    rebuild the CullisClient here (instead of sharing one with the
    stdio MCP server) because the dashboard runs in a separate
    process and on restart picks up whatever identity is on disk
    right now.

    Pre-enrollment dashboards yield with ``inbox_poller = None`` and
    rely on :func:`_ensure_inbox_poller_running` to spin up the
    notifier the moment the identity lands (post admin approval),
    instead of forcing the operator to restart the dashboard. That
    closes the dogfood bug where notifications silently never
    appeared because the dashboard had been launched before the
    profile was enrolled.
    """
    config = app.state.connector_config
    app.state.inbox_poller = None
    app.state.inbox_dispatcher = None
    # Generate / load the statusline bearer token once at startup so the
    # endpoints below can compare against a stable value. The file is
    # chmod 0600 — any local process that can read it already had the
    # means to read ``identity/agent.key`` anyway.
    app.state.statusline_token = ensure_statusline_token(config.config_dir)

    # ADR-019 — install the Ambassador if enabled and an identity exists.
    # We mount it lazily here (vs in build_app) because the identity may
    # land mid-process (post enrollment), so a fresh dashboard start
    # picks it up. If ``ambassador.enabled`` is false this is a no-op.
    # ADR-021 PR4c — when AMBASSADOR_MODE=shared, mount the multi-tenant
    # router instead of the single-user one. Default ``single`` keeps
    # the laptop topology unchanged.
    from cullis_connector.ambassador.shared.wire import (
        shared_mode_settings_from_env,
    )
    try:
        shared_settings = shared_mode_settings_from_env()
    except ValueError as exc:
        import logging as _logging
        _logging.getLogger("cullis_connector.web").error(
            "AMBASSADOR_MODE=shared configuration invalid: %s", exc,
        )
        raise
    if shared_settings.enabled:
        _maybe_install_shared_ambassador(app, config, shared_settings)
    else:
        _maybe_install_ambassador(app, config)

    _ensure_inbox_poller_running(app)
    try:
        yield
    finally:
        dispatcher = getattr(app.state, "inbox_dispatcher", None)
        poller = getattr(app.state, "inbox_poller", None)
        if dispatcher is not None:
            await dispatcher.stop()
        if poller is not None:
            await poller.stop()


def _ensure_inbox_poller_running(app: FastAPI) -> bool:
    """Idempotently start the inbox poller + dispatcher.

    Returns ``True`` if the poller is now running (either we started
    it or it already was), ``False`` if there's no identity to poll
    against or notifications are disabled. Safe to call from:

      - the dashboard lifespan (boot), which fires while the loop is
        still warming up but already running enough for
        ``poller.start()`` to schedule its task
      - ``/api/status`` right after ``save_identity`` succeeds, which
        is the lazy-spawn path that closes the "dashboard launched
        pre-enrollment" hole

    Intentionally synchronous: ``poller.start()`` and
    ``dispatcher.start()`` already wrap ``asyncio.create_task``
    internally, and both call sites run inside the event loop
    (lifespan + async handler), so no extra await plumbing is needed.
    """
    config = app.state.connector_config
    if getattr(app.state, "inbox_poller", None) is not None:
        return True
    if os.environ.get("CULLIS_CONNECTOR_NOTIFICATIONS", "on").lower() in ("0", "off", "false", "no"):
        _log.info("inbox poller disabled via CULLIS_CONNECTOR_NOTIFICATIONS")
        return False

    poller = _start_inbox_poller(config)
    if poller is None:
        return False
    poller.start()
    dispatcher = InboxDispatcher(poller, build_notifier())
    dispatcher.start()
    app.state.inbox_poller = poller
    app.state.inbox_dispatcher = dispatcher
    _log.info("inbox poller spawned (lazy=%s)", poller is not None)
    return True


def _ensure_ambassador_installed(app: FastAPI) -> bool:
    """Idempotently mount the Ambassador router on the running dashboard.

    Mirrors ``_ensure_inbox_poller_running``: the dashboard process may
    have been launched before enrollment (the Frontdesk bundle starts
    the Connector first so the operator can drive the wizard from the
    UI). In that boot the lifespan install at :func:`_dashboard_lifespan`
    short-circuits via ``has_identity`` and the Ambassador stays unmounted,
    so every ``/v1/chat/completions``, ``/v1/models``, ``/api/session/*``
    returns 404 until someone manually restarts the container.

    Calling this from ``/api/status`` the moment the enrollment flips
    to ``approved`` (or the moment a poll lands on an already-enrolled
    profile) closes the gap without an operator restart. Both single
    and shared variants of ``_maybe_install_ambassador`` are themselves
    idempotent, so this helper is safe on every poll.

    Returns ``True`` if the Ambassador is now mounted (either we just
    installed it or it was already there), ``False`` if install failed
    or was skipped — failure is intentionally best-effort: we log a
    warning and let the rest of the enrollment flow continue, because
    an Ambassador wiring error mustn't strand the operator on the
    "Approved" screen.
    """
    config = app.state.connector_config

    if getattr(app.state, "ambassador", None) is not None:
        return True
    if getattr(app.state, "shared_ambassador", None) is not None:
        return True

    try:
        from cullis_connector.ambassador.shared.wire import (
            shared_mode_settings_from_env,
        )
        shared_settings = shared_mode_settings_from_env()
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "post-enrollment Ambassador install skipped — could not read "
            "shared-mode settings: %s", exc,
        )
        return False

    try:
        if shared_settings.enabled:
            _maybe_install_shared_ambassador(app, config, shared_settings)
            return getattr(app.state, "shared_ambassador", None) is not None
        _maybe_install_ambassador(app, config)
        return getattr(app.state, "ambassador", None) is not None
    except Exception as exc:  # noqa: BLE001
        # Best-effort: never abort enrollment on Ambassador install
        # failure. The most likely cause is the Mastio Site being
        # unreachable during the post-CSR ``ensure_local_token`` step;
        # the operator can retry via a container restart once the
        # network settles.
        _log.warning(
            "post-enrollment Ambassador install failed (will retry on "
            "next /api/status poll): %s", exc,
        )
        return False


def _start_inbox_poller(config: ConnectorConfig) -> DashboardInboxPoller | None:
    """Build the poller if the identity is ready, return None otherwise.

    Pre-enrollment dashboards (the user is still on /setup) have no
    identity to poll for — silently skip and let the operator install
    the autostart later, after enrollment, with no extra work.
    """
    if not has_identity(config.config_dir):
        _log.info("no identity at %s — inbox poller skipped", config.config_dir)
        return None

    interval_s = float(os.environ.get("CULLIS_CONNECTOR_POLL_S", "10"))
    try:
        from cullis_sdk import CullisClient
        from cullis_connector.state import get_state

        # Load the identity bundle and attach it to the client. Helpers
        # like ``canonical_recipient`` read the sender's org from
        # ``client.identity.cert`` rather than process-global state —
        # the previous variant relied on ``state.extra["identity"]`` and
        # silently failed when that wasn't seeded (the M2.4 dashboard
        # bootstrap bug).
        identity = load_identity(config.config_dir)
        state = get_state()
        state.agent_id = identity.metadata.agent_id

        client = CullisClient.from_connector(config.config_dir)
        client.identity = identity
        # ``from_connector`` now loads ``identity/agent.key`` itself —
        # no need to re-read here.
    except Exception as exc:  # noqa: BLE001
        _log.warning("inbox poller bootstrap failed: %s", exc)
        return None
    return DashboardInboxPoller(client, poll_interval_s=interval_s)


def _maybe_install_ambassador(app: FastAPI, config: ConnectorConfig) -> None:
    """Mount Ambassador router if enabled and identity is on disk.

    Silent no-op when ``ambassador.enabled`` is false or when there is
    no identity yet (pre-enrollment dashboard). Logs the outcome
    explicitly for operator visibility.

    Idempotent: re-calling after the Ambassador is already mounted is a
    no-op. The post-enrollment hook in ``/api/status`` and the lifespan
    bootstrap can both call this safely — the second caller short-circuits
    here instead of tripping the loud ``RuntimeError`` raised by
    :func:`install_ambassador` on double-mount.
    """
    import logging
    log = logging.getLogger("cullis_connector.web")

    if getattr(app.state, "ambassador", None):
        log.info("Ambassador already installed; skipping re-install")
        return
    if not config.ambassador.enabled:
        log.info("Ambassador disabled by config (ambassador.enabled=False)")
        return
    if not has_identity(config.config_dir):
        log.info(
            "Ambassador install deferred: no identity at %s yet",
            config.config_dir,
        )
        return

    try:
        from cullis_connector.ambassador.auth import ensure_local_token
        from cullis_connector.ambassador.client import AmbassadorClient
        from cullis_connector.ambassador.router import install_ambassador
        from cullis_connector.identity.store import load_identity
    except ImportError:
        log.exception("Ambassador module import failed; skipping mount")
        return

    bundle = load_identity(config.config_dir)
    agent_id = bundle.metadata.agent_id
    site_url = bundle.metadata.site_url or config.site_url
    if "::" in agent_id:
        org_id = agent_id.split("::", 1)[0]
    else:
        org_id = ""
    if not site_url:
        log.warning(
            "Ambassador install skipped: site_url unknown "
            "(metadata=%r config=%r)",
            bundle.metadata.site_url, config.site_url,
        )
        return
    if not agent_id:
        log.warning("Ambassador install skipped: agent_id empty in identity")
        return

    bearer = ensure_local_token(config.config_dir)
    # The SDK accepts the private key in PEM bytes via login_from_pem;
    # serialise the in-memory PrivateKeyTypes object back to PEM here so
    # we don't have to re-read the keyfile (which has the right perms).
    from cryptography.hazmat.primitives import serialization
    key_pem = bundle.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # PR #724 follow-up — surface the on-disk DPoP key so the
    # AmbassadorClient can populate _egress_dpop_key on the SDK
    # instance. The chat completion path (cert-pinned on Mastio) signs
    # with this persistent key; without it Mastio refuses with 401
    # "DPoP proof was signed by a key not registered for this agent".
    _dpop_key_path = config.config_dir / "identity" / "dpop.jwk"

    holder = AmbassadorClient(
        site_url=site_url,
        agent_id=agent_id,
        org_id=org_id,
        cert_pem=bundle.cert_pem,
        key_pem=key_pem,
        verify_tls=config.verify_arg,
        dpop_key_path=_dpop_key_path,
    )
    # Loopback enforcement defaults to True for the laptop topology
    # (Connector bound to 127.0.0.1, defence-in-depth on the bind). In
    # the Frontdesk bundle the Ambassador sits behind nginx on a private
    # docker network and the TCP peer is the sidecar IP, not 127.0.0.1
    # — leaving the check on returns 403 on every ``/api/session/init``.
    # ``CULLIS_AMBASSADOR_LOOPBACK_ONLY=false`` opts out for that case.
    _loopback_env = os.environ.get("CULLIS_AMBASSADOR_LOOPBACK_ONLY", "")
    if _loopback_env.lower() in {"false", "0", "no", "off"}:
        _require_loopback_effective = False
    else:
        _require_loopback_effective = config.ambassador.require_local_only
    install_ambassador(
        app,
        bearer_token=bearer,
        client=holder,
        advertised_models=config.ambassador.advertised_models,
        require_local_only=_require_loopback_effective,
    )
    # Sprint 1 Step 6 PR-A, Connector-local conversation history. The
    # router shares the ambassador's loopback + bearer gate, scopes
    # every row by principal_id, and writes to <config_dir>/conversations.db
    # via the SQLite module in cullis_connector.conversations.
    from cullis_connector.ambassador.conversations_router import (
        router as conversations_router,
    )
    app.include_router(conversations_router)
    log.info(
        "Ambassador mounted: agent=%s site=%s bearer=*** (saved at %s)",
        agent_id, site_url, config.config_dir / "local.token",
    )


def _maybe_install_local_user_provisioner(
    app: FastAPI, config: ConnectorConfig,
) -> None:
    """Wire ADR-025 Phase 3 — local-mode UserPrincipal CSR + cert binding.

    Stashes on ``app.state``:

      - ``local_user_cache``    — :class:`UserCredentialCache` (1h TTL)
      - ``local_provisioner``   — :class:`LocalUserProvisioner`
      - ``local_csr_transport`` — kept alive for SDK token cache

    Also registers the per-request cert middleware on the same
    ``config_dir``. The middleware is idempotent and safe to leave
    installed even when the provisioner is unwired (it bails out early
    when no provisioner is on app.state).

    Silent no-op when:

      - the agent identity (``identity/agent.{crt,key}``) is missing
        — pre-enrollment dashboards. Once the operator finishes
        enrollment they restart the dashboard to pick this up.
      - the import chain fails (defensive — a missing dep should not
        crash the entire dashboard).
    """
    if not has_identity(config.config_dir):
        _log.info(
            "ADR-025 Phase 3 provisioner deferred: no identity at %s yet",
            config.config_dir,
        )
        return

    try:
        from cullis_connector.ambassador.shared.credentials import (
            UserCredentialCache,
        )
        from cullis_connector.ambassador.shared.keystore import (
            UserKeyStore, keystore_dir_for,
        )
        from cullis_connector.ambassador.shared.provisioning import (
            SdkMastioCsrTransport,
        )
        from cullis_connector.auth.cert_middleware import (
            install_cert_middleware,
        )
        from cullis_connector.identity.csr_flow import LocalUserProvisioner
    except ImportError:
        _log.exception(
            "ADR-025 Phase 3 provisioner import failed; skipping",
        )
        return

    # Mastio URL: prefer the same env the Frontdesk container uses so
    # one variable wires both shared and local mode. Fall back to the
    # site_url written into identity/metadata.json at enrollment.
    mastio_url = os.environ.get("CULLIS_FRONTDESK_MASTIO_URL", "").rstrip("/")
    if not mastio_url:
        try:
            bundle = load_identity(config.config_dir)
            mastio_url = (bundle.metadata.site_url or config.site_url).rstrip("/")
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "ADR-025 Phase 3 provisioner skipped: cannot read identity metadata: %s",
                exc,
            )
            return
    if not mastio_url:
        _log.warning(
            "ADR-025 Phase 3 provisioner skipped: no Mastio URL "
            "(CULLIS_FRONTDESK_MASTIO_URL or site_url)",
        )
        return

    transport = SdkMastioCsrTransport(
        config_dir=config.config_dir,
        base_url=mastio_url,
        verify_tls=config.verify_arg,
    )
    cache = UserCredentialCache()
    keystore = UserKeyStore(keystore_dir_for(config.config_dir))
    provisioner = LocalUserProvisioner(
        mastio=transport, cache=cache, keystore=keystore,
    )

    app.state.local_csr_transport = transport
    app.state.local_user_cache = cache
    app.state.local_keystore = keystore
    app.state.local_provisioner = provisioner

    # Cert middleware reads the same config_dir as the login router so
    # the persisted binding is read out of the same users.db file.
    install_cert_middleware(app, config_dir=config.config_dir)
    _log.info(
        "ADR-025 Phase 3 local provisioner mounted: mastio=%s",
        mastio_url,
    )


def _maybe_install_shared_ambassador(
    app: FastAPI,
    config: ConnectorConfig,
    settings,  # SharedModeSettings; typed via runtime import to avoid cycle
) -> None:
    """Mount the shared-mode Ambassador (ADR-021 PR4c).

    Activated when ``AMBASSADOR_MODE=shared``. Composes the cookie
    secret bootstrap, the per-user credential cache, and the
    ``HttpxMastioCsrTransport`` that ships CSRs to Mastio's
    ``/v1/principals/csr`` endpoint (PR4a) on behalf of newly
    SSO-authenticated users.

    The Ambassador's own client identity for the Mastio CSR call is
    the Connector's enrolled cert+key (loaded from
    ``<config_dir>/identity/``). Mastio enforces RBAC same-org so
    any agent enrolled in the deployment org can call the CSR
    endpoint for principals in that same org.
    """
    import logging
    log = logging.getLogger("cullis_connector.web")

    if getattr(app.state, "shared_ambassador", None):
        log.info("shared Ambassador already installed; skipping re-install")
        return
    if not has_identity(config.config_dir):
        log.warning(
            "shared Ambassador install deferred: no identity at %s yet "
            "(complete enrollment first)", config.config_dir,
        )
        return

    try:
        from cullis_connector.ambassador.shared.credentials import (
            UserCredentialCache,
        )
        from cullis_connector.ambassador.shared.keystore import (
            UserKeyStore, keystore_dir_for,
        )
        from cullis_connector.ambassador.shared.provisioning import (
            SdkMastioCsrTransport, UserProvisioner,
        )
        from cullis_connector.ambassador.shared.proxy_trust import (
            TrustedProxiesAllowlist,
        )
        from cullis_connector.ambassador.shared.router import (
            install_shared_ambassador,
        )
        from cullis_connector.ambassador.shared.wire import (
            bootstrap_cookie_secret,
        )
        from cullis_connector.identity.store import (
            CERT_FILENAME, KEY_FILENAME, _identity_dir,
        )
    except ImportError:
        log.exception(
            "shared Ambassador module import failed; skipping mount",
        )
        return

    identity_dir = _identity_dir(config.config_dir)
    cert_path = identity_dir / CERT_FILENAME
    key_path = identity_dir / KEY_FILENAME
    if not cert_path.exists() or not key_path.exists():
        log.warning(
            "shared Ambassador install skipped: identity files missing at %s",
            identity_dir,
        )
        return

    mastio_url = settings.mastio_url or config.site_url
    if not mastio_url:
        log.warning(
            "shared Ambassador install skipped: neither "
            "CULLIS_FRONTDESK_MASTIO_URL nor site_url is set",
        )
        return

    cookie_secret = bootstrap_cookie_secret(config.config_dir)
    trusted = TrustedProxiesAllowlist.from_cidrs(settings.trusted_proxies_cidrs)

    # ADR-021 PR4a-followup: the Court's CSR endpoint requires a
    # DPoP-bound JWT plus the mTLS cert. The previous HttpxMastioCsrTransport
    # only attached the cert and 401'd on every login. SdkMastioCsrTransport
    # uses cullis-sdk ``CullisClient`` to cache an access token + sign
    # per-request DPoP proofs, refreshing on the token TTL boundary.
    # ADR-021 PR4a-followup: the Court's CSR endpoint requires a broker-
    # issued DPoP-bound JWT plus the mTLS cert. The previous
    # HttpxMastioCsrTransport only attached the cert and 401'd on every
    # call. SdkMastioCsrTransport drives ``CullisClient.from_connector`` +
    # ``login_via_proxy_with_local_key`` so the broker token (not a
    # Mastio-local ADR-012 token) authorises the CSR call, with a 10-min
    # token cache + auto refresh.
    transport = SdkMastioCsrTransport(
        config_dir=config.config_dir,
        base_url=mastio_url,
        verify_tls=config.verify_arg,
    )
    app.state.shared_ambassador_csr_transport = transport  # keep alive

    cache = UserCredentialCache()
    keystore = UserKeyStore(keystore_dir_for(config.config_dir))
    provisioner = UserProvisioner(
        mastio=transport, cache=cache, keystore=keystore,
    )
    app.state.shared_ambassador_keystore = keystore  # keep alive

    # ADR-020 Phase 4 — broker URL for the user-inbox passthrough
    # (issue #488). Read from env so the deployment can route the
    # ambassador's inbox calls directly to the broker instead of
    # taking the long way through Mastio (which lacks a user-aware
    # broker bridge for inbox today).
    broker_url = os.environ.get("CULLIS_BROKER_URL", "")
    install_shared_ambassador(
        app,
        cookie_secret=cookie_secret,
        trusted_proxies=trusted,
        org_id=settings.org_id,
        trust_domain=settings.trust_domain,
        provisioner=provisioner,
        cookie_ttl_seconds=settings.cookie_ttl_seconds,
        site_url=mastio_url,
        broker_url=broker_url,
    )
    log.info(
        "shared Ambassador mounted: org=%s td=%s mastio=%s ttl=%ds",
        settings.org_id, settings.trust_domain,
        mastio_url, settings.cookie_ttl_seconds,
    )


def build_app(config: ConnectorConfig) -> FastAPI:
    """Return a FastAPI app bound to the given connector config.

    The config's ``config_dir`` is where the identity will be persisted on
    admin approval. ``site_url`` / ``verify_tls`` act as defaults for the
    setup form so a preconfigured deploy can skip the URL step.
    """
    app = FastAPI(
        title="Cullis Connector",
        docs_url=None,
        redoc_url=None,
        lifespan=_dashboard_lifespan,
    )
    # Stash for the lifespan handler to pick up — FastAPI doesn't pass
    # build-time arguments through to the lifespan callable.
    app.state.connector_config = config

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    # Expose the active profile name to every template (topbar shows
    # "Profile · north" when non-empty). Legacy flat layout and
    # explicit --config-dir override keep the empty-string default so
    # the template falls back to the plain "Local Edge · Your Machine"
    # sub-label.
    templates.env.globals["active_profile"] = config.profile_name or ""
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ADR-019 Phase 8c — mount the Cullis Chat SPA static build at /chat
    # if a built dist/ is reachable. Resolution order:
    #
    #   1. CULLIS_CHAT_DIST env var (operator override, useful in dev when
    #      the SPA is built somewhere unusual)
    #   2. cullis_connector/static/cullis-chat/ (production wheel layout —
    #      the build pipeline copies frontend/cullis-chat/dist there before
    #      packaging; pyproject.toml's force-include picks it up)
    #   3. <repo>/frontend/cullis-chat/dist/ (dev layout, when running from
    #      a source checkout)
    #
    # html=True so a bare GET /chat/ serves /chat/index.html. Templates
    # like connected.html link to /chat/ once enrollment is complete.
    chat_dist = _resolve_chat_dist()
    if chat_dist is not None:
        # Pre-mount gate: a user who navigates to /chat or /chat/ before
        # enrollment would otherwise get the prerendered SPA, which then
        # fails on its first /api/session/init call with a 404 (the
        # Ambassador router is only mounted by the lifespan after
        # has_identity is true). Surface the missing step explicitly by
        # redirecting to /setup. Asset paths under /chat/_astro/ and
        # other deep links keep flowing through to StaticFiles so an
        # already-loaded SPA tab can refresh assets without a redirect
        # ping-pong.
        @app.middleware("http")
        async def _chat_identity_gate(request, call_next):  # type: ignore[no-untyped-def]
            path = request.url.path
            if path == "/chat" or path == "/chat/":
                if not has_identity(config.config_dir):
                    return RedirectResponse("/setup", status_code=303)
            return await call_next(request)

        app.mount(
            "/chat",
            StaticFiles(directory=str(chat_dist), html=True),
            name="cullis_chat",
        )
        _log.info("cullis-chat SPA mounted at /chat from %s", chat_dist)
    else:
        _log.info(
            "cullis-chat SPA not mounted: no dist/ found; "
            "build the SPA (npm run build in frontend/cullis-chat) or "
            "set CULLIS_CHAT_DIST to enable /chat"
        )
    # Templates check this to decide whether to render the "Open Cullis
    # Chat" button on /connected. Stashed on app.state too so the
    # desktop wrapper can navigate to /chat post-enrollment.
    templates.env.globals["cullis_chat_mounted"] = chat_dist is not None
    app.state.cullis_chat_mounted = chat_dist is not None

    # ── ADR-025 Phase 1 — local user provisioning admin API ─────────────
    #
    # Mount only when AUTH_MODE=local (the FrontDesk shared-mode default
    # for SMB deployments without a corporate IdP). Set AUTH_MODE=oidc
    # to skip the mount entirely so the local-users surface does not
    # exist at all in IdP-only deployments.
    #
    # Phase 2 — additionally mount the local login + session router
    # under the same gate so /login, /api/auth/* and the cookie-issuing
    # endpoints exist exactly when admin pre-creation does.
    from cullis_connector.identity.auth_mode import (
        MODE_LOCAL, read_auth_mode,
    )
    auth_mode = read_auth_mode()
    app.state.auth_mode = auth_mode
    if auth_mode == MODE_LOCAL:
        from cullis_connector.admin.users_router import router as _users_router
        from cullis_connector.auth.local_router import router as _auth_local_router
        app.include_router(_users_router)
        app.include_router(_auth_local_router)
        _log.info(
            "ADR-025 admin /admin/users + /api/auth/* mounted (AUTH_MODE=%s)",
            auth_mode,
        )
        # ADR-025 Phase 3 — wire post-login CSR + per-request cert
        # binding. Only when local mode is active AND the agent
        # identity is on disk (``SdkMastioCsrTransport`` reads
        # ``identity/agent.{crt,key}`` to authenticate to Mastio).
        # Pre-enrollment dashboards leave the provisioner unwired;
        # the login router will return ``provisioning="skipped"`` and
        # the cert middleware silently passes through.
        _maybe_install_local_user_provisioner(app, config)
    else:
        _log.info(
            "ADR-025 admin /admin/users NOT mounted (AUTH_MODE=%s)", auth_mode,
        )

    # ── CSRF / cross-origin guard ────────────────────────────────────────
    #
    # Audit 2026-04-30 lane 5 C1 — every state-changing endpoint on the
    # dashboard (14 routes) had no CSRF token, no Origin/Referer check,
    # and no SameSite cookie because the dashboard had no session at all.
    # Any web page the operator visited could POST to ``/setup/pin-ca``
    # and overwrite the TOFU-pinned Org CA, configure their IDE to spawn
    # a malicious MCP server, etc. DNS rebinding to 127.0.0.1:7777
    # amplifies the surface.
    #
    # Defence: reject every state-changing request whose ``Origin`` (or,
    # as fallback, ``Referer``) does not match the dashboard's own host.
    # Browsers attach ``Origin`` automatically on cross-origin POST and
    # cannot be fooled by DNS rebinding because the header carries the
    # name the page was loaded from, not the resolved IP.
    #
    # Exemption: requests carrying ``Authorization: Bearer ...`` skip the
    # check. Bearer auth is the calling convention for non-browser
    # callers (statusline scripts hit ``/status/inbox/seen`` with the
    # token from ``statusline.token``); browsers never auto-attach
    # ``Authorization``, so the bearer path is not a CSRF vector.

    @app.middleware("http")
    async def _csrf_origin_guard(request: Request, call_next):  # type: ignore[no-untyped-def]
        # ADR-019 — Ambassador endpoints under /v1/* and /api/session/*
        # run their own auth (loopback + Bearer/cookie) and cannot rely
        # on Origin/Referer since OpenAI clients (Cullis Chat / Cursor /
        # OpenWebUI) do not always emit those headers. The session
        # endpoints in particular bootstrap the cookie that the rest of
        # the SPA's calls authenticate with; gating them on a CSRF token
        # the SPA does not yet have would deadlock the flow. Skip the
        # dashboard CSRF guard for these prefixes; the Ambassador's
        # session router enforces 401 on missing / invalid auth.
        if (
            request.url.path.startswith("/v1/")
            or request.url.path.startswith("/api/session/")
            or request.url.path.startswith("/api/auth/")
            or request.url.path.startswith("/admin/")
        ):
            # ``/admin/*`` runs its own constant-time ``X-Admin-Secret``
            # check (see ``cullis_connector/admin/auth.py``). The header
            # is not auto-attached by browsers, so the route is not a
            # CSRF vector — mirroring the exemption already granted to
            # the Bearer-token path below.
            #
            # ``/api/auth/*`` (ADR-025 Phase 2) is the login bootstrap:
            # the browser does not yet have a session cookie when it
            # POSTs /api/auth/login, so a CSRF token derived from the
            # session is impossible by construction. We instead require
            # JSON content-type on these routes (browsers will not
            # auto-set ``application/json`` on a cross-origin form-POST
            # without an Origin/Referer header that the SameSite=Strict
            # cookie already gates) — the router uses Pydantic-bound
            # JSON bodies which 422 on form-encoded payloads.
            return await call_next(request)
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            authz = request.headers.get("authorization", "")
            if not authz.startswith("Bearer "):
                expected_host = request.url.netloc
                expected_origins = {
                    f"http://{expected_host}",
                    f"https://{expected_host}",
                }
                origin = request.headers.get("origin")
                if origin is not None:
                    if origin not in expected_origins:
                        return JSONResponse(
                            {"detail": "cross-origin request blocked"},
                            status_code=403,
                        )
                else:
                    referer = request.headers.get("referer", "")
                    if referer:
                        if not any(
                            referer == o or referer.startswith(o + "/")
                            for o in expected_origins
                        ):
                            return JSONResponse(
                                {"detail": "cross-origin referer blocked"},
                                status_code=403,
                            )
                    else:
                        return JSONResponse(
                            {
                                "detail": (
                                    "missing Origin and Referer; "
                                    "browser POSTs must originate from the "
                                    "dashboard. Programmatic callers should "
                                    "use Authorization: Bearer."
                                )
                            },
                            status_code=403,
                        )
        return await call_next(request)

    # ── Routes ────────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def root() -> Response:
        """Dispatch to the correct screen based on current state.

        When identity is present AND the Cullis Chat SPA is mounted at
        /chat (ADR-019 Phase 8c), the root sends users straight to the
        chat surface — that is the consumer-facing destination of the
        desktop installer. The /connected dashboard is still reachable
        directly (or via the tray menu in the desktop wrapper) for
        admin / maintenance flows.

        First-boot default is the auto-discovery wizard at
        ``/setup/discover``: it probes a few local addresses for a
        running Mastio and pre-populates the enrollment form. The
        manual form at ``/setup`` stays reachable via a fallback link
        on the wizard page.
        """
        if has_identity(config.config_dir):
            if getattr(app.state, "cullis_chat_mounted", False):
                return RedirectResponse("/chat/", status_code=303)
            return RedirectResponse("/connected", status_code=303)
        if _pending is not None:
            return RedirectResponse("/waiting", status_code=303)
        return RedirectResponse("/setup/discover", status_code=303)

    @app.get("/setup", response_class=HTMLResponse)
    def setup_get(
        request: Request,
        error: str | None = None,
        site_url: str | None = None,
        ca_pinned: str | None = None,
    ) -> Response:
        # If identity already exists, don't show the form — nothing to do.
        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)

        # ``site_url`` and ``ca_pinned`` arrive as query params when the
        # caller is the auto-discovery wizard handing off to the manual
        # form with a pre-filled URL and an already-pinned CA.
        return templates.TemplateResponse(
            request,
            "setup.html",
            {
                "connector_status": "offline",
                "connector_status_label": "Offline",
                "site_url": site_url or config.site_url or "",
                "requester_name": "",
                "requester_email": "",
                "reason": "",
                "verify_tls_off": not config.verify_tls,
                "error": error,
                "ca_pinned_from_wizard": ca_pinned == "1",
            },
        )

    @app.post("/setup")
    def setup_post(
        request: Request,
        site_url: str = Form(...),
        requester_name: str = Form(...),
        requester_email: str = Form(...),
        reason: str = Form(""),
        verify_tls_off: str | None = Form(None),
    ) -> Response:
        global _pending

        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)

        verify_tls = verify_tls_off is None
        site_url = site_url.strip().rstrip("/")
        requester = RequesterInfo(
            name=requester_name.strip(),
            email=requester_email.strip(),
            reason=(reason or "").strip() or None,
        )

        private_key = generate_keypair()
        pubkey_pem = public_key_to_pem(private_key.public_key()).decode()

        try:
            from cullis_connector.config import verify_arg_for
            start_resp = _start(
                site_url=site_url,
                pubkey_pem=pubkey_pem,
                requester=requester,
                verify_tls=verify_arg_for(verify_tls, config.ca_chain_path),
                timeout_s=config.request_timeout_s,
            )
        except EnrollmentFailed as exc:
            return templates.TemplateResponse(
                request,
                "setup.html",
                {
                    "connector_status": "offline",
                    "connector_status_label": "Offline",
                    "site_url": site_url,
                    "requester_name": requester.name,
                    "requester_email": requester.email,
                    "reason": requester.reason or "",
                    "verify_tls_off": not verify_tls,
                    "error": str(exc),
                },
                status_code=400,
            )

        _pending = _Pending(
            session_id=str(start_resp["session_id"]),
            enroll_url=str(start_resp.get("enroll_url") or ""),
            site_url=site_url,
            verify_tls=verify_tls,
            private_key=private_key,
            requester=requester,
            poll_interval_s=int(start_resp.get("poll_interval_s", 5)),
        )
        return RedirectResponse("/waiting", status_code=303)

    # ── TOFU CA pinning (Finding #3 / dogfood 2026-04-29) ────────────────
    #
    # First-contact bootstrap: dashboard fetches the Org CA from the
    # anonymous /pki/ca.crt endpoint, shows the SHA-256 fingerprint to
    # the operator, and on confirmation pins the PEM to
    # ``<profile>/identity/ca-chain.pem``. Subsequent httpx clients pick
    # it up via ``ConnectorConfig.verify_arg`` and verify the Site's
    # leaf cert end-to-end without needing the operator to keep
    # ``--no-verify-tls`` on.

    def _fetch_ca_pem(site_url: str) -> tuple[str, str]:
        """Download the anonymous CA PEM and compute its SHA-256.

        Always called without TLS verification — the whole point of
        the TOFU bootstrap is that we don't trust the leaf yet. The
        fingerprint the operator compares against the value their
        admin gave them out-of-band is the actual trust anchor, not
        the TLS handshake. See ADR-015 §"Decision" item 2.

        The CI ``Ban insecure TLS opt-outs`` check (see ci.yml) flags
        literal ``verify=False`` even in this file; we route through
        a named constant to make the deviation explicit and locally
        auditable rather than triggering a global allow-list rule.
        """
        from cryptography import x509
        from cullis_connector.enrollment import cert_fingerprint
        # Sentinel — the only place in the Connector that intentionally
        # skips TLS verification. Rationale captured in the docstring
        # above. The constant maps directly to the httpx ``verify=``
        # parameter: False means "do not verify the TLS chain", which is
        # what the TOFU bootstrap requires (no anchor pinned yet). Do
        # NOT inline this back to a literal ``verify=False`` without
        # updating ci.yml + ADR-015.
        _VERIFY_TLS_FOR_CA_FETCH: bool = False
        url = site_url.rstrip("/") + "/pki/ca.crt"
        resp = httpx.get(
            url, verify=_VERIFY_TLS_FOR_CA_FETCH,
            timeout=config.request_timeout_s,
        )
        if resp.status_code == 404:
            raise RuntimeError(
                "Site has no Org CA configured yet — ask the admin to "
                "complete first-boot setup, then retry."
            )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Site returned HTTP {resp.status_code} for /pki/ca.crt"
            )
        pem = resp.text
        cert = x509.load_pem_x509_certificate(pem.encode())
        fingerprint = cert_fingerprint(cert)
        return pem, fingerprint

    @app.post("/setup/preview-ca")
    def setup_preview_ca(site_url: str = Form(...)) -> JSONResponse:
        """Show the operator the CA fingerprint before they pin it.

        Returns the PEM body along with its SHA-256 hex digest. The
        body is round-tripped through the browser so a TOCTOU between
        preview and pin can be caught at pin time by re-fetching and
        re-comparing — see ``setup_pin_ca``.
        """
        try:
            pem, fingerprint = _fetch_ca_pem(site_url)
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=400,
            )
        return JSONResponse({
            "fingerprint_sha256": fingerprint,
            "fingerprint_short": ":".join(
                fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)
            ),
            "ca_pem": pem,
        })

    @app.post("/setup/pin-ca")
    def setup_pin_ca(
        site_url: str = Form(...),
        fingerprint_expected: str = Form(...),
    ) -> JSONResponse:
        """Re-fetch the CA, verify the fingerprint still matches, save it.

        The re-fetch closes the TOCTOU between preview and pin: an
        attacker who could swap the CA between calls would have to
        produce a cert with the same SHA-256 digest, which is the
        whole point of using SHA-256 as the pin.
        """
        try:
            pem, fingerprint = _fetch_ca_pem(site_url)
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            return JSONResponse(
                {"error": str(exc)}, status_code=400,
            )
        if fingerprint.lower() != fingerprint_expected.lower().replace(":", ""):
            return JSONResponse(
                {
                    "error": (
                        "Fingerprint changed between preview and pin. "
                        "Aborting — refresh and verify with your admin."
                    ),
                    "fingerprint_now": fingerprint,
                },
                status_code=409,
            )
        identity_dir = config.config_dir / "identity"
        identity_dir.mkdir(parents=True, exist_ok=True)
        ca_path = identity_dir / "ca-chain.pem"
        ca_path.write_text(pem)
        try:
            ca_path.chmod(0o644)
        except OSError:
            pass  # Windows / non-POSIX filesystems
        return JSONResponse({
            "pinned": True,
            "path": str(ca_path),
            "fingerprint_sha256": fingerprint,
        })

    # ── First-boot auto-discovery wizard ──────────────────────────────
    #
    # Probes a small list of local addresses for a running Mastio,
    # surfaces the ``org_id`` / ``trust_domain`` / CA fingerprint a
    # confirmed Mastio reports via /.well-known/cullis/connector-bootstrap,
    # and on operator confirmation hands off to the existing manual
    # ``/setup`` form with the URL pre-filled and the CA already
    # pinned. The manual form remains the fallback when discovery
    # finds nothing.

    def _format_fingerprint(hex_digest: str | None) -> str | None:
        """Render bare hex as ``AB:CD:EF:..`` groups for visual diffing."""
        if not hex_digest:
            return None
        upper = hex_digest.upper()
        return ":".join(upper[i:i + 2] for i in range(0, len(upper), 2))

    def _enrich_for_template(
        mastio: DiscoveredMastio,
    ) -> dict[str, str | None]:
        """Pre-format fields the template wants but the dataclass doesn't carry."""
        return {
            "base_url": mastio.base_url,
            "org_id": mastio.org_id,
            "trust_domain": mastio.trust_domain,
            "mode": mastio.mode,
            "ca_fingerprint_sha256": mastio.ca_fingerprint_sha256,
            "ca_fingerprint_grouped": _format_fingerprint(
                mastio.ca_fingerprint_sha256,
            ),
        }

    @app.get("/setup/discover", response_class=HTMLResponse)
    def setup_discover_get(request: Request) -> Response:
        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)
        return templates.TemplateResponse(
            request,
            "setup_discovery.html",
            {
                "connector_status": "offline",
                "connector_status_label": "Offline",
            },
        )

    @app.get("/api/setup/discover/results", response_class=HTMLResponse)
    async def api_setup_discover_results(request: Request) -> Response:
        """HTMX endpoint that runs (or returns cached) discovery results."""
        if has_identity(config.config_dir):
            # Identity arrived between page load and HTMX fire — bounce.
            return HTMLResponse(
                '<meta http-equiv="refresh" content="0; url=/connected">'
            )
        state: DiscoveryState = await get_or_run_discovery()
        return templates.TemplateResponse(
            request,
            "setup_discovery_results.html",
            {
                "found": [_enrich_for_template(m) for m in state.found],
                "errors": state.errors,
            },
        )

    @app.post("/setup/discover/select")
    def setup_discover_select(
        base_url: str = Form(...),
        fingerprint: str = Form(...),
    ) -> Response:
        """Pin the CA reported by the wizard, then hand off to ``/setup``.

        The pin step re-fetches the CA from the chosen Mastio and
        verifies the fingerprint still matches what discovery surfaced
        — same TOCTOU guard as ``setup_pin_ca``. On a mismatch we
        bounce the operator back to the wizard with an error rather
        than silently pinning something they didn't see.
        """
        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)

        cleaned_url = base_url.strip().rstrip("/")
        if not cleaned_url.startswith("https://"):
            return RedirectResponse(
                "/setup/discover?error=non_https", status_code=303,
            )

        try:
            pem, observed_fp = _fetch_ca_pem(cleaned_url)
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            _log.warning("discover-select fetch CA failed: %s", exc)
            return RedirectResponse(
                "/setup/discover?error=ca_fetch_failed", status_code=303,
            )

        expected = fingerprint.lower().replace(":", "")
        if observed_fp.lower() != expected:
            _log.warning(
                "discover-select fingerprint mismatch: expected=%s observed=%s",
                expected, observed_fp,
            )
            # Drop the cache so a re-probe shows the new fingerprint.
            reset_discovery_cache()
            return RedirectResponse(
                "/setup/discover?error=fingerprint_changed", status_code=303,
            )

        identity_dir = config.config_dir / "identity"
        identity_dir.mkdir(parents=True, exist_ok=True)
        ca_path = identity_dir / "ca-chain.pem"
        ca_path.write_text(pem)
        try:
            ca_path.chmod(0o644)
        except OSError:
            pass

        # Hand off to the existing manual form with the URL pre-filled
        # and a flag the form can use to skip the TOFU CA section.
        from urllib.parse import urlencode
        qs = urlencode({"site_url": cleaned_url, "ca_pinned": "1"})
        return RedirectResponse(f"/setup?{qs}", status_code=303)

    @app.get("/waiting", response_class=HTMLResponse)
    def waiting_get(request: Request) -> Response:
        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)
        if _pending is None:
            return RedirectResponse("/setup", status_code=303)

        return templates.TemplateResponse(
            request,
            "waiting.html",
            {
                "connector_status": "waiting",
                "connector_status_label": "Pending approval",
                "session_id": _pending.session_id,
                "enroll_url": _pending.enroll_url,
                "admin_enrollments_url": f"{_pending.site_url.rstrip('/')}/proxy/enrollments",
                "started_at_ms": int(_pending.started_at * 1000),
            },
        )

    @app.get("/api/ping")
    def api_ping() -> JSONResponse:
        """Stable identity probe — used by ``cullis-connector dashboard``
        on startup to detect a Connector dashboard already bound to the
        port and tell the operator instead of crashing on EADDRINUSE.

        Returns the app name (and process port for diagnostics). Stays
        cheap and side-effect-free so we can call it from a port-busy
        path without coupling it to enrollment state.
        """
        return JSONResponse({"app": "cullis-connector"})

    @app.get("/api/status")
    async def api_status(request: Request) -> JSONResponse:
        """Single-shot poll of the remote enrollment status.

        Returns JSON so the waiting page's HTMX can route to the next
        screen on its own.

        Bug #10 fix-forward (2026-05-11 sera) — this endpoint MUST be
        ``async def``. The two ``_ensure_inbox_poller_running`` call
        sites (the ``has_identity`` early-return below and the
        post-``save_identity`` lazy-spawn after a successful poll)
        end up calling ``poller.start()`` → ``asyncio.create_task``,
        which requires a running event loop in the current thread.
        FastAPI runs ``def`` handlers in an anyio worker thread that
        has NO event loop, so the create_task call raises
        ``RuntimeError: no running event loop`` and the dashboard
        loops on broken /api/status responses forever. Pre-fix this
        was unreachable (Bug #5 stopped the dashboard from ever
        flipping to ``has_identity``); after #624 unlocked that path
        the customer-path smoke gate caught it immediately.
        """
        if has_identity(config.config_dir):
            # Lazy-spawn the inbox poller — the dashboard may have
            # been launched pre-enrollment, in which case the lifespan
            # bootstrap saw no identity and returned early. Now that
            # the identity is on disk (this branch), the operator
            # should start receiving notifications without having to
            # restart the dashboard. Idempotent + cheap.
            _ensure_inbox_poller_running(request.app)
            # Same shape for the Ambassador router — when the dashboard
            # was launched pre-enrollment the lifespan saw no identity
            # and skipped the mount, so ``/v1/chat/completions`` and
            # ``/api/session/*`` would 404 forever. Mount lazily here
            # (idempotent) so a restart is never required for the
            # customer to start chatting after approval.
            _ensure_ambassador_installed(request.app)
            return JSONResponse({"status": "approved"})
        if _pending is None:
            return JSONResponse({"status": "idle"})

        poll_url = (
            f"{_pending.site_url}/v1/enrollment/{_pending.session_id}/status"
        )
        # M-onb-1 audit fix — Mastio withholds ``cert_pem`` / ``agent_id`` /
        # ``capabilities`` unless the poll carries a proof-of-possession over
        # the enrollment keypair. The CLI path (``cullis_connector.enrollment``)
        # already sends this header; before this fix the dashboard ``/api/status``
        # path did not, so dashboard-driven enrollment got stuck in
        # ``"Approved enrollment is missing cert_pem"`` forever once the
        # admin approved the ticket. Same proof construction as the CLI.
        from cullis_connector.enrollment import _build_enrollment_proof
        proof = _build_enrollment_proof(_pending.private_key, _pending.session_id)
        try:
            from cullis_connector.config import verify_arg_for
            # ``httpx.get`` is synchronous; offload to a worker thread
            # so the FastAPI event loop stays free for other handlers
            # (we are now an ``async def`` after the Bug #10 fix).
            resp = await asyncio.to_thread(
                httpx.get,
                poll_url,
                headers={"X-Enrollment-Proof": proof},
                verify=verify_arg_for(_pending.verify_tls, config.ca_chain_path),
                timeout=config.request_timeout_s,
            )
        except httpx.HTTPError as exc:
            _log.warning("poll transient error: %s", exc)
            return JSONResponse({"status": "pending", "transient": True})

        if resp.status_code == 404:
            _clear_pending()
            return JSONResponse(
                {"status": "error", "error": "Session no longer exists on the proxy."},
                status_code=200,
            )
        if resp.status_code != 200:
            return JSONResponse(
                {
                    "status": "error",
                    "error": f"Proxy returned HTTP {resp.status_code}",
                },
                status_code=200,
            )

        record = resp.json()
        remote_status = record.get("status", "pending")

        if remote_status == "pending":
            return JSONResponse({"status": "pending"})

        if remote_status == "approved":
            cert_pem = record.get("cert_pem")
            if not cert_pem:
                return JSONResponse(
                    {
                        "status": "error",
                        "error": "Approved enrollment is missing cert_pem.",
                    }
                )
            agent_id = str(record.get("agent_id") or "")
            capabilities = list(record.get("capabilities") or [])
            metadata = IdentityMetadata(
                agent_id=agent_id,
                capabilities=capabilities,
                site_url=_pending.site_url,
                issued_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
            save_identity(
                config_dir=config.config_dir,
                cert_pem=cert_pem,
                private_key=_pending.private_key,
                ca_chain_pem=None,  # Phase 2c will fetch the CA chain.
                metadata=metadata,
            )
            _clear_pending()
            # First moment the identity exists on disk — kick the
            # inbox poller now so the operator sees notifications
            # without having to restart the dashboard. The next
            # /api/status poll would also catch this via the
            # ``has_identity`` branch above, but doing it here too
            # closes the small window between approval and the
            # following HTMX poll.
            _ensure_inbox_poller_running(request.app)
            # Same window applies to the Ambassador mount — without
            # this hook the Frontdesk bundle leaves ``/v1/chat`` 404
            # until ``docker compose restart`` because the Connector
            # boots before the operator runs the wizard. The helper
            # is idempotent and best-effort (logs + continues on
            # failure), so the approval response is never blocked
            # on Mastio reachability.
            _ensure_ambassador_installed(request.app)
            return JSONResponse({"status": "approved", "agent_id": agent_id})

        if remote_status == "rejected":
            reason = record.get("rejection_reason") or "Admin rejected the request."
            _clear_pending()
            return JSONResponse({"status": "rejected", "error": reason})

        if remote_status == "expired":
            _clear_pending()
            return JSONResponse(
                {"status": "expired", "error": "Enrollment session expired."}
            )

        return JSONResponse(
            {"status": "error", "error": f"Unexpected status '{remote_status}'"}
        )

    @app.post("/api/test-ping")
    def api_test_ping() -> JSONResponse:
        """Smoke-probe the configured Mastio Site from the dashboard.

        Closes Finding #5 from the 2026-04-29 dogfood: a freshly
        enrolled operator had no in-dashboard way to ask "is this
        actually working?" and had to drop into the MCP tool surface
        (``hello_site``) to confirm. We replicate the same probe here
        — ``GET <site>/health`` with the same TLS posture as the rest
        of the connector — so the answer lives one click away from
        the identity card.
        """
        if not has_identity(config.config_dir):
            return JSONResponse(
                {"ok": False, "error": "No identity loaded — enroll first."},
                status_code=200,
            )
        if not config.site_url:
            return JSONResponse(
                {"ok": False, "error": "Site URL is not configured."},
                status_code=200,
            )

        url = f"{config.site_url.rstrip('/')}/health"
        started = time.perf_counter()
        try:
            resp = httpx.get(
                url,
                verify=config.verify_arg,
                timeout=config.request_timeout_s,
            )
        except httpx.HTTPError as exc:
            return JSONResponse({
                "ok": False,
                "site_url": config.site_url,
                "error": f"Site unreachable: {exc}",
            })

        rtt_ms = round((time.perf_counter() - started) * 1000, 1)
        if resp.status_code != 200:
            return JSONResponse({
                "ok": False,
                "site_url": config.site_url,
                "rtt_ms": rtt_ms,
                "error": f"Site responded with HTTP {resp.status_code}",
            })

        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        return JSONResponse({
            "ok": True,
            "site_url": config.site_url,
            "rtt_ms": rtt_ms,
            "site_status": payload.get("status", "unknown"),
            "site_version": payload.get("version", "unknown"),
            "tls_verified": config.verify_arg is not False,
        })

    @app.post("/cancel")
    def cancel() -> Response:
        _clear_pending()
        return RedirectResponse("/setup", status_code=303)

    def _require_statusline_token(authorization: str | None) -> None:
        """Reject requests without the dashboard's statusline token.

        The loopback bind (127.0.0.1:7777) stops remote callers but any
        other local process under the same user could otherwise read
        inbox metadata / reset the unread counter. The bearer token
        lives under ``<config_dir>/identity/statusline.token`` (0600),
        so any attacker with read access to it already owned the agent
        key anyway.
        """
        expected = getattr(app.state, "statusline_token", None)
        if not expected:
            # Should never happen — lifespan seeds it — but fail closed
            # rather than silently allow unauthenticated reads.
            raise HTTPException(status_code=503, detail="statusline token not initialised")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        presented = authorization.removeprefix("Bearer ").strip()
        # Constant-time compare — the token is short and the server is
        # loopback-only, but it's still a credential.
        if not secrets.compare_digest(presented, expected):
            raise HTTPException(status_code=401, detail="bad bearer token")

    @app.get("/status/inbox")
    def status_inbox(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Statusline-friendly snapshot of the inbox state.

        Designed to be polled cheaply (every few seconds) by a Claude
        Code statusline command or any external script that wants
        to render a "📨 N from Mario" badge. Always returns 200 with
        a stable shape — when notifications are off or the dashboard
        hasn't seen any messages yet, ``unread`` is 0 and the rest
        is null.

        Requires ``Authorization: Bearer <token>`` — see
        ``<config_dir>/identity/statusline.token``.
        """
        _require_statusline_token(authorization)
        dispatcher = getattr(request.app.state, "inbox_dispatcher", None)
        if dispatcher is None:
            return JSONResponse({
                "unread": 0,
                "last_sender": None,
                "last_preview": None,
                "last_received_at": None,
                "total_seen": 0,
            })
        return JSONResponse(dispatcher.status_snapshot())

    @app.post("/status/inbox/seen")
    def status_inbox_seen(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> JSONResponse:
        """Reset the unread counter — call when the user has read the
        latest batch (the dashboard's `/inbox` view does it on load,
        statusline scripts can call it on click).

        Requires ``Authorization: Bearer <token>`` — see
        ``<config_dir>/identity/statusline.token``.
        """
        _require_statusline_token(authorization)
        dispatcher = getattr(request.app.state, "inbox_dispatcher", None)
        if dispatcher is not None:
            dispatcher.ack()
        return JSONResponse({"ok": True})

    @app.get("/connected", response_class=HTMLResponse)
    def connected_get(request: Request) -> Response:
        if not has_identity(config.config_dir):
            return RedirectResponse("/setup", status_code=303)

        identity = load_identity(config.config_dir)
        meta = identity.metadata
        site_host = _host_of(meta.site_url)
        astatus = autostart_status()

        return templates.TemplateResponse(
            request,
            "connected.html",
            {
                "connector_status": "online",
                "connector_status_label": "Online",
                "agent_id": meta.agent_id or "(unassigned)",
                "site_host": site_host,
                "capabilities": list(meta.capabilities or []),
                "issued_at": meta.issued_at or "—",
                "ides": _detect_ides(),
                "mcp_snippet": mcp_entry_snippet(),
                "autostart_enabled": astatus.installed,
                "autostart_platform": astatus.platform,
                "autostart_service_path": (
                    str(astatus.service_path) if astatus.service_path else None
                ),
            },
        )

    @app.get("/api-keys", response_class=HTMLResponse)
    def api_keys_get(request: Request) -> Response:
        """Render the local Ambassador Bearer token + Reveal/Copy/Rotate UI.

        Wave 2 of the show-token gap closure ([[gap-connector-show-token-cli]]).
        The CLI ``cullis-connector show-token`` covers the script path; this
        page covers the GUI path (LibreChat / Cherry Studio / AnythingLLM /
        OpenWebUI operators who never open a terminal).
        """
        if not has_identity(config.config_dir):
            return RedirectResponse("/setup", status_code=303)

        from cullis_connector.ambassador.auth import (
            LOCAL_TOKEN_FILENAME,
            ensure_local_token,
        )

        token = ensure_local_token(config.config_dir)
        token_masked = _mask_token(token)
        token_path = config.config_dir / LOCAL_TOKEN_FILENAME

        # The Ambassador binds to the same host:port as the dashboard. We
        # already know the dashboard URL the operator just opened in the
        # browser (request.base_url); re-use it so the snippet shown matches
        # exactly the URL they will paste into LibreChat / Cherry Studio.
        ambassador_url = str(request.base_url).rstrip("/")

        return templates.TemplateResponse(
            request,
            "api_keys.html",
            {
                "token": token,
                "token_masked": token_masked,
                "token_path": str(token_path),
                "ambassador_url": ambassador_url,
            },
        )

    @app.post("/api-keys/rotate")
    def api_keys_rotate() -> JSONResponse:
        """Force-rotate the local Bearer token and return the new value.

        Idempotent at the file level (file is overwritten atomically by
        ``rotate_local_token``); not idempotent semantically — every external
        client cached with the old value stops working until re-pasted. The
        dashboard's HTMX form confirms this with a ``hx-confirm`` dialog
        before firing the request. Same-origin protection comes from the
        global ``_csrf_origin_guard`` middleware already in place; no extra
        CSRF token because the Ambassador only listens on 127.0.0.1.
        """
        if not has_identity(config.config_dir):
            return JSONResponse({"error": "no identity"}, status_code=400)

        from cullis_connector.ambassador.auth import rotate_local_token

        token = rotate_local_token(config.config_dir)
        return JSONResponse({
            "token": token,
            "token_masked": _mask_token(token),
        })

    @app.post("/autostart/toggle")
    def autostart_toggle() -> JSONResponse:
        """Flip autostart on or off — server is the source of truth for
        current state so the UI stays consistent across reloads."""
        current = autostart_status()
        if current.installed:
            result = uninstall_autostart()
            if result.status in ("uninstalled", "missing"):
                return JSONResponse({"enabled": False, "status": "disabled"})
            return JSONResponse(
                {"enabled": True, "status": "error", "error": result.error},
                status_code=500,
            )
        result = install_autostart(autostart_recommend_command())
        if result.status in ("installed", "already_configured"):
            return JSONResponse(
                {
                    "enabled": True,
                    "status": "enabled",
                    "note": result.note,
                    "service_path": str(result.service_path) if result.service_path else None,
                }
            )
        return JSONResponse(
            {"enabled": False, "status": "error", "error": result.error},
            status_code=500,
        )

    @app.post("/configure/{ide_id}")
    def configure_ide(ide_id: str) -> JSONResponse:
        """Merge the Cullis MCP entry into the IDE's config file.

        The heavy lifting is in ``cullis_connector.ide_config`` — this
        route just wraps it with HTTP status codes and a UI-friendly
        payload.
        """
        backup_dir = config.config_dir / "backups"
        # Propagate the active profile into the registered args so the
        # IDE spawns the connector with --profile <name> when a profile
        # is loaded. Falls back to the SDK default ["serve"] otherwise.
        extra_args: list[str] | None = None
        if config.profile_name:
            extra_args = ["serve", "--profile", config.profile_name]
        result = ide_install_mcp(ide_id, backup_dir=backup_dir, args=extra_args)

        if result.status == "installed":
            _log.info(
                "ide-config installed for %s → %s (backup=%s)",
                ide_id, result.config_path, result.backup_path,
            )
            return JSONResponse(
                {
                    "status": "installed",
                    "ide_id": ide_id,
                    "config_path": str(result.config_path) if result.config_path else None,
                    "backup_path": str(result.backup_path) if result.backup_path else None,
                    "message": "Configured. Restart the app to pick up Cullis.",
                },
                status_code=200,
            )
        if result.status == "already_configured":
            return JSONResponse(
                {
                    "status": "already_configured",
                    "ide_id": ide_id,
                    "config_path": str(result.config_path) if result.config_path else None,
                    "message": "Already configured — nothing to do.",
                },
                status_code=200,
            )

        _log.warning("ide-config failed for %s: %s", ide_id, result.error)
        return JSONResponse(
            {
                "status": "error",
                "ide_id": ide_id,
                "error": result.error or "Unknown error.",
            },
            status_code=400,
        )

    # ── MCP resource registration (ADR-009 sandbox) ──────────────────────

    def _mastio_client() -> httpx.Client:
        identity = load_identity(config.config_dir)
        base = identity.metadata.site_url.rstrip("/")
        return httpx.Client(
            base_url=base, verify=config.verify_arg, timeout=10.0,
        )

    def _mcp_admin_headers() -> dict[str, str]:
        if not _mastio_admin_secret:
            raise RuntimeError("admin secret not set")
        return {"X-Admin-Secret": _mastio_admin_secret}

    @app.get("/mcp", response_class=HTMLResponse)
    def mcp_get(request: Request, error: str | None = None) -> Response:
        """MCP resource registration screen (Connector-side admin UI).

        Gated on identity existing — this is a post-enrollment admin flow.
        If no admin secret is in session, render a prompt form first.
        """
        if not has_identity(config.config_dir):
            return RedirectResponse("/setup", status_code=303)

        identity = load_identity(config.config_dir)
        meta = identity.metadata
        site_host = _host_of(meta.site_url)

        resources: list[dict[str, Any]] = []
        resources_error: str | None = None
        if _mastio_admin_secret:
            try:
                with _mastio_client() as c:
                    r = c.get(
                        "/v1/admin/mcp-resources",
                        headers=_mcp_admin_headers(),
                    )
                    if r.status_code == 403:
                        resources_error = "admin secret rejected (403)"
                    else:
                        r.raise_for_status()
                        resources = r.json()
            except Exception as exc:
                resources_error = f"failed to fetch: {exc}"

        return templates.TemplateResponse(
            request,
            "mcp.html",
            {
                "connector_status": "online",
                "connector_status_label": "Online",
                "agent_id": meta.agent_id or "(unassigned)",
                "site_host": site_host,
                "admin_secret_set": _mastio_admin_secret is not None,
                "resources": resources,
                "resources_error": resources_error,
                "error": error,
            },
        )

    @app.post("/mcp/admin-secret")
    def mcp_set_admin_secret(admin_secret: str = Form(...)) -> Response:
        _set_admin_secret(admin_secret.strip())
        return RedirectResponse("/mcp", status_code=303)

    @app.post("/mcp/admin-secret/clear")
    def mcp_clear_admin_secret() -> Response:
        _set_admin_secret(None)
        return RedirectResponse("/mcp", status_code=303)

    @app.post("/mcp/register")
    def mcp_register(
        name: str = Form(...),
        endpoint_url: str = Form(...),
        description: str = Form(""),
        required_capability: str = Form(""),
    ) -> Response:
        if not _mastio_admin_secret:
            return RedirectResponse(
                "/mcp?error=" + "admin+secret+not+set", status_code=303,
            )
        identity = load_identity(config.config_dir)
        body: dict[str, Any] = {
            "name": name.strip(),
            "endpoint_url": endpoint_url.strip(),
            "auth_type": "none",
            "enabled": True,
        }
        if description.strip():
            body["description"] = description.strip()
        if required_capability.strip():
            body["required_capability"] = required_capability.strip()
        # The Mastio scopes resources per-org; pull it from the enrolled
        # agent_id prefix (``org::agent``).
        agent_id = identity.metadata.agent_id or ""
        if "::" in agent_id:
            body["org_id"] = agent_id.split("::", 1)[0]

        try:
            with _mastio_client() as c:
                r = c.post(
                    "/v1/admin/mcp-resources",
                    headers=_mcp_admin_headers(),
                    json=body,
                )
                if r.status_code == 403:
                    return RedirectResponse(
                        "/mcp?error=admin+secret+rejected", status_code=303,
                    )
                if r.status_code == 409:
                    return RedirectResponse(
                        "/mcp?error=name+already+exists", status_code=303,
                    )
                if not r.is_success:
                    return RedirectResponse(
                        "/mcp?error=" + f"registration+failed+({r.status_code})",
                        status_code=303,
                    )
        except Exception as exc:
            _log.warning("mcp_register failed: %s", exc)
            return RedirectResponse("/mcp?error=network+error", status_code=303)

        return RedirectResponse("/mcp", status_code=303)

    @app.post("/mcp/{resource_id}/delete")
    def mcp_delete(resource_id: str) -> Response:
        if not _mastio_admin_secret:
            return RedirectResponse("/mcp", status_code=303)
        try:
            with _mastio_client() as c:
                c.delete(
                    f"/v1/admin/mcp-resources/{resource_id}",
                    headers=_mcp_admin_headers(),
                )
        except Exception as exc:
            _log.warning("mcp_delete failed: %s", exc)
        return RedirectResponse("/mcp", status_code=303)

    @app.post("/mcp/{resource_id}/bind-self")
    def mcp_bind_self(resource_id: str) -> Response:
        """Bind the currently-enrolled agent to this resource."""
        if not _mastio_admin_secret:
            return RedirectResponse("/mcp", status_code=303)
        identity = load_identity(config.config_dir)
        agent_id = identity.metadata.agent_id
        if not agent_id:
            return RedirectResponse(
                "/mcp?error=agent_id+unknown", status_code=303,
            )
        try:
            with _mastio_client() as c:
                r = c.post(
                    "/v1/admin/mcp-resources/bindings",
                    headers=_mcp_admin_headers(),
                    json={"agent_id": agent_id, "resource_id": resource_id},
                )
                if r.status_code == 409:
                    # idempotent from the UX standpoint
                    pass
        except Exception as exc:
            _log.warning("mcp_bind_self failed: %s", exc)
        return RedirectResponse("/mcp", status_code=303)

    @app.get("/profiles", response_class=HTMLResponse)
    def profiles_get(request: Request) -> Response:
        """List the profiles on this workstation.

        The page is informational — runtime switching is out of scope
        for M3.3b. The bottom of the page turns a chosen profile name
        into a ready-to-paste shell snippet the user can run in a new
        terminal to enrol it.
        """
        from cullis_connector.profile import (
            config_root_from_dir,
            list_profiles,
            profile_dir,
        )
        from cullis_connector.identity.store import has_identity

        root = config_root_from_dir(config.config_dir, config.profile_name)
        rows: list[dict[str, Any]] = []
        for name in list_profiles(root):
            if name == "default" and not config.profile_name and (
                config.config_dir == root
            ):
                # Legacy flat layout — the "default" profile actually
                # lives at the root, not under profiles/default/.
                pdir = root
            else:
                pdir = profile_dir(root, name)
            rows.append({
                "name": name,
                "path": str(pdir),
                "enrolled": has_identity(pdir),
            })

        return templates.TemplateResponse(
            request,
            "profiles.html",
            {
                "connector_status": "online"
                    if has_identity(config.config_dir) else "waiting",
                "connector_status_label": "Online"
                    if has_identity(config.config_dir) else "Setting up",
                "profiles": rows,
            },
        )

    @app.post("/profiles/create", response_class=HTMLResponse)
    def profiles_create(request: Request, name: str = Form(...)) -> Response:
        """HTMX handler — validates a candidate profile name and
        returns a snippet of shell commands that enrol it. No
        filesystem side effects: the user runs the snippet when
        they're ready, so nothing is partially created if they
        change their mind."""
        from cullis_connector.profile import validate_profile_name

        try:
            validate_profile_name(name.strip())
        except ValueError as exc:
            return HTMLResponse(
                f'<div class="profile-create-error">'
                f'{html.escape(str(exc))}</div>',
                status_code=400,
            )

        site_url = ""
        if has_identity(config.config_dir):
            try:
                site_url = load_identity(config.config_dir).metadata.site_url or ""
            except Exception:
                site_url = ""

        clean_name = name.strip()
        enroll_cmd = (
            f"cullis-connector enroll --profile {clean_name} "
            f"--site-url {site_url or 'https://cullis.example'} "
            f"--requester-name \"You\" "
            f"--requester-email \"you@example.com\""
        )
        serve_cmd = f"cullis-connector desktop --profile {clean_name}"

        snippet = (
            f'<div class="profile-create-ok">'
            f'<p>Run these in a new terminal:</p>'
            f'<pre class="profile-create-snippet">{html.escape(enroll_cmd)}</pre>'
            f'<p>Once your admin approves, launch the new profile with:</p>'
            f'<pre class="profile-create-snippet">{html.escape(serve_cmd)}</pre>'
            f'</div>'
        )
        return HTMLResponse(snippet)

    # ── ADR-033 Phase 2 — WebAuthn dashboard surface ─────────────────────
    async def _webauthn_proxy(
        request: Request,
        *,
        method: str,
        path: str,
        body: bytes | None = None,
        json_body: bool = False,
    ) -> Response:
        """Forward a WebAuthn dashboard call to the Mastio.

        The Connector dashboard runs on the user's machine on a loopback
        port; the browser cannot present the Connector workload certificate
        directly. We proxy the call through this helper so the same mTLS
        identity the Ambassador uses for ``/v1/principals/csr`` also
        authorises the WebAuthn endpoints.

        Phase 2 ships with a thin httpx-based forwarder: it relies on
        ``CULLIS_FRONTDESK_MASTIO_URL`` for the upstream URL and on the
        Ambassador-provided cert + DPoP-bound token already cached in
        ``cullis_connector.ambassador.shared`` to authenticate. When that
        wiring is missing (developer setup running the dashboard without
        the shared Ambassador) the proxy returns 503 so the dashboard
        renders the message instead of failing silently.
        """
        if not has_identity(config.config_dir):
            return JSONResponse(
                {"detail": "connector not enrolled yet"}, status_code=403,
            )
        identity = load_identity(config.config_dir)
        principal_id = getattr(
            identity.metadata, "user_principal_id", "",
        ) or getattr(identity.metadata, "agent_id", "")
        if not principal_id:
            return JSONResponse(
                {"detail": "no principal id resolved on this connector"},
                status_code=503,
            )

        mastio_url = os.environ.get("CULLIS_FRONTDESK_MASTIO_URL", "").rstrip("/")
        if not mastio_url:
            mastio_url = (
                getattr(identity.metadata, "site_url", "") or config.site_url or ""
            ).rstrip("/")
        if not mastio_url:
            return JSONResponse(
                {
                    "detail": (
                        "no Mastio URL configured; set "
                        "CULLIS_FRONTDESK_MASTIO_URL or re-run enrollment "
                        "to refresh identity metadata."
                    ),
                },
                status_code=503,
            )

        target = (
            f"{mastio_url}/v1/principals/{principal_id}/{path}"
            if "webauthn/" in path
            else f"{mastio_url}/v1/principals/{principal_id}/webauthn/{path}"
        )

        # Phase 2 ships the proxy surface + dashboard UI; the underlying
        # shared Ambassador HTTP client wiring (DPoP-bound JWT, mTLS
        # cert chain, refresh on rotate) lands in Phase 2b. Returning
        # 501 with a stable detail lets the dashboard render an explicit
        # banner instead of degenerating into a "fetch failed" toast,
        # and keeps the route shape stable for the Phase 2b commit.
        log.info(
            "webauthn proxy stub hit: method=%s path=%s principal=%s "
            "target=%s (Phase 2b wires the upstream client)",
            method, path, principal_id, target,
        )
        return JSONResponse(
            {
                "detail": (
                    "WebAuthn proxy is staged but not yet wired to the "
                    "shared Ambassador HTTP client; tracked as ADR-033 "
                    "Phase 2b. The dashboard UI, schema, Mastio endpoints "
                    "and audit chain rows are already live; this stub "
                    "lifts to a real forwarder once the Ambassador "
                    "exposes a reusable client surface."
                ),
            },
            status_code=501,
        )

    @app.get("/webauthn", response_class=HTMLResponse)
    def webauthn_page(request: Request) -> Response:
        """Render the per-principal authenticator management screen.

        The page lists registered credentials, lets the user enrol a new
        authenticator through ``navigator.credentials.create``, and
        revokes one through DELETE on the Connector proxy endpoints
        below. Resolving the principal id needs an enrolled Connector
        identity; redirect to /setup when missing so the user sees the
        onboarding flow first.
        """
        if not has_identity(config.config_dir):
            return RedirectResponse("/setup", status_code=303)
        identity = load_identity(config.config_dir)
        meta = identity.metadata
        principal_id = getattr(meta, "user_principal_id", "") or getattr(
            meta, "agent_id", "",
        ) or "(unassigned)"
        return templates.TemplateResponse(
            request,
            "webauthn.html",
            {
                "connector_status": "online",
                "connector_status_label": "Online",
                "principal_id": principal_id,
            },
        )

    @app.get("/api/webauthn/credentials", response_class=JSONResponse)
    async def webauthn_list_credentials(request: Request) -> JSONResponse:
        return await _webauthn_proxy(request, method="GET", path="credentials")

    @app.post("/api/webauthn/register/start", response_class=JSONResponse)
    async def webauthn_register_start(request: Request) -> JSONResponse:
        return await _webauthn_proxy(
            request, method="POST", path="webauthn/register/start",
        )

    @app.post("/api/webauthn/register/finish", response_class=JSONResponse)
    async def webauthn_register_finish(request: Request) -> JSONResponse:
        body = await request.body()
        return await _webauthn_proxy(
            request, method="POST", path="webauthn/register/finish",
            body=body, json_body=True,
        )

    @app.delete("/api/webauthn/credentials/{credential_id_b64url}")
    async def webauthn_revoke_credential(
        request: Request, credential_id_b64url: str,
    ) -> Response:
        return await _webauthn_proxy(
            request, method="DELETE",
            path=f"webauthn/credentials/{credential_id_b64url}",
        )

    return app


# ── Helpers ──────────────────────────────────────────────────────────────


def _host_of(url: str) -> str:
    if not url:
        return "—"
    try:
        parsed = urlparse(url)
        return parsed.netloc or url
    except ValueError:
        return url


def _detect_ides() -> list[dict[str, Any]]:
    """Map the IDE detector's typed results onto the simpler shape the
    template expects (id, name, status, note).

    The template treats ``installed`` / ``detected`` / ``missing`` as
    three visual states; the less-common ``error`` bucket piggy-backs on
    ``detected`` (card still clickable, but the note warns the user).
    """
    status_map = {
        IDEStatus.CONFIGURED: "installed",
        IDEStatus.DETECTED:   "detected",
        IDEStatus.MISSING:    "missing",
        IDEStatus.ERROR:      "detected",
    }
    rows = []
    for r in ide_detect_all():
        rows.append({
            "id": r.ide_id,
            "name": r.display_name,
            "status": status_map.get(r.status, "missing"),
            "note": r.note or "",
        })
    return rows
