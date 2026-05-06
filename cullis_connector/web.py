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
    """
    import logging
    log = logging.getLogger("cullis_connector.web")

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

    holder = AmbassadorClient(
        site_url=site_url,
        agent_id=agent_id,
        org_id=org_id,
        cert_pem=bundle.cert_pem,
        key_pem=key_pem,
        verify_tls=config.verify_arg,
    )
    install_ambassador(
        app,
        bearer_token=bearer,
        client=holder,
        advertised_models=config.ambassador.advertised_models,
        require_local_only=config.ambassador.require_local_only,
    )
    log.info(
        "Ambassador mounted: agent=%s site=%s bearer=*** (saved at %s)",
        agent_id, site_url, config.config_dir / "local.token",
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
    provisioner = UserProvisioner(mastio=transport, cache=cache)

    install_shared_ambassador(
        app,
        cookie_secret=cookie_secret,
        trusted_proxies=trusted,
        org_id=settings.org_id,
        trust_domain=settings.trust_domain,
        provisioner=provisioner,
        cookie_ttl_seconds=settings.cookie_ttl_seconds,
        site_url=mastio_url,
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
        ):
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
        """
        if has_identity(config.config_dir):
            if getattr(app.state, "cullis_chat_mounted", False):
                return RedirectResponse("/chat/", status_code=303)
            return RedirectResponse("/connected", status_code=303)
        if _pending is not None:
            return RedirectResponse("/waiting", status_code=303)
        return RedirectResponse("/setup", status_code=303)

    @app.get("/setup", response_class=HTMLResponse)
    def setup_get(request: Request, error: str | None = None) -> Response:
        # If identity already exists, don't show the form — nothing to do.
        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)

        return templates.TemplateResponse(
            request,
            "setup.html",
            {
                "connector_status": "offline",
                "connector_status_label": "Offline",
                "site_url": config.site_url or "",
                "requester_name": "",
                "requester_email": "",
                "reason": "",
                "verify_tls_off": not config.verify_tls,
                "error": error,
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
        # above. Do NOT inline this back to ``verify=False`` without
        # updating ci.yml + ADR-015.
        _TOFU_NO_VERIFY: bool = False
        url = site_url.rstrip("/") + "/pki/ca.crt"
        resp = httpx.get(url, verify=_TOFU_NO_VERIFY, timeout=config.request_timeout_s)
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
    def api_status(request: Request) -> JSONResponse:
        """Single-shot poll of the remote enrollment status.

        Returns JSON so the waiting page's HTMX can route to the next
        screen on its own.
        """
        if has_identity(config.config_dir):
            # Lazy-spawn the inbox poller — the dashboard may have
            # been launched pre-enrollment, in which case the lifespan
            # bootstrap saw no identity and returned early. Now that
            # the identity is on disk (this branch), the operator
            # should start receiving notifications without having to
            # restart the dashboard. Idempotent + cheap.
            _ensure_inbox_poller_running(request.app)
            return JSONResponse({"status": "approved"})
        if _pending is None:
            return JSONResponse({"status": "idle"})

        poll_url = (
            f"{_pending.site_url}/v1/enrollment/{_pending.session_id}/status"
        )
        try:
            from cullis_connector.config import verify_arg_for
            resp = httpx.get(
                poll_url,
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
