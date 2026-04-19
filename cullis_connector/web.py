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
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cullis_connector.config import ConnectorConfig
from cullis_connector.enrollment import (
    EnrollmentFailed,
    RequesterInfo,
    _bcrypt_hash,
    _generate_api_key,
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
    api_key_raw: str
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
    """
    config = app.state.connector_config
    app.state.inbox_poller = None
    app.state.inbox_dispatcher = None
    if os.environ.get("CULLIS_CONNECTOR_NOTIFICATIONS", "on").lower() in ("0", "off", "false", "no"):
        _log.info("inbox poller disabled via CULLIS_CONNECTOR_NOTIFICATIONS")
        yield
        return

    poller = _start_inbox_poller(config)
    app.state.inbox_poller = poller
    dispatcher: InboxDispatcher | None = None
    if poller is not None:
        poller.start()
        dispatcher = InboxDispatcher(poller, build_notifier())
        dispatcher.start()
        app.state.inbox_dispatcher = dispatcher
    try:
        yield
    finally:
        if dispatcher is not None:
            await dispatcher.stop()
        if poller is not None:
            await poller.stop()


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

        # Mirror cli._cmd_serve: load the identity into the process-
        # global state so helpers like own_org_id() / canonical_recipient
        # can read the sender's org from the cert subject. Without this
        # the prime_sender_pubkey_cache helper sends a bare recipient
        # to /v1/egress/resolve and gets a 400 "internal id must be
        # 'org::agent'" — which then cascades into the JWT-required
        # fallback path in decrypt_oneshot and surfaces as
        # "Not authenticated — call login() first" every poll tick.
        from cullis_connector.state import get_state
        identity = load_identity(config.config_dir)
        state = get_state()
        state.agent_id = identity.metadata.agent_id
        state.extra["identity"] = identity

        client = CullisClient.from_connector(config.config_dir)
        key_path = config.config_dir / "identity" / "agent.key"
        if key_path.exists():
            client._signing_key_pem = key_path.read_text()
    except Exception as exc:  # noqa: BLE001
        _log.warning("inbox poller bootstrap failed: %s", exc)
        return None
    return DashboardInboxPoller(client, poll_interval_s=interval_s)


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
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ── Routes ────────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def root() -> Response:
        """Dispatch to the correct screen based on current state."""
        if has_identity(config.config_dir):
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
        api_key_raw = _generate_api_key()
        api_key_hash = _bcrypt_hash(api_key_raw)

        try:
            start_resp = _start(
                site_url=site_url,
                pubkey_pem=pubkey_pem,
                requester=requester,
                api_key_hash=api_key_hash,
                verify_tls=verify_tls,
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
            api_key_raw=api_key_raw,
            requester=requester,
            poll_interval_s=int(start_resp.get("poll_interval_s", 5)),
        )
        return RedirectResponse("/waiting", status_code=303)

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
                "started_at_ms": int(_pending.started_at * 1000),
            },
        )

    @app.get("/api/status")
    def api_status() -> JSONResponse:
        """Single-shot poll of the remote enrollment status.

        Returns JSON so the waiting page's HTMX can route to the next
        screen on its own.
        """
        if has_identity(config.config_dir):
            return JSONResponse({"status": "approved"})
        if _pending is None:
            return JSONResponse({"status": "idle"})

        poll_url = (
            f"{_pending.site_url}/v1/enrollment/{_pending.session_id}/status"
        )
        try:
            resp = httpx.get(
                poll_url,
                verify=_pending.verify_tls,
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
                api_key=_pending.api_key_raw,
            )
            _clear_pending()
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

    @app.post("/cancel")
    def cancel() -> Response:
        _clear_pending()
        return RedirectResponse("/setup", status_code=303)

    @app.get("/status/inbox")
    def status_inbox(request: Request) -> JSONResponse:
        """Statusline-friendly snapshot of the inbox state.

        Designed to be polled cheaply (every few seconds) by a Claude
        Code statusline command or any external script that wants
        to render a "📨 N from Mario" badge. Always returns 200 with
        a stable shape — when notifications are off or the dashboard
        hasn't seen any messages yet, ``unread`` is 0 and the rest
        is null.
        """
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
    def status_inbox_seen(request: Request) -> JSONResponse:
        """Reset the unread counter — call when the user has read the
        latest batch (the dashboard's `/inbox` view does it on load,
        statusline scripts can call it on click)."""
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
        result = ide_install_mcp(ide_id, backup_dir=backup_dir)

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
            base_url=base, verify=config.verify_tls, timeout=10.0,
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
