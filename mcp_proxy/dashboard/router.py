"""
MCP Proxy Dashboard — admin control plane for managing agents, tools, and policies.

Routes:
  /proxy/                — Smart entry point (redirects based on state)
  /proxy/login           — Sign in with the admin password
  /proxy/logout          — Clear session
  /proxy/register        — One-shot: set the admin password (first run only)
  /proxy/setup           — Broker uplink wizard (URL + invite token, org details, CA, Vault)
  /proxy/agents          — Internal agent management
  /proxy/network         — Network directory (discover remote agents via broker)
  /proxy/tools           — Tool registry viewer
  /proxy/policies        — Policy editor
  /proxy/audit           — Audit log viewer
  /proxy/pki             — PKI overview (Org CA info, agent cert stats)
  /proxy/vault           — Vault connection management
  /proxy/org-status      — HTMX org status polling
"""
import json
import logging
import pathlib

import httpx

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    get_session,
    clear_session,
    require_login,
    verify_csrf,
    is_admin_password_set,
    set_admin_password,
    verify_admin_password,
    MIN_PASSWORD_LENGTH,
)
from mcp_proxy.admin.approval_hook import (
    ACTION_AGENTS_DELETE,
    ACTION_LICENSE_IMPORT,
    maybe_intercept_for_approval,
)

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"

from mcp_proxy.dashboard._template_env import (  # noqa: E402
    _parse_device_info,
    build_templates,
)
# F-B-201 PR-1: pure helpers extracted to a sibling module so upcoming
# per-feature sub-routers can import them without dragging the
# 5000-LOC router.py. Mirrors the Court sibling _helpers.py (F-B-202).
from mcp_proxy.dashboard._helpers import (  # noqa: E402
    _ctx,
    _enforce_safe_outbound_url,
    _login_client_ip,
    _post_login_redirect,
)
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(prefix="/proxy", tags=["dashboard"])

# F-B-201 PR-2: include the auth sub-router (login / logout / register).
# Routes inside auth_routes.py declare paths relative to /proxy so the
# outer router's prefix is inherited via include_router. Mirrors the
# Court PR-2 pattern (#841).
from mcp_proxy.dashboard import auth_routes as _auth_routes  # noqa: E402
router.include_router(_auth_routes.router)

# F-B-201 PR-3: include the setup sub-router (broker uplink wizard).
from mcp_proxy.dashboard import setup_routes as _setup_routes  # noqa: E402
router.include_router(_setup_routes.router)

# F-B-201 PR-4: include the agents sub-router (list + per-agent management).
from mcp_proxy.dashboard import agents_routes as _agents_routes  # noqa: E402
router.include_router(_agents_routes.router)

# F-B-201 PR-5: include the tools + network sub-router.
from mcp_proxy.dashboard import tools_network_routes as _tools_network_routes  # noqa: E402
router.include_router(_tools_network_routes.router)

# F-B-201 PR-6: include the policies sub-router (rules + PDP + webhook probe).
from mcp_proxy.dashboard import policies_routes as _policies_routes  # noqa: E402
router.include_router(_policies_routes.router)

# F-B-201 PR-7: include the audit sub-router (admin + traffic stream viewer).
from mcp_proxy.dashboard import audit_routes as _audit_routes  # noqa: E402
router.include_router(_audit_routes.router)

# F-B-201 PR-8: include the pki sub-router (CA overview + export + rotate).
from mcp_proxy.dashboard import pki_routes as _pki_routes  # noqa: E402
router.include_router(_pki_routes.router)

# F-B-201 PR-9: include the vault + oidc sub-routers.
from mcp_proxy.dashboard import vault_routes as _vault_routes  # noqa: E402
router.include_router(_vault_routes.router)
from mcp_proxy.dashboard import oidc_routes as _oidc_routes  # noqa: E402
router.include_router(_oidc_routes.router)

# F-B-201 PR-10: include the mastio-key sub-router (rotation lifecycle).
from mcp_proxy.dashboard import mastio_key_routes as _mastio_key_routes  # noqa: E402
router.include_router(_mastio_key_routes.router)

# F-B-201 PR-11: include the users sub-router (multi-user admin lifecycle).
from mcp_proxy.dashboard import users_routes as _users_routes  # noqa: E402
router.include_router(_users_routes.router)

# F-B-201 PR-12: include the enrollments sub-router (admin review queue
# for pending Connector enrollment requests).
from mcp_proxy.dashboard import enrollments_routes as _enrollments_routes  # noqa: E402
router.include_router(_enrollments_routes.router)

# F-B-201 PR-12: include the badges sub-router (sidebar HTMX status
# indicators for agents / enrollments / users / approvals / audit /
# updates / version).
from mcp_proxy.dashboard import badges_routes as _badges_routes  # noqa: E402
router.include_router(_badges_routes.router)


# Helpers (_ctx, _enforce_safe_outbound_url, _login_client_ip,
# _post_login_redirect, _load_display_name, generate_org_ca,
# _test_vault_connectivity, _store_ca_key_in_vault) live in
# ``mcp_proxy/dashboard/_helpers.py`` since F-B-201 PR-1 / PR-2 / PR-3.


# generate_org_ca, _test_vault_connectivity, _store_ca_key_in_vault
# moved to ``mcp_proxy/dashboard/_helpers.py`` since F-B-201 PR-3.



# ─────────────────────────────────────────────────────────────────────────────
# Auth — admin password (bcrypt) + smart entry point
# ─────────────────────────────────────────────────────────────────────────────
#
# State machine:
#
#   no admin_password_hash      -> /proxy/register   (one-shot account creation)
#   hash set, no session        -> /proxy/login      (sign in)
#   hash set, session, no org   -> /proxy/setup      (broker uplink wizard)
#   hash set, session, org      -> /proxy/agents     (operational dashboard)
#
# Login and register are pre-session: no CSRF (no cookie to read the token from).
# Every other state-changing endpoint enforces CSRF via verify_csrf().


# _post_login_redirect moved to ``mcp_proxy/dashboard/_helpers.py``
# since F-B-201 PR-2.


@router.get("/", response_class=HTMLResponse)
async def proxy_root(request: Request):
    """Smart entry point — route based on registration + session + broker state."""
    if not await is_admin_password_set():
        return RedirectResponse(url="/proxy/register", status_code=303)

    session = get_session(request)
    if not session.logged_in:
        return RedirectResponse(url="/proxy/login", status_code=303)

    return RedirectResponse(url=await _post_login_redirect(), status_code=303)


# Login / logout / register routes moved to
# ``mcp_proxy/dashboard/auth_routes.py`` since F-B-201 PR-2.


# ─────────────────────────────────────────────────────────────────────────────
# Org Status Polling (HTMX)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/org-status")
async def org_status(request: Request):
    """HTMX endpoint: check org registration status with the broker."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.db import get_config, set_config

    org_id = await get_config("org_id")
    if not org_id:
        return HTMLResponse("")

    org_status_val = await get_config("org_status")

    # Already active — no banner needed
    if org_status_val == "active":
        return HTMLResponse("")

    # Not pending — nothing to poll
    if org_status_val != "pending":
        return HTMLResponse("")

    # Poll broker for status
    broker_url = await get_config("broker_url")
    org_secret = await get_config("org_secret")

    if not broker_url or not org_secret:
        return HTMLResponse(
            '<div class="px-4 py-2.5 bg-gray-500/10 border-b border-gray-700/50 text-xs text-gray-400">'
            'Cannot check organization status — broker not configured</div>'
        )

    try:
        from mcp_proxy.config import get_settings, broker_tls_verify
        async with httpx.AsyncClient(
            verify=broker_tls_verify(get_settings()), timeout=5.0,
        ) as http:
            resp = await http.get(
                f"{broker_url}/v1/registry/orgs/me",
                headers={"X-Org-Id": org_id, "X-Org-Secret": org_secret},
            )
            if resp.is_success:
                data = resp.json()
                status = data.get("status", "unknown")

                # Update cached status
                if status != org_status_val:
                    await set_config("org_status", status)

                if status == "pending":
                    return HTMLResponse(
                        '<div class="px-4 py-2.5 bg-amber-500/10 border-b border-amber-600/30 text-xs text-amber-400 flex items-center gap-2">'
                        '<svg class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/></svg>'
                        'Organization registration pending — waiting for broker admin approval'
                        '</div>'
                    )
                elif status == "active":
                    return HTMLResponse(
                        '<div id="org-active-banner" class="px-4 py-2.5 bg-emerald-500/10 border-b border-emerald-600/30 text-xs text-emerald-400 flex items-center gap-2">'
                        '<span class="w-2 h-2 rounded-full bg-emerald-500"></span>'
                        'Organization active — you can now create agents'
                        '</div>'
                        '<script>setTimeout(function(){var el=document.getElementById("org-active-banner");if(el)el.remove();},5000);</script>'
                    )
                elif status == "rejected":
                    return HTMLResponse(
                        '<div class="px-4 py-2.5 bg-red-500/10 border-b border-red-600/30 text-xs text-red-400 flex items-center gap-2">'
                        '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>'
                        'Organization registration was rejected by the broker admin'
                        '</div>'
                    )
            else:
                return HTMLResponse(
                    '<div class="px-4 py-2.5 bg-gray-500/10 border-b border-gray-700/50 text-xs text-gray-400">'
                    f'Cannot check status (HTTP {resp.status_code})</div>'
                )
    except Exception:
        return HTMLResponse(
            '<div class="px-4 py-2.5 bg-gray-500/10 border-b border-gray-700/50 text-xs text-gray-400">'
            'Cannot check organization status — broker unreachable</div>'
        )


# Setup wizard (/proxy/setup GET + POST + /proxy/setup/test-connection)
# moved to ``mcp_proxy/dashboard/setup_routes.py`` since F-B-201 PR-3.



# ─────────────────────────────────────────────────────────────────────────────
# Org settings — inline-edit display name (overview card)
# ─────────────────────────────────────────────────────────────────────────────

_DISPLAY_NAME_MAX_LEN = 255


async def _render_org_title_block(
    request: Request,
    session: ProxyDashboardSession,
    *,
    mode: str,
) -> HTMLResponse:
    from mcp_proxy.db import get_config

    org_id = await get_config("org_id") or ""
    display_name = await get_config("display_name") or ""
    return templates.TemplateResponse(
        "_org_title_block.html",
        _ctx(
            request, session,
            mode=mode,
            org_id=org_id,
            display_name=display_name,
        ),
    )


@router.get("/settings/org/display-name", response_class=HTMLResponse)
async def org_display_name_view(request: Request):
    """HTMX endpoint: return the static title partial (used by Cancel)."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return await _render_org_title_block(request, session, mode="view")


@router.get("/settings/org/display-name/edit", response_class=HTMLResponse)
async def org_display_name_edit(request: Request):
    """HTMX endpoint: swap the title partial into inline-edit mode."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return await _render_org_title_block(request, session, mode="edit")


@router.post("/settings/org/display-name", response_class=HTMLResponse)
async def org_display_name_update(request: Request):
    """Persist a new friendly display name for the org.

    The org_id is derived from the Org CA pubkey in standalone (ADR-006
    §2.2) and immutable here; only the human-facing label is editable.
    Empty input clears the label, falling back to the hex org_id in the
    UI.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import set_config, log_audit

    form = await request.form()
    raw = str(form.get("display_name", "")).strip()
    if len(raw) > _DISPLAY_NAME_MAX_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Display name must be at most {_DISPLAY_NAME_MAX_LEN} characters.",
        )

    await set_config("display_name", raw)
    await log_audit(
        agent_id="admin",
        action="org.display_name.update",
        status="success",
        detail=f"display_name={raw}" if raw else "display_name=<cleared>",
    )

    return await _render_org_title_block(request, session, mode="view")


# Agents surface (/proxy/agents + create + per-agent detail / env-download /
# reach / deactivate / delete) moved to ``mcp_proxy/dashboard/agents_routes.py``
# since F-B-201 PR-4.
#
# Private helper ``_refresh_org_status_from_broker`` moved with it (only
# consumer was the agents_page handler).


# Tools + Network (/proxy/tools + /proxy/network + /proxy/tools/reload)
# moved to ``mcp_proxy/dashboard/tools_network_routes.py`` since F-B-201 PR-5.
#
# Policies (/proxy/policies + /proxy/policies/save + /proxy/policies/test-webhook)
# moved to ``mcp_proxy/dashboard/policies_routes.py`` since F-B-201 PR-6.


# Audit (/proxy/audit) moved to ``mcp_proxy/dashboard/audit_routes.py`` since F-B-201 PR-7.


# PKI (/proxy/pki + /proxy/pki/export-ca + /proxy/pki/rotate-ca) moved to
# ``mcp_proxy/dashboard/pki_routes.py`` since F-B-201 PR-8.


# Mastio Key rotation (/proxy/mastio-key + /mastio-key/grace-days + /mastio-key/rotate +
# /mastio-key/complete-staged) moved to ``mcp_proxy/dashboard/mastio_key_routes.py``
# since F-B-201 PR-10.


# Vault (/proxy/vault + /proxy/vault/save + /proxy/vault/test +
# /proxy/vault/migrate-keys) moved to
# ``mcp_proxy/dashboard/vault_routes.py`` since F-B-201 PR-9.


# Connector enrollments (/proxy/enrollments + approve + reject) moved to
# ``mcp_proxy/dashboard/enrollments_routes.py`` since F-B-201 PR-12.


# HTMX badge fragments for agents / enrollments / users / approvals /
# audit / updates / version moved to
# ``mcp_proxy/dashboard/badges_routes.py`` since F-B-201 PR-13.


# Users management (/proxy/users + lifecycle endpoints) moved to ``mcp_proxy/dashboard/users_routes.py`` since F-B-201 PR-11.


@router.get("/api/update-status")
async def api_update_status(request: Request):
    """Render the update-available banner fragment (HTMX target).

    Polls GitHub releases lazily — first call after the 24h cache
    expiry pays the latency, subsequent calls within the window read
    from ``proxy_config``. Returns empty HTML when no update is
    available or the operator has dismissed the current latest.

    No-auth on the GET would leak the running Mastio version to any
    visitor; gate to logged-in sessions only. The banner is
    operator-only by design.
    """
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.dashboard.update_check import get_update_status

    try:
        status = await get_update_status()
    except Exception as exc:  # noqa: BLE001
        # Never blank the page on update-check failure — log and
        # render empty so the dashboard keeps working offline.
        _log.warning("api_update_status: failed: %s", exc)
        return HTMLResponse("")

    if not status.available:
        return HTMLResponse("")

    # Strip the ``mastio-v`` prefix so the tarball filename matches the
    # release-mastio.yml artifact naming (``cullis-mastio-bundle-X.Y.Z.tar.gz``).
    latest_tag = status.latest or ""
    latest_stripped = latest_tag.removeprefix("mastio-v") if latest_tag else ""
    return templates.TemplateResponse(
        "update_banner.html",
        {
            "request": request,
            "current": status.current,
            "latest": latest_tag,
            "latest_stripped": latest_stripped,
            "latest_url": status.latest_url or "",
            "csrf_token": session.csrf_token,
        },
    )


@router.post("/api/update-status/dismiss")
async def api_update_status_dismiss(request: Request):
    """Operator dismisses the banner for the current latest version.

    Pins the dismissed tag in ``proxy_config``; the banner stays
    hidden until a newer release shows up in a future poll. Audit
    row captures who dismissed and which version so the operator
    can find their own dismissal later (rare but useful).
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse("/proxy/overview?error=csrf", status_code=303)

    from mcp_proxy.dashboard.update_check import dismiss_current_latest
    from mcp_proxy.db import log_audit

    dismissed = await dismiss_current_latest()
    operator = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )
    if dismissed is not None:
        try:
            await log_audit(
                agent_id=operator,
                action="update_check.dismiss",
                status="success",
                details={"dismissed_tag": dismissed},
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "api_update_status_dismiss: audit append failed: %s", exc,
            )

    # Redirect back to the page the operator was on (Referer) or
    # overview as a safe default. Refresh causes the HTMX banner load
    # to re-fetch and see dismissed=true → empty fragment.
    referer = request.headers.get("referer", "/proxy/overview")
    # Defensive: only honor same-origin referers so a malicious link
    # can't bounce the operator off the dashboard.
    if not referer.startswith("/") and "/proxy/" not in referer:
        referer = "/proxy/overview"
    return RedirectResponse(referer, status_code=303)


# /badge/audit, /badge/updates and /badge/version moved to
# ``mcp_proxy/dashboard/badges_routes.py`` since F-B-201 PR-13.


# ─────────────────────────────────────────────────────────────────────────────
# Update advisory — banner + JSON polled by the dashboard frame.
# The container can't auto-replace itself (no docker.sock), so we
# advise + show the operator the exact ``./deploy.sh --upgrade <ver>``
# they should run on the host.
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/api/version-status")
async def api_version_status(request: Request):
    """JSON the banner polls every few minutes — surfaces a newer
    Mastio release on GHCR when one is out.

    Auth-gated to dashboard sessions: a leaked anonymous endpoint
    that hits the GitHub API on every request would be an easy
    rate-limit target. Logged-in admins are the only audience for
    this advisory anyway.
    """
    from fastapi.responses import JSONResponse
    session = get_session(request)
    if not session.logged_in:
        return JSONResponse({"update_available": False}, status_code=200)

    from dataclasses import asdict as _asdict
    from mcp_proxy.version_check import check_for_updates

    status = await check_for_updates()
    return JSONResponse(_asdict(status))


# ─────────────────────────────────────────────────────────────────────────────
# Overview (post-login landing)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/overview", response_class=HTMLResponse)
async def overview_page(request: Request):
    """Landing page after login: org name, broker uplink, federation status."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.config import get_settings as _get_settings
    from mcp_proxy.db import get_config, list_agents

    org_id = await get_config("org_id") or ""
    display_name = await get_config("display_name") or ""
    broker_url = await get_config("broker_url") or ""
    org_status = await get_config("org_status") or ""

    # ADR-006 §2.2 — show the deterministic org_id in standalone mode so
    # the admin can paste it into a broker attach-ca invite without
    # digging into the DB. In federated mode the uplink is already
    # bound, so the card is hidden to avoid UI noise.
    _settings = _get_settings()
    standalone_mode = bool(_settings.standalone) and not broker_url
    if standalone_mode and not org_id:
        # The derivation runs at lifespan time, but an operator who
        # boots with MCP_PROXY_ORG_ID set will have a non-derived value.
        # Fall back to settings.org_id so the card always renders.
        org_id = _settings.org_id

    # Federation subscriber live stats, if running
    fed_stats = getattr(request.app.state, "federation_subscriber_stats", None)
    fed_running = getattr(request.app.state, "federation_subscriber_task", None) is not None

    # Counts
    local_agents = await list_agents()
    local_count = len(local_agents)
    local_active_count = sum(1 for a in local_agents if a.get("is_active"))

    federated_count = 0
    federated_orgs = 0
    backend_total = 0
    backend_enabled = 0
    binding_total = 0
    binding_active = 0
    recent_backends: list[dict] = []
    try:
        from sqlalchemy import text as _text
        from mcp_proxy.db import get_db as _get_db
        async with _get_db() as conn:
            row = (await conn.execute(
                _text(
                    "SELECT COUNT(*) AS c, COUNT(DISTINCT org_id) AS o "
                    "FROM cached_federated_agents WHERE revoked = 0"
                )
            )).mappings().first()
            if row:
                federated_count = int(row["c"] or 0)
                federated_orgs = int(row["o"] or 0)

            # Backend totals (ADR-007 Phase 1 — table `local_mcp_resources`,
            # surfaced here as "backends" for the operator UI).
            brow = (await conn.execute(
                _text(
                    "SELECT COUNT(*) AS total, "
                    "SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled "
                    "FROM local_mcp_resources"
                )
            )).mappings().first()
            if brow:
                backend_total = int(brow["total"] or 0)
                backend_enabled = int(brow["enabled"] or 0)

            grow = (await conn.execute(
                _text(
                    "SELECT COUNT(*) AS total, "
                    "SUM(CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END) AS active "
                    "FROM local_agent_resource_bindings"
                )
            )).mappings().first()
            if grow:
                binding_total = int(grow["total"] or 0)
                binding_active = int(grow["active"] or 0)

            # Three newest backends for the overview panel.
            rrows = (await conn.execute(
                _text(
                    "SELECT name, endpoint_url, enabled, created_at "
                    "FROM local_mcp_resources "
                    "ORDER BY created_at DESC LIMIT 3"
                )
            )).mappings().all()
            recent_backends = [dict(r) for r in rrows]
    except Exception:
        # cache/backend tables may be missing on older schemas — the
        # overview still renders, just with zeros.
        pass

    # Three newest local agents for the overview panel.
    recent_agents = [
        {
            "agent_id": a.get("agent_id"),
            "display_name": a.get("display_name"),
            "is_active": a.get("is_active"),
            "created_at": a.get("created_at"),
        }
        for a in (local_agents or [])[:3]
    ]

    return templates.TemplateResponse("overview.html", _ctx(
        request, session,
        active="overview",
        org_id=org_id,
        display_name=display_name,
        broker_url=broker_url,
        org_status=org_status,
        local_count=local_count,
        local_active_count=local_active_count,
        federated_count=federated_count,
        federated_orgs=federated_orgs,
        fed_stats=fed_stats,
        fed_running=fed_running,
        standalone_mode=standalone_mode,
        backend_total=backend_total,
        backend_enabled=backend_enabled,
        binding_total=binding_total,
        binding_active=binding_active,
        recent_agents=recent_agents,
        recent_backends=recent_backends,
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Settings (OIDC config)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Display current OIDC config (issuer + client_id) with an edit form.

    The client_secret is NEVER rendered. We only show whether a value is set.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.config import get_settings
    from mcp_proxy.dashboard.oidc import is_oidc_configured, load_oidc_config
    from mcp_proxy.dashboard.session import is_local_password_login_enabled

    cfg = await load_oidc_config()
    return templates.TemplateResponse("settings.html", _ctx(
        request, session,
        active="settings",
        issuer_url=cfg["issuer_url"],
        client_id=cfg["client_id"],
        has_client_secret=bool(cfg["client_secret"]),
        local_password_enabled=await is_local_password_login_enabled(),
        oidc_configured=await is_oidc_configured(),
        force_local_password_env=get_settings().force_local_password,
        error=request.query_params.get("error"),
        success=request.query_params.get("ok"),
    ))


@router.post("/settings")
async def settings_submit(request: Request):
    """Persist OIDC settings. Empty client_secret leaves the stored value
    untouched so the admin can update other fields without resupplying it."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.dashboard.oidc import load_oidc_config, save_oidc_config
    from mcp_proxy.db import log_audit

    form = await request.form()
    issuer_url = str(form.get("oidc_issuer_url", "")).strip()
    client_id = str(form.get("oidc_client_id", "")).strip()
    client_secret_raw = str(form.get("oidc_client_secret", ""))

    errors: list[str] = []
    if issuer_url and not issuer_url.startswith(("http://", "https://")):
        errors.append("Issuer URL must start with http:// or https://")
    if issuer_url and not client_id:
        errors.append("Client ID is required when issuer URL is set.")

    if errors:
        from mcp_proxy.config import get_settings
        from mcp_proxy.dashboard.oidc import is_oidc_configured
        from mcp_proxy.dashboard.session import is_local_password_login_enabled
        cfg = await load_oidc_config()
        return templates.TemplateResponse("settings.html", _ctx(
            request, session,
            active="settings",
            issuer_url=issuer_url or cfg["issuer_url"],
            client_id=client_id or cfg["client_id"],
            has_client_secret=bool(cfg["client_secret"]),
            local_password_enabled=await is_local_password_login_enabled(),
            oidc_configured=await is_oidc_configured(),
            force_local_password_env=get_settings().force_local_password,
            error="; ".join(errors),
            success=None,
        ), status_code=400)

    # Only overwrite client_secret if the admin typed something. An empty
    # input means "keep current value" — otherwise an admin who only wants
    # to rename the client_id would silently lose the stored secret.
    secret_arg = client_secret_raw if client_secret_raw != "" else None
    await save_oidc_config(issuer_url, client_id, secret_arg)

    await log_audit(
        agent_id="admin",
        action="settings.oidc_update",
        status="success",
        detail=f"issuer={issuer_url or '(cleared)'}, client_id={client_id or '(cleared)'}",
    )

    from mcp_proxy.config import get_settings
    from mcp_proxy.dashboard.oidc import is_oidc_configured
    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    cfg = await load_oidc_config()
    return templates.TemplateResponse("settings.html", _ctx(
        request, session,
        active="settings",
        issuer_url=cfg["issuer_url"],
        client_id=cfg["client_id"],
        has_client_secret=bool(cfg["client_secret"]),
        local_password_enabled=await is_local_password_login_enabled(),
        oidc_configured=await is_oidc_configured(),
        force_local_password_env=get_settings().force_local_password,
        error=None,
        success="OIDC configuration saved.",
    ))


@router.post("/settings/local-password")
async def settings_local_password(request: Request):
    """Flip the local-password sign-in toggle from Settings.

    Single-click lockout guard: we refuse to disable the toggle when no
    OIDC provider is configured — without SSO or an env break-glass the
    admin would have no way back into the dashboard. Operators who
    really want a password-less deploy can set the env
    ``MCP_PROXY_FORCE_LOCAL_PASSWORD=1`` and re-enable later; the guard
    is here because the UI flip is the easy-to-misfire path.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.dashboard.oidc import is_oidc_configured
    from mcp_proxy.dashboard.session import set_local_password_login_enabled
    from mcp_proxy.db import log_audit

    form = await request.form()
    enabled = str(form.get("enabled", "")).strip() not in ("0", "false", "no", "off", "")

    if not enabled and not await is_oidc_configured():
        return HTMLResponse(
            "Refusing to disable password sign-in: no OIDC provider is "
            "configured on this proxy. Configure OIDC in Settings first, "
            "otherwise flipping this toggle would lock the admin out.",
            status_code=400,
        )

    await set_local_password_login_enabled(enabled)
    await log_audit(
        agent_id="admin",
        action="auth.password_login_toggle",
        status="success",
        detail=f"source=dashboard enabled={enabled}",
    )
    return HTMLResponse(
        f"Local password sign-in {'enabled' if enabled else 'disabled'}.",
        status_code=200,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Admin password rotation (issue #653)
#
# The Mastio admin password used to be rotate-only via ``python -m
# mcp_proxy.cli reset-password`` over docker exec, which every first-time
# operator hit as "I logged in with MCP_PROXY_INITIAL_ADMIN_PASSWORD and
# now there's no way to change it from the dashboard". This handler
# exposes the same helper (``set_admin_password``) via a small form on
# the Settings page.
#
# Auth: requires an existing dashboard session (the helper assumes the
# caller already authenticated). The CSRF token gates POSTs from the
# same browser session. Current-password re-check ensures a stolen
# cookie alone is not enough to rotate.
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/settings/admin-password/change")
async def settings_admin_password_change(request: Request):
    """Rotate the dashboard admin password from the Settings page."""
    from mcp_proxy.db import log_audit

    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    current = str(form.get("current_password", ""))
    new = str(form.get("new_password", ""))
    confirm = str(form.get("new_password_confirm", ""))

    if not current or not new or not confirm:
        return RedirectResponse(
            "/proxy/settings?error=All+three+password+fields+are+required",
            status_code=303,
        )

    if new != confirm:
        return RedirectResponse(
            "/proxy/settings?error=New+passwords+do+not+match",
            status_code=303,
        )

    # Generic 401 on bad current password — don't leak whether the value
    # was wrong vs the session was somehow detached from the persisted
    # admin row. Same pattern as the /proxy/login error handler.
    if not await verify_admin_password(current):
        _log.warning(
            "admin password change rejected: wrong current password "
            "(actor=%s)", getattr(session, "username", "?"),
        )
        return RedirectResponse(
            "/proxy/settings?error=Current+password+is+wrong",
            status_code=303,
        )

    try:
        await set_admin_password(new)
    except ValueError as exc:
        # set_admin_password enforces MIN_PASSWORD_LENGTH and possibly
        # other complexity rules; surface the constraint to the operator.
        from urllib.parse import quote
        return RedirectResponse(
            f"/proxy/settings?error={quote(str(exc))}",
            status_code=303,
        )

    actor = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "admin"
    )
    await log_audit(
        agent_id=actor,
        action="admin_password_rotated",
        status="success",
        detail=f"source=dashboard actor={actor}",
    )
    return RedirectResponse(
        "/proxy/settings?ok=Admin+password+rotated."
        "+Re-login+required+on+next+session.",
        status_code=303,
    )


# ─────────────────────────────────────────────────────────────────────────────
# License hot-swap (H3 P0.2)
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/settings/license")
async def settings_license_swap(request: Request):
    """Hot-swap the in-process license JWT without a restart.

    Closes the rotation gap for the first paid deal: customers on a
    paid tier need to rotate the license JWT every ~90 days without
    bouncing the bundle. Validates the candidate token against the
    baked / overridden public key; on success the cache is replaced
    atomically and the plugin registry is invalidated so the feature
    gate re-applies on the next call. On validation failure the cache
    stays unchanged and the operator gets a flash message.

    Optional 4-eyes gate: when the enterprise rbac_multi_admin plugin
    is loaded and policy-gated, the import is queued for a second
    admin signoff via ``ACTION_LICENSE_IMPORT``. Community deploys
    skip the gate entirely.
    """
    from urllib.parse import quote

    from mcp_proxy.db import log_audit
    from mcp_proxy.license import LicenseSwapError, swap_token

    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    candidate = str(form.get("license_jwt", "")).strip()
    if not candidate:
        return RedirectResponse(
            "/proxy/settings?error=Paste+the+license+JWT+before+submitting",
            status_code=303,
        )

    # 4-eyes gate. We forward the JWT prefix to the plugin payload so
    # the second signer can see WHICH license is being imported (the
    # 90gg rotation procedure ships out-of-band, so the prefix is
    # enough to cross-reference); we do NOT log the full JWT to the
    # payload because the plugin persists it for audit.
    jwt_prefix = candidate.split(".", 1)[0][:80]
    intercept = await maybe_intercept_for_approval(
        session=session,
        action_type=ACTION_LICENSE_IMPORT,
        payload={"license_jwt_prefix": jwt_prefix},
        request=request,
    )
    if intercept is not None:
        return intercept

    try:
        claims = swap_token(candidate)
    except LicenseSwapError as exc:
        # Audit the failed swap attempt so a paste-error / hostile JWT
        # is forensically visible. The candidate token itself is NOT
        # logged (it may be a valid JWT for the wrong tenant and we do
        # not want to leak it via grep).
        actor = (
            getattr(session, "principal_id", None)
            or getattr(session, "username", None)
            or "admin"
        )
        await log_audit(
            agent_id=actor,
            action="license_swap",
            status="error",
            detail=f"reason={exc} actor={actor}",
        )
        return RedirectResponse(
            f"/proxy/settings?error={quote(f'License swap rejected: {exc}')}",
            status_code=303,
        )

    actor = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "admin"
    )
    await log_audit(
        agent_id=actor,
        action="license_swap",
        status="success",
        detail=(
            f"tier={claims.tier} org={claims.org} "
            f"features={len(claims.features)} exp={claims.exp} actor={actor}"
        ),
    )
    return RedirectResponse(
        f"/proxy/settings?ok={quote('License updated. Tier: ' + claims.tier)}",
        status_code=303,
    )


# OIDC handshake (/proxy/oidc/start + /proxy/oidc/callback) moved to
# ``mcp_proxy/dashboard/oidc_routes.py`` since F-B-201 PR-9.
# OIDC primitives (state, JWKS, token exchange) still live in the
# sibling ``mcp_proxy/dashboard/oidc.py`` module.


# _load_display_name moved to ``mcp_proxy/dashboard/_helpers.py``
# since F-B-201 PR-2.


# ─────────────────────────────────────────────────────────────────────────────
# Federated-agents partial (accordion expansion) — REMOVED.
# The ``/proxy/agents`` accordion that consumed this partial was
# deleted in the reach-UX refactor (PR #224). Peer-org discovery
# now lives on ``/proxy/network``. The helper ``_federated_agents_rows``
# template was removed alongside.
# ─────────────────────────────────────────────────────────────────────────────
