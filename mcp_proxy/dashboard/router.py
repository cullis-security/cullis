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
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    get_session,
    set_session,
    clear_session,
    require_login,
    verify_csrf,
    is_admin_password_set,
    set_admin_password,
    verify_admin_password,
    MIN_PASSWORD_LENGTH,
)

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


def _parse_device_info(raw):
    """Best-effort parse of ``internal_agents.device_info`` (migration 0013)
    — Connectors send a mix of conventions across versions, so we normalize
    a handful of aliases and fall back to ``None`` on anything malformed so
    the template short-circuits to a dash."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None

    def _pick(*keys):
        for k in keys:
            v = data.get(k)
            if v:
                return str(v)
        return None

    return {
        "os": _pick("os", "platform", "system"),
        "hostname": _pick("hostname", "host", "node"),
        "version": _pick("version", "connector_version", "client_version"),
    }


templates.env.filters["parse_device"] = _parse_device_info

router = APIRouter(prefix="/proxy", tags=["dashboard"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ctx(request: Request, session: ProxyDashboardSession, **kwargs) -> dict:
    """Build the standard template context."""
    return {
        "request": request,
        "session": session,
        "csrf_token": session.csrf_token,
        **kwargs,
    }


def generate_org_ca(org_id: str) -> tuple[str, str]:
    """Generate self-signed Org CA. Returns (cert_pem, key_pem).

    10-year validity: this is an offline-held root (NIST SP 800-57
    Part 1 §5.3.6 — root CAs held offline with long lifetimes).
    All online signing is done by the Mastio intermediate CA minted
    underneath this root; the intermediate rotates on a shorter cycle.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id} CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        # pathLen=1 because this Org CA signs a Mastio intermediate
        # (_mint_mastio_ca) which then signs agent leaves. RFC 5280
        # §4.2.1.9: pathLen=0 would forbid the intermediate and any
        # stdlib verifier (OpenSSL, Go crypto/x509, webpki, browser)
        # would reject the full chain at federation/mTLS time. See #280.
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


# Wave B G1 (audit 2026-05-11) — SSRF guard for the dashboard's three
# outbound-fetch test endpoints (test-connection / test-webhook /
# vault/test). Refuses loopback / RFC1918 / link-local / reserved IPs
# unless ``allow_private=True`` (the Vault case in docker-compose).
# Resolves the hostname so a public DNS that points at 127.0.0.1
# can't bypass the check via a CNAME.
def _enforce_safe_outbound_url(url: str, *, allow_private: bool = False) -> None:
    """Raise ValueError when ``url`` resolves to a forbidden target.

    The check parses the URL, resolves the hostname, and inspects every
    returned IP. ``allow_private=True`` skips the RFC1918/loopback ban
    for legitimate same-network targets (Vault, dev fixtures); the
    hostname-resolution + scheme check still fires."""
    import ipaddress
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Only http(s) URLs are allowed (got scheme {parsed.scheme!r})"
        )
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")
    if not allow_private and hostname in (
        "localhost", "127.0.0.1", "::1", "0.0.0.0",
    ):
        raise ValueError(f"URL points to loopback address: {hostname}")
    try:
        addrs = socket.getaddrinfo(
            hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname: {hostname}") from exc
    for _family, _type, _proto, _canonname, sockaddr in addrs:
        ip = ipaddress.ip_address(sockaddr[0])
        if not allow_private and (
            ip.is_private or ip.is_loopback
            or ip.is_link_local or ip.is_reserved
        ):
            raise ValueError(
                f"URL resolves to private/reserved IP: {ip}"
            )


async def _test_vault_connectivity(vault_addr: str, vault_token: str) -> tuple[bool, str]:
    """Test Vault connectivity. Returns (success, message)."""
    import httpx
    from mcp_proxy.config import get_settings, vault_tls_verify
    try:
        async with httpx.AsyncClient(
            verify=vault_tls_verify(get_settings()), timeout=5.0,
        ) as client:
            resp = await client.get(
                f"{vault_addr.rstrip('/')}/v1/sys/health",
                headers={"X-Vault-Token": vault_token},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("sealed"):
                    return False, "Vault is sealed"
                return True, "Connected"
            return False, f"HTTP {resp.status_code}"
    except Exception as exc:
        return False, f"Connection failed: {exc}"


async def _store_ca_key_in_vault(vault_addr: str, vault_token: str, org_id: str, key_pem: str) -> None:
    """Store Org CA private key in Vault."""
    import httpx
    from mcp_proxy.config import get_settings, vault_tls_verify
    path = f"secret/data/mcp-proxy/{org_id}/org-ca"
    url = f"{vault_addr.rstrip('/')}/v1/{path}"
    async with httpx.AsyncClient(
        verify=vault_tls_verify(get_settings()), timeout=5.0,
    ) as client:
        resp = await client.post(
            url,
            json={"data": {"key_pem": key_pem}},
            headers={"X-Vault-Token": vault_token},
        )
        resp.raise_for_status()


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


async def _post_login_redirect() -> str:
    """Where to send a freshly-authenticated admin.

    - No broker uplink yet     -> /proxy/setup (wizard)
    - Fully configured         -> /proxy/overview (landing)
    """
    from mcp_proxy.db import get_config
    org_id = await get_config("org_id")
    return "/proxy/overview" if org_id else "/proxy/setup"


@router.get("/", response_class=HTMLResponse)
async def proxy_root(request: Request):
    """Smart entry point — route based on registration + session + broker state."""
    if not await is_admin_password_set():
        return RedirectResponse(url="/proxy/register", status_code=303)

    session = get_session(request)
    if not session.logged_in:
        return RedirectResponse(url="/proxy/login", status_code=303)

    return RedirectResponse(url=await _post_login_redirect(), status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # Pristine proxy: send the user to set an admin password first.
    if not await is_admin_password_set():
        return RedirectResponse(url="/proxy/register", status_code=303)

    # Already authenticated? Skip the form.
    session = get_session(request)
    if session.logged_in:
        return RedirectResponse(url=await _post_login_redirect(), status_code=303)

    from mcp_proxy.dashboard.oidc import is_oidc_configured
    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    oidc_enabled = await is_oidc_configured()
    password_enabled = await is_local_password_login_enabled()
    display_name = await _load_display_name()

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
        "oidc_enabled": oidc_enabled,
        "password_enabled": password_enabled,
        "display_name": display_name,
    })


def _login_client_ip(request: Request) -> str:
    """Best-effort client IP for the login handler.

    Uses the immediate transport peer rather than ``X-Forwarded-For``:
    nginx in front of the Mastio handles trusted-proxy resolution and
    rewrites ``request.client`` accordingly, while in dev / direct
    deployments ``X-Forwarded-For`` is attacker-controlled and would
    let any client mint a fresh "IP" per request to dodge the lockout.
    """
    client = request.client
    return client.host if client is not None else "unknown"


@router.post("/login")
async def login_submit(request: Request):
    # State guard: if no password is set, you can't sign in — go register first.
    if not await is_admin_password_set():
        return RedirectResponse(url="/proxy/register", status_code=303)

    # SSO-only hardening toggle: refuse before touching bcrypt so a
    # timing side-channel can't probe the stored secret. The env
    # break-glass (``MCP_PROXY_FORCE_LOCAL_PASSWORD=1``) is honoured
    # inside ``is_local_password_login_enabled`` itself.
    from mcp_proxy.dashboard.session import is_local_password_login_enabled
    if not await is_local_password_login_enabled():
        from mcp_proxy.db import log_audit
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="denied",
            detail="password sign-in disabled",
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Password sign-in is disabled. Use the SSO button instead.",
            "password_enabled": False,
        }, status_code=403)

    # H9 audit fix — per-IP lockout + rate-limit before bcrypt.
    from mcp_proxy.auth.rate_limit import get_agent_rate_limiter
    from mcp_proxy.dashboard.login_lockout import (
        LOGIN_RATE_PER_MINUTE,
        get_login_lockout_store,
    )
    from mcp_proxy.db import log_audit

    client_ip = _login_client_ip(request)
    lockout_store = get_login_lockout_store()

    locked_until = await lockout_store.is_locked(client_ip)
    if locked_until is not None:
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="denied",
            detail=f"ip-locked-until {int(locked_until)} ip={client_ip}",
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": (
                "Too many failed attempts from this address. Try again later "
                "or reset the admin password from the local CLI."
            ),
        }, status_code=429)

    if not await get_agent_rate_limiter().check(
        f"ip:{client_ip}:dashboard.login", LOGIN_RATE_PER_MINUTE,
    ):
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="denied",
            detail=f"rate-limited ip={client_ip}",
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Too many login attempts. Slow down and try again in a minute.",
        }, status_code=429)

    form = await request.form()
    password = str(form.get("password", ""))

    if not password:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Password is required.",
        }, status_code=400)

    if not await verify_admin_password(password):
        # Audit the failure but keep the message vague (don't leak whether the
        # account exists, the username is wrong, etc.).
        fail_count, locked_until = await lockout_store.record_failure(client_ip)
        detail = f"invalid password ip={client_ip} consecutive_fails={fail_count}"
        if locked_until is not None:
            detail += f" locked-until={int(locked_until)}"
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="error",
            detail=detail,
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid password.",
        }, status_code=401)

    await lockout_store.record_success(client_ip)
    await log_audit(
        agent_id="admin",
        action="auth.login",
        status="success",
        detail=f"ip={client_ip}",
    )

    response = RedirectResponse(url=await _post_login_redirect(), status_code=303)
    set_session(response, role="admin")
    return response


@router.post("/logout")
async def logout(request: Request):
    session = get_session(request)
    # Audit F-B-9: raise on CSRF failure instead of calling
    # ``verify_csrf`` purely for side effects. Previously a cross-site
    # POST without the form token logged the victim out anyway — a
    # force-logout via any attacker-controlled page the victim loaded
    # while holding a valid Mastio admin session. Enforce on any
    # non-empty ``csrf_token`` (valid cookie) and keep the bare
    # no-cookie path idempotent with a friendly 303.
    if session.csrf_token and not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    response = RedirectResponse(url="/proxy/login", status_code=303)
    clear_session(response)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Register — one-shot admin password creation
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    # Already registered? Send them to login.
    if await is_admin_password_set():
        return RedirectResponse(url="/proxy/login", status_code=303)

    return templates.TemplateResponse("register.html", {
        "request": request,
        "error": None,
        "min_length": MIN_PASSWORD_LENGTH,
    })


@router.post("/register")
async def register_submit(request: Request):
    # Cannot re-register: someone already set the password.
    if await is_admin_password_set():
        return RedirectResponse(url="/proxy/login", status_code=303)

    form = await request.form()
    password = str(form.get("password", ""))
    confirm = str(form.get("confirm_password", ""))

    if not password or not confirm:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Both fields are required.",
            "min_length": MIN_PASSWORD_LENGTH,
        }, status_code=400)

    if len(password) < MIN_PASSWORD_LENGTH:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.",
            "min_length": MIN_PASSWORD_LENGTH,
        }, status_code=400)

    if password != confirm:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "The two passwords do not match.",
            "min_length": MIN_PASSWORD_LENGTH,
        }, status_code=400)

    try:
        await set_admin_password(password)
    except ValueError as exc:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": str(exc),
            "min_length": MIN_PASSWORD_LENGTH,
        }, status_code=400)

    from mcp_proxy.db import log_audit
    await log_audit(
        agent_id="admin",
        action="auth.register",
        status="success",
        details={
            "event": "admin_password_registered",
            "client_ip": _login_client_ip(request),
            "user_agent": (request.headers.get("user-agent") or "")[:200],
        },
    )

    # Force a clean sign-in for the very first session.
    return RedirectResponse(url="/proxy/login", status_code=303)


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


# ─────────────────────────────────────────────────────────────────────────────
# Setup Wizard
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.config import get_settings as _get_settings
    from mcp_proxy.db import get_config

    _settings = _get_settings()
    broker_url    = await get_config("broker_url") or ""
    invite_token  = await get_config("invite_token") or ""
    # ADR-006 §2.2 — derive org_id from the in-memory CA when available,
    # fall back to proxy_config for legacy / pre-derive boots. The form
    # never accepts org_id as input in standalone (PR-E1 closes #326).
    agent_mgr = getattr(request.app.state, "agent_manager", None)
    derived_org_id = None
    if agent_mgr is not None and getattr(agent_mgr, "ca_loaded", False):
        derived_org_id = agent_mgr.derive_org_id_from_ca()
    org_id        = derived_org_id or (await get_config("org_id") or "")
    display_name  = await get_config("display_name") or ""
    contact_email = await get_config("contact_email") or ""
    webhook_url   = await get_config("webhook_url") or ""
    has_ca        = bool(await get_config("org_ca_cert"))
    vault_addr    = await get_config("vault_addr") or ""
    vault_enabled = bool(vault_addr)

    return templates.TemplateResponse("setup.html", _ctx(
        request, session,
        active="setup",
        # ADR-014 PR-D — standalone is the default; wizard can hide the
        # broker section when this is true. PR-E2 will remove the
        # broker fields from the template entirely; until then the
        # template just shows them and the handler ignores them.
        standalone=_settings.standalone,
        broker_url=broker_url,
        invite_token=invite_token,
        org_id=org_id,
        derived_org_id=derived_org_id,
        display_name=display_name,
        contact_email=contact_email,
        webhook_url=webhook_url,
        has_ca=has_ca,
        vault_addr=vault_addr,
        vault_enabled=vault_enabled,
    ))


@router.post("/setup")
async def setup_submit(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    import re as _re
    import secrets as _secrets

    from mcp_proxy.config import get_settings as _get_settings
    from mcp_proxy.db import set_config, get_config, log_audit

    _settings = _get_settings()

    form = await request.form()
    broker_url    = str(form.get("broker_url", "")).strip().rstrip("/")
    invite_token  = str(form.get("invite_token", "")).strip()
    org_id        = str(form.get("org_id", "")).strip().lower()
    display_name  = str(form.get("display_name", "")).strip()
    contact_email = str(form.get("contact_email", "")).strip()
    webhook_url   = str(form.get("webhook_url", "")).strip()
    org_ca_mode   = str(form.get("org_ca_mode", "skip")).strip()
    ca_key_pem    = str(form.get("ca_key_pem", "")).strip()
    ca_cert_pem   = str(form.get("ca_cert_pem", "")).strip()
    vault_enabled = bool(form.get("vault_enabled"))
    vault_addr    = str(form.get("vault_addr", "")).strip()
    vault_token   = str(form.get("vault_token", "")).strip()

    # ── ADR-014 PR-E1 — standalone short-circuit (closes #326) ─────────────
    # When the Mastio runs in standalone mode (default after PR-D), the
    # wizard is configuring an org that owns its identity outright:
    #   - org_id is derived from the Org CA pubkey (ADR-006 §2.2), NEVER
    #     accepted as form input — derive it from the in-memory CA and
    #     ignore whatever the form said. This is the fix for #326: the
    #     previous handler called set_config("org_id", form_value) and
    #     overwrote the derived value (often with empty string), leaving
    #     ``/v1/egress/resolve`` with bare ``::agent-X`` recipients that
    #     parse_internal() rejects.
    #   - broker_url + invite_token are not collected; the federation flow
    #     ("allaccio al Court") is post-setup, opt-in via /proxy/federation
    #     (PR-E2). Skip the broker validation + /v1/onboarding/* call.
    if _settings.standalone:
        agent_mgr = getattr(request.app.state, "agent_manager", None)
        derived: str | None = None
        if agent_mgr is not None and getattr(agent_mgr, "ca_loaded", False):
            derived = agent_mgr.derive_org_id_from_ca()
        if not derived:
            derived = (await get_config("org_id")) or ""
        # Always override the form-supplied value. The derived value is
        # the only one that satisfies the cert-chain invariants — any
        # other value silently breaks resolve.
        if derived:
            org_id = derived
        return await _setup_submit_standalone(
            request, session,
            org_id=org_id,
            display_name=display_name,
            contact_email=contact_email,
            webhook_url=webhook_url,
            org_ca_mode=org_ca_mode,
            ca_key_pem=ca_key_pem,
            ca_cert_pem=ca_cert_pem,
            vault_enabled=vault_enabled,
            vault_addr=vault_addr,
            vault_token=vault_token,
        )

    # If no webhook URL provided, fall back to env or auto-construct
    # this proxy's built-in PDP endpoint.
    if not webhook_url:
        import os as _os
        from mcp_proxy.config import get_settings as _get_settings
        webhook_url = _os.environ.get("MCP_PROXY_PDP_URL", "")
        if not webhook_url:
            webhook_url = await get_config("pdp_webhook_url") or ""
        if not webhook_url:
            proxy_public = _get_settings().proxy_public_url
            if proxy_public:
                webhook_url = f"{proxy_public.rstrip('/')}/pdp/policy"

    # ── Inspect the invite to decide flow (join vs attach-ca) ──────────────
    # For attach-ca invites, org_id comes from the token (linked_org_id) and
    # the org-level fields (display_name, contact_email, webhook_url) were
    # already set by the broker admin when the org was created.
    invite_type = "org-join"
    linked_org_id: str | None = None
    inspect_err: str | None = None
    if broker_url and invite_token:
        try:
            from mcp_proxy.config import broker_tls_verify
            async with httpx.AsyncClient(
                verify=broker_tls_verify(_get_settings()), timeout=10.0,
            ) as http:
                r = await http.post(
                    f"{broker_url}/v1/onboarding/invite/inspect",
                    json={"invite_token": invite_token},
                )
            if r.status_code == 200:
                data = r.json()
                invite_type = data.get("invite_type") or "org-join"
                linked_org_id = data.get("org_id")
            elif r.status_code == 404:
                inspect_err = ("Invite token is invalid, revoked, expired, or already used. "
                               "Ask the broker admin for a fresh one.")
            # Other statuses: fall back to org-join behaviour, the /join call
            # will surface the real error.
        except Exception as exc:
            _log.warning("Invite inspect failed, falling back to join flow: %s", exc)

    errors: list[str] = []
    if inspect_err:
        errors.append(inspect_err)
    if not broker_url:
        errors.append("Broker URL is required.")
    if not invite_token:
        errors.append("Invite token is required (paste the one from the broker admin).")

    if invite_type == "attach-ca":
        # org_id is authoritative from the invite; override any form input
        # so a malicious/confused form submission cannot target a different org.
        if not linked_org_id:
            errors.append("attach-ca invite missing bound org_id — broker bug.")
        else:
            org_id = linked_org_id
        # display_name / contact_email / webhook_url are not sent in attach flow
    else:
        if not org_id:
            errors.append("Organization ID is required.")
        elif not _re.match(r"^[a-z][a-z0-9_-]*$", org_id):
            errors.append("Org ID must start with a letter and contain only lowercase letters, digits, hyphens, underscores.")
        if not display_name:
            errors.append("Display name is required.")
        if not contact_email:
            errors.append("Contact email is required.")

    # Validate CA import PEMs
    if org_ca_mode == "import":
        if not ca_key_pem or not ca_cert_pem:
            errors.append("Both CA certificate and CA private key PEM are required for import.")
        else:
            try:
                serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
            except Exception:
                errors.append("CA private key is not valid PEM.")
            try:
                x509.load_pem_x509_certificate(ca_cert_pem.encode())
            except Exception:
                errors.append("CA certificate is not valid PEM.")

    # The proxy needs a CA to sign agent certs. The broker also requires
    # a CA in the join request. So 'skip' is only acceptable if a CA was
    # already configured on a previous run.
    if org_ca_mode == "skip" and not await get_config("org_ca_cert"):
        errors.append("This proxy has no CA yet — choose 'Generate new' or 'Import existing'.")

    # Validate Vault config
    if vault_enabled:
        if not vault_addr:
            errors.append("Vault address is required when Vault is enabled.")
        if not vault_token:
            errors.append("Vault token is required when Vault is enabled.")

    if errors:
        has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("setup.html", _ctx(
            request, session,
            active="setup",
            broker_url=broker_url,
            invite_token=invite_token,
            org_id=org_id,
            display_name=display_name,
            contact_email=contact_email,
            webhook_url=webhook_url,
            has_ca=has_ca,
            vault_addr=vault_addr,
            vault_enabled=vault_enabled,
            errors=errors,
        ))

    # Save broker + org config
    await set_config("broker_url", broker_url)
    await set_config("invite_token", invite_token)
    await set_config("org_id", org_id)
    await set_config("display_name", display_name)
    await set_config("contact_email", contact_email)
    await set_config("webhook_url", webhook_url)

    # Auto-generate the org secret if we don't already have one. The admin
    # never has to choose it — it is opaque material used by the proxy to
    # authenticate to the broker on behalf of the organization.
    org_secret = await get_config("org_secret")
    if not org_secret:
        org_secret = _secrets.token_urlsafe(32)
        await set_config("org_secret", org_secret)

    # Handle Org CA
    ca_generated = False
    if org_ca_mode == "generate":
        cert_pem, key_pem = generate_org_ca(org_id)
        await set_config("org_ca_cert", cert_pem)
        await set_config("org_ca_key", key_pem)
        ca_generated = True
        await log_audit(
            agent_id="admin",
            action="ca.generate",
            status="success",
            detail=f"org_id={org_id}, self-signed RSA-4096, valid 10 years",
        )
    elif org_ca_mode == "import":
        await set_config("org_ca_cert", ca_cert_pem)
        await set_config("org_ca_key", ca_key_pem)
        await log_audit(
            agent_id="admin",
            action="ca.import",
            status="success",
            detail=f"org_id={org_id}",
        )

    # Handle Vault
    if vault_enabled and vault_addr and vault_token:
        ok, msg = await _test_vault_connectivity(vault_addr, vault_token)
        if ok:
            await set_config("vault_addr", vault_addr)
            await set_config("vault_token", vault_token)
            await log_audit(
                agent_id="admin",
                action="vault.configure",
                status="success",
                detail=f"addr={vault_addr}",
            )
            # Store CA key in Vault if CA was just generated
            if ca_generated:
                try:
                    ca_key = await get_config("org_ca_key")
                    if ca_key:
                        await _store_ca_key_in_vault(vault_addr, vault_token, org_id, ca_key)
                        await log_audit(
                            agent_id="admin",
                            action="vault.store_ca_key",
                            status="success",
                            detail=f"org_id={org_id}",
                        )
                except Exception as exc:
                    _log.warning("Failed to store CA key in Vault: %s", exc)
        else:
            _log.warning("Vault connectivity test failed during setup: %s", msg)
    elif not vault_enabled:
        # Clear vault config if disabled
        await set_config("vault_addr", "")
        await set_config("vault_token", "")

    await log_audit(
        agent_id="admin",
        action="setup.local_save",
        status="success",
        detail=f"broker_url={broker_url}, org_id={org_id}, ca_mode={org_ca_mode}, vault={'yes' if vault_enabled else 'no'}",
    )

    # ── Register the org on the broker ──────────────────────────────────────
    # This is the actual point of no return: it consumes the invite token on
    # the broker side and creates a pending Organization record there. If the
    # broker rejects, the local config is still good (so the admin can fix
    # invite_token / broker_url and retry without losing CA / Vault settings).
    org_ca_cert_pem = await get_config("org_ca_cert") or ""
    if not org_ca_cert_pem:
        # Should not happen — the validator above blocks this — but be defensive.
        return _setup_error_response(
            request, session,
            "Cannot register on broker: no CA certificate available.",
            broker_url, invite_token, org_id, display_name, contact_email, webhook_url,
            vault_addr, vault_enabled,
        )

    error_msg: str | None = None
    try:
        from mcp_proxy.config import get_settings as _s, broker_tls_verify
        async with httpx.AsyncClient(
            verify=broker_tls_verify(_s()), timeout=10.0,
        ) as http:
            if invite_type == "attach-ca":
                # Existing org on broker (pre-registered by admin), we just
                # attach the CA and claim the org by rotating its secret.
                resp = await http.post(f"{broker_url}/v1/onboarding/attach", json={
                    "ca_certificate": org_ca_cert_pem,
                    "invite_token": invite_token,
                    "secret": org_secret,
                })
                success_statuses = (200,)
            else:
                resp = await http.post(f"{broker_url}/v1/onboarding/join", json={
                    "org_id": org_id,
                    "display_name": display_name,
                    "secret": org_secret,
                    "ca_certificate": org_ca_cert_pem,
                    "contact_email": contact_email,
                    "webhook_url": webhook_url,
                    "invite_token": invite_token,
                })
                success_statuses = (200, 202)

            if resp.status_code in success_statuses:
                # attach returns 200 with status field; join returns 202 with "pending".
                try:
                    body_json = resp.json()
                    final_status = body_json.get("status") or ("active" if resp.status_code == 200 else "pending")
                except Exception:
                    final_status = "active" if resp.status_code == 200 else "pending"
                await set_config("org_status", final_status)
                await log_audit(
                    agent_id="admin",
                    action="org.register",
                    status="success",
                    detail=(f"org_id={org_id}, broker={broker_url}, status={final_status}, "
                            f"flow={invite_type}"),
                )
                return RedirectResponse(url="/proxy/agents", status_code=303)
            elif resp.status_code == 403:
                error_msg = "Invalid or expired invite token. Ask the broker admin for a fresh one."
            elif resp.status_code == 409:
                if invite_type == "attach-ca":
                    error_msg = "This organization already has a CA on the broker — nothing to attach."
                else:
                    error_msg = "An organization with this ID is already registered on the broker."
            elif resp.status_code == 404:
                error_msg = "Target organization no longer exists on the broker."
            else:
                error_msg = f"Broker rejected the registration (HTTP {resp.status_code}): {resp.text[:200]}"
    except Exception as exc:
        error_msg = f"Cannot reach broker: {exc}"

    await log_audit(
        agent_id="admin",
        action="org.register",
        status="error",
        detail=f"org_id={org_id}, error={error_msg}",
    )

    return _setup_error_response(
        request, session, error_msg,
        broker_url, invite_token, org_id, display_name, contact_email, webhook_url,
        vault_addr, vault_enabled,
    )


def _setup_error_response(
    request: Request,
    session: ProxyDashboardSession,
    error_msg: str,
    broker_url: str,
    invite_token: str,
    org_id: str,
    display_name: str,
    contact_email: str,
    webhook_url: str,
    vault_addr: str,
    vault_enabled: bool,
):
    """Re-render setup.html with an error and the previously-typed values."""
    return templates.TemplateResponse("setup.html", _ctx(
        request, session,
        active="setup",
        broker_url=broker_url,
        invite_token=invite_token,
        org_id=org_id,
        display_name=display_name,
        contact_email=contact_email,
        webhook_url=webhook_url,
        has_ca=True,  # we only get here after CA setup succeeded
        vault_addr=vault_addr,
        vault_enabled=vault_enabled,
        errors=[error_msg],
    ))


async def _setup_submit_standalone(
    request: Request,
    session: ProxyDashboardSession,
    *,
    org_id: str,
    display_name: str,
    contact_email: str,
    webhook_url: str,
    org_ca_mode: str,
    ca_key_pem: str,
    ca_cert_pem: str,
    vault_enabled: bool,
    vault_addr: str,
    vault_token: str,
):
    """ADR-014 PR-E1 — wizard handler for the standalone case (closes #326).

    The standalone Mastio owns its identity outright:
      - ``org_id`` is the value derived by the caller from the in-memory
        CA (or read from proxy_config when the in-memory CA isn't loaded).
        We do not accept the form-supplied value.
      - The federation flow (broker_url + invite_token + /onboarding) is
        out of scope here. PR-E2 will move the corresponding controls
        out of the wizard entirely; until then we just skip them.

    Failure modes that still show in the form:
      - missing display_name / contact_email
      - CA import requested but PEMs missing or unparseable
      - Vault enabled but addr/token missing or unreachable
    """
    from mcp_proxy.db import set_config, get_config, log_audit

    errors: list[str] = []

    if not org_id:
        # Should be impossible in standalone after first-boot — flag
        # loudly so the operator knows the boot path didn't run.
        errors.append(
            "Cannot derive org_id — the Mastio's Org CA isn't loaded yet. "
            "Restart the container; first-boot derivation should populate it."
        )
    if not display_name:
        errors.append("Display name is required.")
    if not contact_email:
        errors.append("Contact email is required.")

    if org_ca_mode == "import":
        if not ca_key_pem or not ca_cert_pem:
            errors.append("Both CA certificate and CA private key PEM are required for import.")
        else:
            try:
                serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
            except Exception:
                errors.append("CA private key is not valid PEM.")
            try:
                x509.load_pem_x509_certificate(ca_cert_pem.encode())
            except Exception:
                errors.append("CA certificate is not valid PEM.")

    if org_ca_mode == "skip" and not await get_config("org_ca_cert"):
        errors.append("This proxy has no CA yet — choose 'Generate new' or 'Import existing'.")

    if vault_enabled:
        if not vault_addr:
            errors.append("Vault address is required when Vault is enabled.")
        if not vault_token:
            errors.append("Vault token is required when Vault is enabled.")

    if errors:
        has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("setup.html", _ctx(
            request, session,
            active="setup",
            broker_url="",
            invite_token="",
            org_id=org_id,
            display_name=display_name,
            contact_email=contact_email,
            webhook_url=webhook_url,
            has_ca=has_ca,
            vault_addr=vault_addr,
            vault_enabled=vault_enabled,
            errors=errors,
        ))

    # Persist org-level config. Note: org_id is the derived value; we
    # pass through ``set_config`` to keep proxy_config consistent (the
    # in-memory derive is authoritative either way).
    if org_id:
        await set_config("org_id", org_id)
    await set_config("display_name", display_name)
    await set_config("contact_email", contact_email)
    if webhook_url:
        await set_config("webhook_url", webhook_url)

    # CA: regenerate / import. The standalone Mastio normally has a CA
    # already (auto-generated at first boot per ADR-006 §2.2); the
    # ``import`` branch lets an operator BYOCA on top of that.
    if org_ca_mode == "generate":
        # ``generate_org_ca`` from the dashboard helpers wraps the same
        # primitive the lifespan uses. We avoid touching it when the
        # in-memory derivation already produced one — regenerate would
        # change org_id and orphan every existing agent cert.
        cert_pem, key_pem = generate_org_ca(org_id)
        await set_config("org_ca_cert", cert_pem)
        await set_config("org_ca_key", key_pem)
        await log_audit(
            agent_id="admin",
            action="ca.generate",
            status="success",
            detail=f"org_id={org_id}, standalone wizard, RSA-4096, 10y",
        )
    elif org_ca_mode == "import":
        await set_config("org_ca_cert", ca_cert_pem)
        await set_config("org_ca_key", ca_key_pem)
        await log_audit(
            agent_id="admin",
            action="ca.import",
            status="success",
            detail=f"org_id={org_id}, standalone wizard",
        )

    if vault_enabled and vault_addr and vault_token:
        ok, msg = await _test_vault_connectivity(vault_addr, vault_token)
        if ok:
            await set_config("vault_addr", vault_addr)
            await set_config("vault_token", vault_token)
            await log_audit(
                agent_id="admin",
                action="vault.configure",
                status="success",
                detail=f"addr={vault_addr}",
            )
        else:
            _log.warning("Vault connectivity test failed: %s", msg)
    elif not vault_enabled:
        await set_config("vault_addr", "")
        await set_config("vault_token", "")

    # Standalone Mastio is "active" the moment it has a CA + identity.
    # No broker handshake to wait on.
    await set_config("org_status", "active")
    await log_audit(
        agent_id="admin",
        action="setup.standalone_save",
        status="success",
        detail=f"org_id={org_id}, ca_mode={org_ca_mode}, vault={'yes' if vault_enabled else 'no'}",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)


@router.post("/setup/test-connection")
async def setup_test_connection(request: Request):
    """HTMX endpoint: test broker connectivity."""
    import html as _html
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return HTMLResponse('<span class="text-red-400">Not authenticated</span>')

    # Wave B G1 (audit 2026-05-11) — verify CSRF on this state-affecting
    # outbound-fetch endpoint, refuse RFC1918 / loopback / link-local
    # targets, and HTML-escape any exception text we render. Pre-fix
    # the handler did none of the three: any cross-site page that the
    # admin visited could trigger arbitrary outbound HTTP from the
    # Mastio host; ``Connection failed: {exc}`` echoed httpx error
    # text containing the URL into innerHTML which reflected XSS.
    if not await verify_csrf(request, session):
        return HTMLResponse(
            '<span class="text-red-400">CSRF check failed</span>'
        )

    form = await request.form()
    broker_url = str(form.get("broker_url", "")).strip()

    if not broker_url:
        return HTMLResponse(
            '<span class="text-red-400">Enter a broker URL first</span>'
        )

    try:
        _enforce_safe_outbound_url(broker_url)
    except ValueError as exc:
        return HTMLResponse(
            f'<span class="text-red-400">{_html.escape(str(exc))}</span>'
        )

    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{broker_url.rstrip('/')}/.well-known/jwks.json")
            if resp.status_code == 200:
                return HTMLResponse(
                    '<span class="text-emerald-400 flex items-center gap-1.5">'
                    '<span class="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>'
                    'Connected — JWKS fetched</span>'
                )
            return HTMLResponse(
                f'<span class="text-yellow-400">HTTP {resp.status_code}</span>'
            )
    except Exception as exc:
        return HTMLResponse(
            f'<span class="text-red-400">Connection failed: '
            f'{_html.escape(str(exc))}</span>'
        )


# ─────────────────────────────────────────────────────────────────────────────
# Agents
# ─────────────────────────────────────────────────────────────────────────────

async def _refresh_org_status_from_broker() -> str:
    """Synchronously ask the broker for the current org status and update
    the cached value in proxy_config.

    The cached value can drift behind reality in two situations:
      1. The broker admin approves the org while the proxy was not polling
         (no dashboard tab open).
      2. The bootstrap script (setup_proxy_org.py) writes status='pending'
         and never updates it after the broker admin approves.

    Returns the latest known status string ('pending', 'active', 'rejected',
    or '' if unknown / not configured). On any error, returns the cached
    value unchanged so the page render still works offline.
    """
    from mcp_proxy.db import get_config, set_config

    cached = await get_config("org_status") or ""

    org_id = await get_config("org_id")
    broker_url = await get_config("broker_url")
    org_secret = await get_config("org_secret")
    if not org_id or not broker_url or not org_secret:
        return cached

    try:
        from mcp_proxy.config import get_settings as _s, broker_tls_verify
        async with httpx.AsyncClient(
            verify=broker_tls_verify(_s()), timeout=3.0,
        ) as http:
            resp = await http.get(
                f"{broker_url}/v1/registry/orgs/me",
                headers={"X-Org-Id": org_id, "X-Org-Secret": org_secret},
            )
            if resp.is_success:
                fresh = (resp.json() or {}).get("status", "")
                if fresh and fresh != cached:
                    await set_config("org_status", fresh)
                return fresh or cached
    except Exception as exc:
        _log.debug("org_status refresh failed: %s", exc)

    return cached


@router.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import list_agents, get_config
    # Refresh the cached broker status BEFORE rendering, so the static
    # 'Approval Pending' banner in the template is never lying about a
    # state that the broker has already moved past.
    org_status = await _refresh_org_status_from_broker()
    agents = await list_agents()
    has_ca = bool(await get_config("org_ca_cert"))

    # Split by reach so the template can render two sections:
    # Federated (reach in {'cross','both'}) on top, Local (reach ==
    # 'intra') below. Peer-org agents live on /proxy/network now —
    # this page is exclusively "my agents".
    federated_agents = [a for a in agents if a.get("reach", "both") != "intra"]
    local_agents = [a for a in agents if a.get("reach", "both") == "intra"]

    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        federated_agents=federated_agents,
        local_agents=local_agents,
        org_status=org_status,
        has_ca=has_ca,
        new_agent_id=None,
    ))




@router.post("/agents/create")
async def agents_create(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import list_agents, log_audit, get_config
    from mcp_proxy.egress.agent_manager import AgentManager
    from mcp_proxy.config import get_settings

    form = await request.form()
    agent_name = str(form.get("agent_name", "")).strip().lower().replace(" ", "_")
    display_name = str(form.get("display_name", "")).strip()
    capabilities_raw = str(form.get("capabilities", "")).strip()

    if not agent_name or not display_name:
        agents = await list_agents()
        _org_status = await get_config("org_status") or ""
        _has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("agents.html", _ctx(
            request, session,
            active="agents",
            agents=agents,
            org_status=_org_status,
            has_ca=_has_ca,
            error="Agent name and display name are required.",
            new_agent_id=None,
        ))

    capabilities = [c.strip() for c in capabilities_raw.split(",") if c.strip()]

    # Determine org_id from config or settings
    org_id = await get_config("org_id") or get_settings().org_id

    # ADR-014 PR-C — agent creation requires a loaded Org CA so the
    # Mastio can mint the agent's TLS client cert (the credential).
    try:
        mgr = AgentManager(org_id=org_id)
        ca_loaded = await mgr.load_org_ca_from_config()

        if not ca_loaded:
            agents = await list_agents()
            _org_status = await get_config("org_status") or ""
            return templates.TemplateResponse("agents.html", _ctx(
                request, session,
                active="agents",
                agents=agents,
                org_status=_org_status,
                has_ca=False,
                error=(
                    "Org CA is not loaded — complete broker setup before "
                    "creating agents (the cert is the agent credential)."
                ),
                new_agent_id=None,
            ))

        agent_info, _key_pem = await mgr.create_agent(agent_name, display_name, capabilities)
        agent_id = agent_info["agent_id"]
    except Exception as exc:
        agents = await list_agents()
        _org_status = await get_config("org_status") or ""
        _has_ca = bool(await get_config("org_ca_cert"))
        return templates.TemplateResponse("agents.html", _ctx(
            request, session,
            active="agents",
            agents=agents,
            org_status=_org_status,
            has_ca=_has_ca,
            error=f"Failed to create agent: {exc}",
            new_agent_id=None,
        ))

    await log_audit(
        agent_id=agent_id,
        action="agent.create",
        status="success",
        detail=f"display_name={display_name}, capabilities={capabilities}, mode=x509",
    )

    # ADR-010 Phase 6a-4 — the dashboard used to follow agent creation with
    # ``POST /v1/registry/agents`` + ``POST /v1/registry/bindings`` + auto-
    # approve via the legacy org_secret auth. That path is gone. Cross-org
    # exposure is now opt-in: the operator flips the federate toggle on
    # this agent row and manages bindings separately. Both happen through
    # the standard Mastio admin surface (see PATCH /v1/admin/agents/{id}/
    # federated and /v1/registry/bindings endpoints from the dashboard).

    agents = await list_agents()
    org_status = await get_config("org_status") or ""
    has_ca = bool(await get_config("org_ca_cert"))
    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        org_status=org_status,
        has_ca=has_ca,
        new_agent_id=agent_id,
    ))


@router.get("/agents/{agent_id:path}", response_class=HTMLResponse)
async def agent_detail_page(request: Request, agent_id: str):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_agent, get_config
    from mcp_proxy.config import get_settings

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Fetch recent audit entries for this agent
    from sqlalchemy import text

    from mcp_proxy.db import get_db
    async with get_db() as db:
        result = await db.execute(
            text("SELECT * FROM audit_log WHERE agent_id = :agent_id ORDER BY timestamp DESC LIMIT 20"),
            {"agent_id": agent_id},
        )
        audit_entries = [dict(row) for row in result.mappings().all()]

    # Extra context for integration snippets
    settings = get_settings()
    proxy_url = settings.proxy_public_url or f"http://localhost:{settings.port}"
    broker_url = await get_config("broker_url") or ""
    org_id = await get_config("org_id") or settings.org_id
    agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id

    return templates.TemplateResponse("agent_detail.html", _ctx(
        request, session,
        active="agents",
        agent=agent,
        audit_entries=audit_entries,
        proxy_url=proxy_url,
        broker_url=broker_url,
        org_id=org_id,
        agent_name=agent_name,
    ))


@router.get("/agents/{agent_id:path}/env-download")
async def agent_env_download(request: Request, agent_id: str):
    """Download .env file with agent configuration."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_agent, get_config
    from mcp_proxy.config import get_settings

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    settings = get_settings()
    proxy_url = settings.proxy_public_url or f"http://localhost:{settings.port}"
    broker_url = await get_config("broker_url") or ""
    org_id = await get_config("org_id") or settings.org_id

    agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id

    env_content = f"""# Cullis Agent Configuration — {agent_id}
# Generated from MCP Proxy dashboard
# ADR-014: the agent authenticates by presenting its TLS client cert
# at the handshake. Mount cert.pem + key.pem from the identity bundle.
CULLIS_PROXY_URL={proxy_url}
CULLIS_AGENT_ID={agent_id}
CULLIS_ORG_ID={org_id}
CULLIS_BROKER_URL={broker_url}
"""

    return Response(
        content=env_content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="{agent_name}.env"'
        },
    )


_VALID_REACH = {"intra", "cross", "both"}


@router.post("/agents/{agent_id:path}/reach")
async def agent_set_reach(request: Request, agent_id: str):
    """Set ``internal_agents.reach`` from the dashboard.

    Migration 0017 introduced three states:

    * ``intra``  — same-org chat only, NOT published to the Court
    * ``cross``  — other-org chat only, published to the Court
    * ``both``   — intra + cross, published

    The legacy ``federated`` boolean is kept in sync so the publisher
    (ADR-010 Phase 3) still finds the right rows to PUT / revoke; it is
    now derived from ``reach`` instead of being the primary knob.
    ``federation_revision`` is bumped on every mutation so the publisher
    picks up the change on its next tick.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    new_reach = (form.get("reach") or "").strip().lower()
    if new_reach not in _VALID_REACH:
        raise HTTPException(
            status_code=400,
            detail=f"reach must be one of {sorted(_VALID_REACH)}",
        )

    from mcp_proxy.db import get_agent, get_db, log_audit
    from sqlalchemy import text as _text

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    new_federated = new_reach != "intra"
    async with get_db() as conn:
        await conn.execute(
            _text(
                """
                UPDATE internal_agents
                   SET reach = :reach,
                       federated = :fed,
                       federation_revision = federation_revision + 1
                 WHERE agent_id = :aid
                """
            ),
            {"reach": new_reach, "fed": bool(new_federated), "aid": agent_id},
        )

    await log_audit(
        agent_id=agent_id,
        action="agent.reach_set",
        status="success",
        detail=f"source=dashboard reach={new_reach} federated={new_federated}",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)


@router.post("/agents/{agent_id:path}/deactivate")
async def agent_deactivate(request: Request, agent_id: str):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import deactivate_agent, log_audit

    found = await deactivate_agent(agent_id)
    if not found:
        raise HTTPException(status_code=404, detail="Agent not found")

    await log_audit(
        agent_id=agent_id,
        action="agent.deactivate",
        status="success",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)


@router.post("/agents/{agent_id:path}/delete")
async def agent_delete(request: Request, agent_id: str):
    """Permanently delete an agent and all associated data."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from sqlalchemy import text

    from mcp_proxy.db import get_agent, get_db, log_audit

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Delete from local DB
    async with get_db() as db:
        await db.execute(
            text("DELETE FROM internal_agents WHERE agent_id = :agent_id"),
            {"agent_id": agent_id},
        )
        # Also remove stored key from proxy_config if present
        await db.execute(
            text("DELETE FROM proxy_config WHERE key = :key"),
            {"key": f"agent_key:{agent_id}"},
        )

    # ADR-010 Phase 6a-4 — the ``DELETE /v1/registry/agents/{id}`` hop is
    # gone. ``db_deactivate_agent`` bumps ``federation_revision`` for
    # federated rows, and the publisher carries the revocation to the
    # Court via ``/v1/federation/publish-agent`` on its next tick.

    await log_audit(
        agent_id=agent_id,
        action="agent.delete",
        status="success",
        detail="Agent permanently deleted",
    )

    return RedirectResponse(url="/proxy/agents", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.tools.registry import tool_registry
    tools = tool_registry.list_tools()

    return templates.TemplateResponse("tools.html", _ctx(
        request, session,
        active="tools",
        tools=tools,
    ))


@router.get("/network", response_class=HTMLResponse)
async def network_page(request: Request):
    """Network directory — discover agents across the trust network via broker."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import list_agents, get_config

    q = (request.query_params.get("q") or "").strip() or None
    pattern = (request.query_params.get("pattern") or "").strip() or None
    org_filter = (request.query_params.get("org_id") or "").strip() or None
    capabilities_raw = (request.query_params.get("capabilities") or "").strip()
    capabilities = [c.strip() for c in capabilities_raw.split(",") if c.strip()] or None
    # ``include_own_org`` defaults on for the first page load — the list is
    # a directory, not a filter result, so showing your own org's agents
    # alongside peers is the expected default. Operators uncheck it when
    # they want to focus on cross-org visibility.
    has_query = any(k in request.query_params for k in (
        "q", "pattern", "org_id", "capabilities", "include_own_org", "querier",
    ))
    include_own_org = (
        request.query_params.get("include_own_org") == "on"
        if has_query
        else True
    )
    querier = (request.query_params.get("querier") or "").strip() or None

    internal_agents = await list_agents()
    own_org_id = await get_config("org_id") or ""
    broker_url = await get_config("broker_url") or ""

    bridge = getattr(request.app.state, "broker_bridge", None)

    # Default querier: first active internal agent.
    if not querier and internal_agents:
        querier = next(
            (a["agent_id"] for a in internal_agents if a.get("is_active", True)),
            internal_agents[0]["agent_id"],
        )

    agents: list[dict] = []
    error: str | None = None

    # Always populate the directory on every page load (no more ``submitted``
    # gate). Empty filters = full peer list under the selected querier;
    # typed filters narrow the same list. Errors are surfaced inline so the
    # missing-prereq path (no bridge / no internal agents) stays discoverable.
    if bridge is None:
        error = "Broker bridge not initialized — complete the Setup wizard first."
    elif not internal_agents:
        error = "Create an internal agent first — discovery queries go through an agent identity."
    elif not querier:
        error = "Select a querier agent."
    else:
        try:
            agents = await bridge.discover_agents(
                querier,
                capabilities=capabilities,
                q=q,
                org_id=org_filter,
                pattern=pattern,
            )
            if not include_own_org and own_org_id:
                agents = [a for a in agents if a.get("org_id") != own_org_id]
        except Exception as exc:
            _log.warning("Network directory query failed: %s", exc)
            error = f"Discovery failed: {exc}"

    own_org_count = sum(1 for a in agents if a.get("org_id") == own_org_id) if own_org_id else 0
    peer_count = len(agents) - own_org_count
    has_active_filters = bool(q or pattern or org_filter or capabilities)

    return templates.TemplateResponse("network.html", _ctx(
        request, session,
        active="network",
        internal_agents=internal_agents,
        querier=querier,
        q=q or "",
        pattern=pattern or "",
        org_filter=org_filter or "",
        capabilities=capabilities_raw,
        include_own_org=include_own_org,
        agents=agents,
        own_org_count=own_org_count,
        peer_count=peer_count,
        has_active_filters=has_active_filters,
        own_org_id=own_org_id,
        broker_url=broker_url,
        error=error,
    ))


@router.post("/tools/reload")
async def tools_reload(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.tools.registry import tool_registry
    from mcp_proxy.config import get_settings

    settings = get_settings()
    tool_registry.load_from_yaml(settings.tools_config_path)

    from mcp_proxy.db import log_audit
    await log_audit(
        agent_id="admin",
        action="tools.reload",
        status="success",
        detail=f"Loaded {len(tool_registry)} tool(s)",
    )

    return RedirectResponse(url="/proxy/tools", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Policies
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/policies", response_class=HTMLResponse)
async def policies_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_config

    rules_json = await get_config("policy_rules") or json.dumps({
        "allowed_orgs": [],
        "blocked_agents": [],
        "capabilities": {},
    }, indent=2)

    pdp_url = await get_config("pdp_webhook_url") or ""
    pdp_timeout = await get_config("pdp_timeout") or "5"

    return templates.TemplateResponse("policies.html", _ctx(
        request, session,
        active="policies",
        rules_json=rules_json,
        pdp_url=pdp_url,
        pdp_timeout=pdp_timeout,
    ))


@router.post("/policies/save")
async def policies_save(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import set_config, get_config, log_audit

    form = await request.form()
    tab = str(form.get("tab", "rules"))

    if tab == "rules":
        rules_raw = str(form.get("rules_json", ""))
        try:
            parsed = json.loads(rules_raw)
            rules_json = json.dumps(parsed, indent=2)
        except json.JSONDecodeError:
            # Re-render with error
            pdp_url = await get_config("pdp_webhook_url") or ""
            pdp_timeout = await get_config("pdp_timeout") or "5"
            return templates.TemplateResponse("policies.html", _ctx(
                request, session,
                active="policies",
                rules_json=rules_raw,
                pdp_url=pdp_url,
                pdp_timeout=pdp_timeout,
                error="Invalid JSON in policy rules.",
            ))

        await set_config("policy_rules", rules_json)
        await log_audit(
            agent_id="admin",
            action="policy.update_rules",
            status="success",
        )

    elif tab == "pdp":
        pdp_url = str(form.get("pdp_url", "")).strip()
        pdp_timeout = str(form.get("pdp_timeout", "5")).strip()
        await set_config("pdp_webhook_url", pdp_url)
        await set_config("pdp_timeout", pdp_timeout)
        await log_audit(
            agent_id="admin",
            action="policy.update_pdp",
            status="success",
            detail=f"url={pdp_url}, timeout={pdp_timeout}s",
        )

    return RedirectResponse(url="/proxy/policies", status_code=303)


@router.post("/policies/test-webhook")
async def policies_test_webhook(request: Request):
    """HTMX endpoint: test PDP webhook connectivity."""
    import html as _html
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return HTMLResponse('<span class="text-red-400">Not authenticated</span>')

    # Wave B G1 — verify CSRF + SSRF allow-list + escape exception text
    if not await verify_csrf(request, session):
        return HTMLResponse('<span class="text-red-400">CSRF check failed</span>')

    form = await request.form()
    webhook_url = str(form.get("pdp_url", "")).strip()

    if not webhook_url:
        return HTMLResponse('<span class="text-red-400">Enter a webhook URL first</span>')

    try:
        _enforce_safe_outbound_url(webhook_url)
    except ValueError as exc:
        return HTMLResponse(
            f'<span class="text-red-400">{_html.escape(str(exc))}</span>'
        )

    try:
        import httpx
        test_payload = {
            "agent_id": "test::probe",
            "action": "tool_execute",
            "tool": "test_tool",
            "capabilities": ["test"],
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(webhook_url, json=test_payload)
            if resp.status_code == 200:
                return HTMLResponse(
                    '<span class="text-emerald-400 flex items-center gap-1.5">'
                    '<span class="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>'
                    'Webhook responded OK</span>'
                )
            return HTMLResponse(
                f'<span class="text-yellow-400">HTTP {resp.status_code}</span>'
            )
    except Exception as exc:
        return HTMLResponse(
            f'<span class="text-red-400">Connection failed: '
            f'{_html.escape(str(exc))}</span>'
        )


# ─────────────────────────────────────────────────────────────────────────────
# Audit
# ─────────────────────────────────────────────────────────────────────────────

def _pretty_and_recipient(raw: str | None) -> tuple[str | None, str | None]:
    """Pretty-print a JSON detail string and pluck the recipient hint.

    The proxy writes traffic events to ``local_audit.details`` as JSON
    strings (oneshot forwarded, mcp tool execute, session send…). We
    parse the payload once server-side so the template can show both a
    formatted blob in the inspector and a ``Target`` hint in the row
    without doing the parsing twice.
    """
    import json as _json
    if not raw:
        return None, None
    try:
        parsed = _json.loads(raw)
    except (ValueError, TypeError):
        return raw, None
    pretty = _json.dumps(parsed, indent=2, sort_keys=True)
    recipient = None
    if isinstance(parsed, dict):
        recipient = (
            parsed.get("recipient")
            or parsed.get("recipient_agent_id")
            or parsed.get("target_agent_id")
            or parsed.get("target")
        )
    return pretty, recipient


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_db, list_agents

    agent_filter = request.query_params.get("agent", "")
    action_filter = request.query_params.get("action", "")
    status_filter = request.query_params.get("status", "")
    source_filter = request.query_params.get("source", "")  # '', 'admin', 'traffic'
    page = int(request.query_params.get("page", "1"))
    per_page = 50

    from sqlalchemy import text

    # ``audit_log`` uses ``status='success'``; ``local_audit`` uses
    # ``result='ok'`` for the same concept. Map the UI filter once and
    # use the per-table equivalent when building WHERE clauses.
    local_audit_result_for = {"success": "ok", "ok": "ok", "error": "error", "denied": "denied"}

    async with get_db() as db:
        admin_rows: list[dict] = []
        traffic_rows: list[dict] = []

        # Admin stream — legacy ``audit_log`` (auth, enroll, agent CRUD, policy…)
        if source_filter in ("", "admin"):
            a_conds: list[str] = []
            a_params: dict[str, object] = {}
            if agent_filter:
                a_conds.append("agent_id = :agent_id")
                a_params["agent_id"] = agent_filter
            if action_filter:
                a_conds.append("action = :action")
                a_params["action"] = action_filter
            if status_filter:
                a_conds.append("status = :status")
                a_params["status"] = status_filter
            a_where = (" WHERE " + " AND ".join(a_conds)) if a_conds else ""
            result = await db.execute(
                text(f"SELECT * FROM audit_log{a_where} ORDER BY timestamp DESC LIMIT 500"),
                a_params,
            )
            admin_rows = [dict(r) for r in result.mappings().all()]

        # Traffic stream — hash-chained ``local_audit`` (oneshot, mcp, sessions)
        if source_filter in ("", "traffic"):
            t_conds: list[str] = []
            t_params: dict[str, object] = {}
            if agent_filter:
                t_conds.append("agent_id = :agent_id")
                t_params["agent_id"] = agent_filter
            if action_filter:
                t_conds.append("event_type = :event_type")
                t_params["event_type"] = action_filter
            if status_filter:
                t_conds.append("result = :result")
                t_params["result"] = local_audit_result_for.get(status_filter, status_filter)
            t_where = (" WHERE " + " AND ".join(t_conds)) if t_conds else ""
            result = await db.execute(
                text(f"SELECT * FROM local_audit{t_where} ORDER BY timestamp DESC LIMIT 500"),
                t_params,
            )
            traffic_rows = [dict(r) for r in result.mappings().all()]

        # Distinct actions + event_types for the filter dropdown.
        r1 = await db.execute(text("SELECT DISTINCT action FROM audit_log WHERE action IS NOT NULL"))
        r2 = await db.execute(text("SELECT DISTINCT event_type FROM local_audit WHERE event_type IS NOT NULL"))
        actions = sorted(set(r[0] for r in r1.fetchall()) | set(r[0] for r in r2.fetchall()))

    # Normalize both streams into a single shape so the template has
    # exactly one cell layout to render. Fields that only exist in one
    # table are left as ``None`` for the other source; the inspector
    # hides rows where the value is missing.
    unified: list[dict] = []
    for r in admin_rows:
        detail_pretty, _ = _pretty_and_recipient(r.get("detail"))
        unified.append({
            "source": "admin",
            "timestamp": r.get("timestamp"),
            "agent_id": r.get("agent_id"),
            "event": r.get("action"),
            "status": r.get("status"),
            "target": r.get("tool_name"),
            "tool_name": r.get("tool_name"),
            "duration_ms": r.get("duration_ms"),
            "request_id": r.get("request_id"),
            "session_id": None,
            "org_id": None,
            "chain_seq": None,
            "entry_hash": None,
            "peer_org_id": None,
            "detail_pretty": detail_pretty,
        })
    for r in traffic_rows:
        detail_pretty, recipient = _pretty_and_recipient(r.get("details"))
        raw_result = r.get("result")
        status_display = "success" if raw_result == "ok" else raw_result
        unified.append({
            "source": "traffic",
            "timestamp": r.get("timestamp"),
            "agent_id": r.get("agent_id"),
            "event": r.get("event_type"),
            "status": status_display,
            "target": recipient,
            "tool_name": None,
            "duration_ms": None,
            "request_id": None,
            "session_id": r.get("session_id"),
            "org_id": r.get("org_id"),
            "chain_seq": r.get("chain_seq"),
            "entry_hash": r.get("entry_hash"),
            "peer_org_id": r.get("peer_org_id"),
            "detail_pretty": detail_pretty,
        })

    # ISO-8601 strings sort correctly as plain strings — no parsing needed.
    unified.sort(key=lambda x: x["timestamp"] or "", reverse=True)

    total = len(unified)
    admin_total = sum(1 for e in unified if e["source"] == "admin")
    traffic_total = total - admin_total
    total_pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page
    entries = unified[offset:offset + per_page]

    agents = await list_agents()
    agent_ids = sorted(set(a["agent_id"] for a in agents))

    return templates.TemplateResponse("audit.html", _ctx(
        request, session,
        active="audit",
        entries=entries,
        agent_ids=agent_ids,
        actions=actions,
        agent_filter=agent_filter,
        action_filter=action_filter,
        status_filter=status_filter,
        source_filter=source_filter,
        page=page,
        total_pages=total_pages,
        admin_total=admin_total,
        traffic_total=traffic_total,
        total=total,
    ))


# ─────────────────────────────────────────────────────────────────────────────
# PKI Overview
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/pki", response_class=HTMLResponse)
async def pki_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_config, list_agents

    ca_cert_pem = await get_config("org_ca_cert")
    vault_addr = await get_config("vault_addr") or ""

    ca = None
    if ca_cert_pem:
        try:
            cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
            cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            org_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            try:
                bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
                is_ca = bc.value.ca
            except x509.ExtensionNotFound:
                is_ca = False
            key_size = cert.public_key().key_size if hasattr(cert.public_key(), "key_size") else "N/A"
            ca = {
                "subject_cn": cn_attrs[0].value if cn_attrs else "N/A",
                "organization": org_attrs[0].value if org_attrs else "N/A",
                "serial_number": format(cert.serial_number, "X"),
                "valid_from": cert.not_valid_before_utc.isoformat()[:19],
                "valid_until": cert.not_valid_after_utc.isoformat()[:19],
                "is_ca": is_ca,
                "key_size": f"RSA-{key_size}" if isinstance(key_size, int) else key_size,
                "cert_pem": ca_cert_pem,
            }
        except Exception as exc:
            _log.warning("Failed to parse CA cert: %s", exc)

    # Parse agent certs for the table
    agents = await list_agents()
    agent_certs = []
    now = datetime.now(timezone.utc)
    for agent in agents:
        if agent.get("cert_pem"):
            try:
                acert = x509.load_pem_x509_certificate(agent["cert_pem"].encode())
                cn_attrs = acert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                # Extract SAN URI
                san_uri = ""
                try:
                    san_ext = acert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
                    san_uri = uris[0] if uris else ""
                except x509.ExtensionNotFound:
                    pass
                valid_until = acert.not_valid_after_utc
                is_valid = valid_until > now
                is_expiring = is_valid and (valid_until - now).days < 30
                agent_certs.append({
                    "agent_id": agent["agent_id"],
                    "subject_cn": cn_attrs[0].value if cn_attrs else agent["agent_id"],
                    "san_uri": san_uri,
                    "valid_until": valid_until.isoformat()[:19],
                    "is_valid": is_valid and not is_expiring,
                    "is_expiring": is_expiring,
                })
            except Exception:
                pass

    # Vault status for PKI page
    vault = None
    if vault_addr:
        vault_token = await get_config("vault_token") or ""
        ok, msg = await _test_vault_connectivity(vault_addr, vault_token) if vault_token else (False, "No token")
        vault = {"addr": vault_addr, "connected": ok, "error": msg if not ok else None}

    return templates.TemplateResponse("pki.html", _ctx(
        request, session,
        active="pki",
        ca=ca,
        agent_certs=agent_certs,
        vault=vault,
    ))


@router.post("/pki/export-ca")
async def pki_export_ca(request: Request):
    """Download the Org CA certificate PEM (public cert only, never the private key)."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import get_config, log_audit

    ca_cert_pem = await get_config("org_ca_cert")
    if not ca_cert_pem:
        raise HTTPException(status_code=404, detail="No Org CA configured")

    await log_audit(
        agent_id="admin",
        action="ca.export_cert",
        status="success",
    )

    return Response(
        content=ca_cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=org-ca.pem"},
    )


@router.post("/pki/rotate-ca")
async def pki_rotate_ca(request: Request):
    """Generate new Org CA. WARNING: invalidates all existing agent certificates."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import get_config, set_config, log_audit

    org_id = await get_config("org_id")
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization ID not configured. Run setup first.")

    cert_pem, key_pem = generate_org_ca(org_id)
    await set_config("org_ca_cert", cert_pem)
    await set_config("org_ca_key", key_pem)

    await log_audit(
        agent_id="admin",
        action="ca.rotate",
        status="success",
        detail=f"org_id={org_id}, new self-signed RSA-4096. All agent certs need re-issue.",
    )

    # Store in Vault if configured
    vault_addr = await get_config("vault_addr")
    vault_token = await get_config("vault_token")
    if vault_addr and vault_token:
        try:
            await _store_ca_key_in_vault(vault_addr, vault_token, org_id, key_pem)
            await log_audit(
                agent_id="admin",
                action="vault.store_ca_key",
                status="success",
                detail=f"org_id={org_id}, after CA rotation",
            )
        except Exception as exc:
            _log.warning("Failed to store rotated CA key in Vault: %s", exc)

    return RedirectResponse(url="/proxy/pki", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Mastio ES256 signing key — rotation dashboard (ADR-012 Phase 2.1 UX)
# ─────────────────────────────────────────────────────────────────────────────

MASTIO_ROTATION_GRACE_DAYS_DEFAULT = 7
MASTIO_ROTATION_GRACE_DAYS_MIN = 1
MASTIO_ROTATION_GRACE_DAYS_MAX = 90

# Minimum seconds between two ``/mastio-key/rotate`` calls. Configurable
# via env so sandbox integration tests (#268) can lower / disable it
# during ``./demo.sh full``, and so incident response can drop it to 0
# without code edits. Not a trust-governance knob (never goes through
# ``proxy_config``) — purely an operational guardrail against
# burst-loop abuse from a stolen admin cookie. See #282.
_MASTIO_ROTATION_MIN_INTERVAL_SECONDS_DEFAULT = 30


def _mastio_rotation_min_interval_seconds() -> int:
    """Read ``CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS`` from env.

    Falls back to 30s on unset / malformed. Accepts 0 to disable the
    guardrail (test environments, incident rollback).
    """
    import os
    raw = os.environ.get("CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS")
    if raw is None:
        return _MASTIO_ROTATION_MIN_INTERVAL_SECONDS_DEFAULT
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _MASTIO_ROTATION_MIN_INTERVAL_SECONDS_DEFAULT
    return max(0, value)


async def _load_rotation_grace_days() -> int:
    """Read the configured rotation grace window (days) from proxy_config.

    Falls back to the baseline default on first visit / malformed config.
    """
    from mcp_proxy.db import get_config
    raw = await get_config("rotation_grace_days")
    if raw is None:
        return MASTIO_ROTATION_GRACE_DAYS_DEFAULT
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return MASTIO_ROTATION_GRACE_DAYS_DEFAULT
    if value < MASTIO_ROTATION_GRACE_DAYS_MIN:
        return MASTIO_ROTATION_GRACE_DAYS_MIN
    if value > MASTIO_ROTATION_GRACE_DAYS_MAX:
        return MASTIO_ROTATION_GRACE_DAYS_MAX
    return value


def _mastio_key_to_view(key, *, now: datetime) -> dict:
    """Render a ``MastioKey`` into a plain dict the template can iterate over."""
    expires_at = key.expires_at
    grace_total = None
    grace_remaining = None
    grace_pct = None
    if key.deprecated_at is not None and expires_at is not None:
        grace_total_s = (expires_at - key.deprecated_at).total_seconds()
        grace_remaining_s = max(0, (expires_at - now).total_seconds())
        grace_total = max(1, int(grace_total_s))
        grace_remaining = int(grace_remaining_s)
        # 0% = just rotated, 100% = grace fully elapsed
        grace_pct = max(
            0, min(100, 100 - int(grace_remaining_s * 100 / grace_total)),
        )
    return {
        "kid": key.kid,
        "pubkey_pem": key.pubkey_pem,
        "cert_pem": key.cert_pem or "",
        "created_at": key.created_at.isoformat(),
        "activated_at": key.activated_at.isoformat() if key.activated_at else None,
        "deprecated_at": key.deprecated_at.isoformat() if key.deprecated_at else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "is_active": key.is_active,
        "is_valid_for_verification": key.is_valid_for_verification,
        "grace_total_seconds": grace_total,
        "grace_remaining_seconds": grace_remaining,
        "grace_pct": grace_pct,
    }


@router.get("/mastio-key", response_class=HTMLResponse)
async def mastio_key_page(request: Request):
    """Signing-key rotation dashboard.

    Shows the active Mastio ES256 signer, any keys still inside the
    verifier grace window, and exposes the ``rotation_grace_days``
    configuration + a one-click rotate action.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.auth.local_keystore import LocalKeyStore
    from mcp_proxy.db import get_config

    org_id = await get_config("org_id") or ""
    grace_days = await _load_rotation_grace_days()
    standalone = getattr(request.app.state, "broker_bridge", None) is None

    keystore = LocalKeyStore()
    now = datetime.now(timezone.utc)

    active_view = None
    try:
        active_key = await keystore.current_signer()
    except RuntimeError as exc:
        # Identity not yet provisioned — the page renders with an
        # empty-state CTA pointing at /proxy/setup.
        _log.info("mastio_key page: no active signer (%s)", exc)
        active_key = None

    if active_key is not None:
        active_view = _mastio_key_to_view(active_key, now=now)

    grace_keys = []
    try:
        valid = await keystore.all_valid_keys()
        for k in valid:
            if k.deprecated_at is None:
                continue  # that is the active one, shown above
            grace_keys.append(_mastio_key_to_view(k, now=now))
        grace_keys.sort(key=lambda k: k["expires_at"] or "")
    except Exception:
        pass

    return templates.TemplateResponse("mastio_key.html", _ctx(
        request, session,
        active="mastio_key",
        org_id=org_id,
        active_key=active_view,
        grace_keys=grace_keys,
        grace_days=grace_days,
        grace_days_min=MASTIO_ROTATION_GRACE_DAYS_MIN,
        grace_days_max=MASTIO_ROTATION_GRACE_DAYS_MAX,
        standalone=standalone,
    ))


@router.post("/mastio-key/grace-days")
async def mastio_key_save_grace(request: Request):
    """Persist the ``rotation_grace_days`` preference (clamped to 1..90)."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import log_audit, set_config

    form = await request.form()
    raw = form.get("grace_days", "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail=f"grace_days must be an integer between {MASTIO_ROTATION_GRACE_DAYS_MIN} and {MASTIO_ROTATION_GRACE_DAYS_MAX}",
        )
    if (
        value < MASTIO_ROTATION_GRACE_DAYS_MIN
        or value > MASTIO_ROTATION_GRACE_DAYS_MAX
    ):
        raise HTTPException(
            status_code=400,
            detail=f"grace_days must be between {MASTIO_ROTATION_GRACE_DAYS_MIN} and {MASTIO_ROTATION_GRACE_DAYS_MAX}",
        )

    await set_config("rotation_grace_days", str(value))
    await log_audit(
        agent_id="admin",
        action="mastio_key.grace_days_set",
        status="success",
        detail=f"rotation_grace_days={value}",
    )
    return RedirectResponse(url="/proxy/mastio-key", status_code=303)


@router.post("/mastio-key/rotate")
async def mastio_key_rotate(request: Request):
    """Trigger a Mastio ES256 leaf rotation.

    Flow (ADR-012 Phase 2.1, issue #261):
      1. ``AgentManager.rotate_mastio_key`` mints a new leaf under the
         intermediate CA, signs a continuity proof with the current key.
      2. The ``propagator`` (wired to ``BrokerBridge`` when available)
         POSTs the proof to the Court's rotate endpoint. On Court
         rejection we raise 502 with the Court's own error.
      3. The local ``mastio_keys`` swap runs in a single DB transaction —
         the previous key is marked ``deprecated_at=now`` / ``expires_at``
         at ``now + grace_days`` and remains verifier-valid during the
         grace window.

    Standalone deploys (no broker uplink) allow rotation without
    propagation — a warning surfaces in the UI. This is a deliberate
    relaxation: a standalone Mastio has no Court pin to update.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    if form.get("confirm_text") != "ROTATE":
        raise HTTPException(
            status_code=400,
            detail="Confirmation text mismatch — rotation aborted",
        )

    from mcp_proxy.db import log_audit

    agent_mgr = getattr(request.app.state, "agent_manager", None)
    if agent_mgr is None or not getattr(agent_mgr, "mastio_loaded", False):
        raise HTTPException(
            status_code=409,
            detail="Mastio identity not loaded — complete setup first",
        )

    # Issue #282 — minimum rotation interval. A logged-in admin can
    # POST ``confirm_text=ROTATE`` in a tight loop and with the default
    # grace_days=7 that's thousands of keys / hour, all passing
    # ``is_valid_for_verification``; with the 90-day max cadence an
    # 8-hour session could mint ~2.5M verification-valid rows.
    # Downstream verifiers OOM, Court gets hammered. A 30-second
    # floor (configurable via env for sandbox integration tests and
    # incident-response rollback) puts a human-scale rate ceiling on
    # the operator surface without entering proxy_config as a
    # trust-governance toggle — this is an operational guardrail.
    min_interval_s = _mastio_rotation_min_interval_seconds()
    if min_interval_s > 0:
        from mcp_proxy.auth.local_keystore import LocalKeyStore
        from datetime import datetime, timezone
        ks = LocalKeyStore()
        try:
            latest_act = max(
                (k.activated_at for k in await ks.all_valid_keys()
                 if k.activated_at is not None),
                default=None,
            )
        except Exception:
            latest_act = None
        if latest_act is not None:
            delta_s = (datetime.now(timezone.utc) - latest_act).total_seconds()
            if delta_s < min_interval_s:
                await log_audit(
                    agent_id="admin",
                    action="mastio_key.rotate",
                    status="rate_limited",
                    detail=(
                        f"min_interval={min_interval_s}s, "
                        f"seconds_since_last={delta_s:.1f}s"
                    ),
                )
                retry_after = max(1, int(min_interval_s - delta_s) + 1)
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Minimum rotation interval {min_interval_s}s — "
                        f"last rotation {delta_s:.1f}s ago. Retry in "
                        f"{retry_after}s or lower "
                        f"CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )

    grace_days = await _load_rotation_grace_days()
    broker_bridge = getattr(request.app.state, "broker_bridge", None)
    propagator = (
        broker_bridge.propagate_mastio_key_rotation
        if broker_bridge is not None
        else None
    )

    old_kid = agent_mgr._active_key.kid if agent_mgr._active_key else None

    try:
        new_active = await agent_mgr.rotate_mastio_key(
            grace_days=grace_days,
            propagator=propagator,
        )
    except HTTPException as exc:
        await log_audit(
            agent_id="admin",
            action="mastio_key.rotate",
            status="failure",
            detail=f"old_kid={old_kid}, reason={exc.detail}",
        )
        raise
    except Exception as exc:
        # Audit H-IO-2 — audit row carries the full reason; HTTP detail
        # is generic so an attacker can't probe rotation internals.
        _log.warning("mastio_key.rotate failed (old_kid=%s): %s", old_kid, exc)
        await log_audit(
            agent_id="admin",
            action="mastio_key.rotate",
            status="failure",
            detail=f"old_kid={old_kid}, reason={exc}",
        )
        raise HTTPException(
            status_code=500,
            detail="rotation failed",
        ) from exc

    # Rebuild the LocalIssuer so subsequent token mints use the new signer.
    try:
        from mcp_proxy.auth.local_issuer import build_from_keystore
        from mcp_proxy.auth.local_keystore import LocalKeyStore
        ks = getattr(request.app.state, "local_keystore", None) or LocalKeyStore()
        request.app.state.local_keystore = ks
        org_id = getattr(request.app.state, "org_id", None)
        if org_id:
            request.app.state.local_issuer = await build_from_keystore(org_id, ks)
    except Exception as exc:
        _log.warning("LocalIssuer rebuild after rotation failed: %s", exc)

    await log_audit(
        agent_id="admin",
        action="mastio_key.rotate",
        status="success",
        detail=(
            f"old_kid={old_kid}, new_kid={new_active.kid}, "
            f"grace_days={grace_days}"
        ),
    )
    # Redirect with flash-state in query string so the page can render a
    # success toast without a dedicated session flash channel.
    return RedirectResponse(
        url=(
            f"/proxy/mastio-key?rotated=1"
            f"&old_kid={old_kid or ''}"
            f"&new_kid={new_active.kid}"
        ),
        status_code=303,
    )


@router.post("/mastio-key/complete-staged")
async def mastio_key_complete_staged(request: Request):
    """Resolve an orphaned staged rotation row (issue #281 recovery).

    The form accepts ``decision=activate`` or ``decision=drop`` plus
    the standard ``confirm_text`` gate. ``activate`` completes a
    rotation whose Court-side propagation succeeded but whose local
    commit crashed; ``drop`` discards a staged row whose Court-side
    propagation never completed.

    On success, clears the sign-halt state on the AgentManager and
    rebuilds the LocalIssuer so token issuance resumes without a
    restart. Emits an audit event with the chosen branch and the
    kids involved.

    Follow-up #287 tracks the full dashboard UI (Court-pin preview
    banner, 2-button flow); this endpoint is the backend plumbing
    reachable from that UI and from ``curl`` for the current
    emergency path.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    decision = (form.get("decision") or "").strip()
    if decision not in ("activate", "drop"):
        raise HTTPException(
            status_code=400,
            detail="decision must be 'activate' or 'drop'",
        )
    expected_confirm = "ACTIVATE" if decision == "activate" else "DROP"
    if form.get("confirm_text") != expected_confirm:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Confirmation text mismatch — type {expected_confirm} "
                f"to complete the {decision} branch"
            ),
        )

    from mcp_proxy.db import log_audit

    agent_mgr = getattr(request.app.state, "agent_manager", None)
    if agent_mgr is None:
        raise HTTPException(
            status_code=409,
            detail="AgentManager not initialized",
        )

    try:
        result = await agent_mgr.complete_staged_rotation(decision)
    except RuntimeError as exc:
        # Audit H-IO-2 — audit row carries the full reason; HTTP detail
        # is generic so an attacker can't probe internal staging state.
        _log.warning(
            "mastio_key.complete_staged failed (decision=%s): %s",
            decision, exc,
        )
        await log_audit(
            agent_id="admin",
            action="mastio_key.complete_staged",
            status="failure",
            detail=f"decision={decision}, reason={exc}",
        )
        raise HTTPException(
            status_code=409,
            detail="complete-staged rotation failed",
        ) from exc

    # Rebuild LocalIssuer so local-token issuance resumes. Mirrors the
    # rebuild that runs at the end of the rotate endpoint above — the
    # halt flag has just been cleared by ``complete_staged_rotation``.
    try:
        from mcp_proxy.auth.local_issuer import build_from_keystore
        from mcp_proxy.auth.local_keystore import LocalKeyStore
        ks = getattr(request.app.state, "local_keystore", None) or LocalKeyStore()
        request.app.state.local_keystore = ks
        org_id = getattr(request.app.state, "org_id", None)
        if org_id:
            request.app.state.local_issuer = await build_from_keystore(org_id, ks)
    except Exception as exc:
        _log.warning(
            "LocalIssuer rebuild after complete-staged failed: %s", exc,
        )

    await log_audit(
        agent_id="admin",
        action="mastio_key.complete_staged",
        status="success",
        detail=(
            f"decision={result['decision']}, kid={result.get('kid', '')}, "
            f"old_kid={result.get('old_kid', '')}"
        ),
    )
    return RedirectResponse(
        url=(
            f"/proxy/mastio-key?completed={result['decision']}"
            f"&kid={result.get('kid', '')}"
        ),
        status_code=303,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Vault Settings
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/vault", response_class=HTMLResponse)
async def vault_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_config, get_db

    vault_addr = await get_config("vault_addr") or ""
    vault_token = await get_config("vault_token") or ""

    # Count local keys (agent_key:* in proxy_config)
    from sqlalchemy import text

    async with get_db() as db:
        result = await db.execute(
            text("SELECT COUNT(*) as cnt FROM proxy_config WHERE key LIKE 'agent_key:%'")
        )
        row = result.mappings().first()
        local_key_count = row["cnt"] if row else 0

    # Test vault status if configured
    vault_status = None
    vault_key_count = 0
    if vault_addr and vault_token:
        import httpx
        from mcp_proxy.config import get_settings as _s, vault_tls_verify
        try:
            async with httpx.AsyncClient(
                verify=vault_tls_verify(_s()), timeout=5.0,
            ) as client:
                resp = await client.get(
                    f"{vault_addr.rstrip('/')}/v1/sys/health",
                    headers={"X-Vault-Token": vault_token},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    vault_status = {
                        "connected": not data.get("sealed", True),
                        "version": data.get("version", "unknown"),
                        "sealed": data.get("sealed", False),
                    }
                else:
                    vault_status = {"connected": False, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:
            vault_status = {"connected": False, "error": str(exc)}

    return templates.TemplateResponse("vault.html", _ctx(
        request, session,
        active="vault",
        vault_addr=vault_addr,
        vault_token=vault_token,
        vault_status=vault_status,
        local_key_count=local_key_count,
        vault_key_count=vault_key_count,
    ))


@router.post("/vault/save")
async def vault_save(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import set_config, log_audit

    form = await request.form()
    vault_addr = str(form.get("vault_addr", "")).strip()
    vault_token = str(form.get("vault_token", "")).strip()

    errors: list[str] = []
    if not vault_addr:
        errors.append("Vault address is required.")
    if not vault_token:
        errors.append("Vault token is required.")

    if errors:
        return templates.TemplateResponse("vault.html", _ctx(
            request, session,
            active="vault",
            vault_addr=vault_addr,
            vault_token="",
            vault_status=None,
            local_key_count=0,
            vault_key_count=0,
            errors=errors,
        ))

    # Test connectivity before saving
    ok, msg = await _test_vault_connectivity(vault_addr, vault_token)
    if not ok:
        return templates.TemplateResponse("vault.html", _ctx(
            request, session,
            active="vault",
            vault_addr=vault_addr,
            vault_token="",
            vault_status={"connected": False, "error": msg},
            local_key_count=0,
            vault_key_count=0,
            errors=[f"Vault connectivity test failed: {msg}"],
        ))

    await set_config("vault_addr", vault_addr)
    await set_config("vault_token", vault_token)

    await log_audit(
        agent_id="admin",
        action="vault.configure",
        status="success",
        detail=f"addr={vault_addr}",
    )

    return RedirectResponse(url="/proxy/vault", status_code=303)


@router.post("/vault/test")
async def vault_test(request: Request):
    """HTMX endpoint: test Vault connectivity."""
    import html as _html
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return HTMLResponse('<span class="text-red-400">Not authenticated</span>')

    # Wave B G1 — verify CSRF + SSRF allow-list (Vault behind a docker
    # network is the legitimate case; ``allow_private=True`` honours
    # the same flag that PDP webhooks use, so docker-compose vault://
    # addresses keep working).
    if not await verify_csrf(request, session):
        return HTMLResponse('<span class="text-red-400">CSRF check failed</span>')

    form = await request.form()
    vault_addr = str(form.get("vault_addr", "")).strip()
    vault_token = str(form.get("vault_token", "")).strip()

    if not vault_addr:
        return HTMLResponse('<span class="text-red-400">Enter a Vault address first</span>')

    try:
        _enforce_safe_outbound_url(vault_addr, allow_private=True)
    except ValueError as exc:
        return HTMLResponse(
            f'<span class="text-red-400">{_html.escape(str(exc))}</span>'
        )

    if not vault_token:
        # Try stored token
        from mcp_proxy.db import get_config
        vault_token = await get_config("vault_token") or ""

    if not vault_token:
        return HTMLResponse('<span class="text-red-400">Vault token required</span>')

    ok, msg = await _test_vault_connectivity(vault_addr, vault_token)
    if ok:
        return HTMLResponse(
            '<span class="text-emerald-400 flex items-center gap-1.5">'
            '<span class="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>'
            'Vault connected and unsealed</span>'
        )
    return HTMLResponse(f'<span class="text-red-400">{_html.escape(msg)}</span>')


@router.post("/vault/migrate-keys")
async def vault_migrate_keys(request: Request):
    """Migrate all agent private keys from DB to Vault."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import get_config, get_db, log_audit

    vault_addr = await get_config("vault_addr")
    vault_token = await get_config("vault_token")
    if not vault_addr or not vault_token:
        raise HTTPException(status_code=400, detail="Vault not configured")

    # Test connectivity first
    ok, msg = await _test_vault_connectivity(vault_addr, vault_token)
    if not ok:
        raise HTTPException(status_code=502, detail=f"Vault unreachable: {msg}")

    import httpx
    from mcp_proxy.config import get_settings as _s, vault_tls_verify

    _vault_verify = vault_tls_verify(_s())

    # Find all agent keys stored in proxy_config (agent_key:* pattern)
    from sqlalchemy import text

    migrated = 0
    async with get_db() as db:
        result = await db.execute(
            text("SELECT key, value FROM proxy_config WHERE key LIKE 'agent_key:%'")
        )
        rows = result.mappings().all()

    for row in rows:
        agent_id = row["key"].replace("agent_key:", "", 1)
        key_pem = row["value"]
        path = f"secret/data/mcp-proxy/agents/{agent_id}"
        url = f"{vault_addr.rstrip('/')}/v1/{path}"
        try:
            async with httpx.AsyncClient(verify=_vault_verify, timeout=5.0) as client:
                resp = await client.post(
                    url,
                    json={"data": {"key_pem": key_pem}},
                    headers={"X-Vault-Token": vault_token},
                )
                resp.raise_for_status()
            migrated += 1
        except Exception as exc:
            _log.warning("Failed to migrate key for %s to Vault: %s", agent_id, exc)

    await log_audit(
        agent_id="admin",
        action="vault.migrate_keys",
        status="success",
        detail=f"Migrated {migrated}/{len(rows)} agent keys to Vault",
    )

    return RedirectResponse(url="/proxy/vault", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Connector enrollments (Phase 2c — admin review UI)
#
# The JSON API lives under /v1/admin/enrollments/* (mcp_proxy.enrollment.router).
# These routes render the HTML dashboard page and accept form-based POST
# submissions so the approve/reject flow matches the prevailing form+CSRF
# pattern used by the rest of the dashboard (agents/create, vault/save, etc).
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_agent_manager(request: Request):
    """Return a usable AgentManager for enrollment approval.

    Prefers ``app.state.agent_manager`` (set in tests), then the one
    embedded in ``app.state.broker_bridge``, then falls back to
    constructing one on the fly and loading the Org CA from config.
    """
    from mcp_proxy.egress.agent_manager import AgentManager

    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is not None:
        return mgr

    bridge = getattr(request.app.state, "broker_bridge", None)
    if bridge is not None:
        embedded = getattr(bridge, "_agent_manager", None)
        if embedded is not None:
            return embedded

    # Fallback: construct from config. ``load_org_ca_from_config`` is a
    # no-op when no CA is stored; the enrollment service will then raise a
    # clean 503 that we surface in the page.
    from mcp_proxy.config import get_settings

    settings = get_settings()
    return AgentManager(org_id=settings.org_id, trust_domain=settings.trust_domain)


@router.get("/enrollments", response_class=HTMLResponse)
async def enrollments_page(request: Request):
    """Admin-only list of pending Connector enrollment requests."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_db as _get_db
    from mcp_proxy.enrollment import service as _enrollment_service

    async with _get_db() as conn:
        pending = await _enrollment_service.list_pending(conn)

    flash = request.query_params.get("flash")
    flash_kind = request.query_params.get("flash_kind", "success")
    error = request.query_params.get("error")

    return templates.TemplateResponse("enrollments.html", _ctx(
        request, session,
        active="enrollments",
        pending=pending,
        flash=flash,
        flash_kind=flash_kind,
        error=error,
    ))


@router.post("/enrollments/{session_id}/approve")
async def enrollments_approve(request: Request, session_id: str):
    """Form-based approve handler. Calls the service and redirects back."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import get_db as _get_db
    from mcp_proxy.enrollment import service as _enrollment_service

    form = await request.form()
    agent_id = str(form.get("agent_id", "")).strip()
    capabilities_raw = str(form.get("capabilities", "")).strip()
    groups_raw = str(form.get("groups", "")).strip()

    if not agent_id:
        return RedirectResponse(
            url="/proxy/enrollments?error=agent_id+is+required",
            status_code=303,
        )

    capabilities = [c.strip() for c in capabilities_raw.split(",") if c.strip()]
    groups = [g.strip() for g in groups_raw.split(",") if g.strip()]

    agent_manager = _resolve_agent_manager(request)

    try:
        async with _get_db() as conn:
            record = await _enrollment_service.approve(
                conn,
                session_id=session_id,
                agent_id=agent_id,
                capabilities=capabilities,
                groups=groups,
                admin_name=session.role or "admin",
                agent_manager=agent_manager,
            )
    except _enrollment_service.EnrollmentError as exc:
        from urllib.parse import quote
        return RedirectResponse(
            url=f"/proxy/enrollments?error={quote(str(exc))}",
            status_code=303,
        )

    _log.info(
        "enrollment_approved via dashboard: session=%s agent=%s admin=%s",
        session_id, record.get("agent_id_assigned"), session.role,
    )
    from urllib.parse import quote
    msg = f"Approved enrollment — agent {record.get('agent_id_assigned', agent_id)} issued"
    return RedirectResponse(
        url=f"/proxy/enrollments?flash={quote(msg)}",
        status_code=303,
    )


@router.post("/enrollments/{session_id}/reject")
async def enrollments_reject(request: Request, session_id: str):
    """Form-based reject handler. Calls the service and redirects back."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import get_db as _get_db
    from mcp_proxy.enrollment import service as _enrollment_service

    form = await request.form()
    reason = str(form.get("reason", "")).strip()
    if not reason:
        return RedirectResponse(
            url="/proxy/enrollments?error=Rejection+reason+is+required",
            status_code=303,
        )

    try:
        async with _get_db() as conn:
            await _enrollment_service.reject(
                conn,
                session_id=session_id,
                reason=reason,
                admin_name=session.role or "admin",
            )
    except _enrollment_service.EnrollmentError as exc:
        from urllib.parse import quote
        return RedirectResponse(
            url=f"/proxy/enrollments?error={quote(str(exc))}",
            status_code=303,
        )

    _log.info(
        "enrollment_rejected via dashboard: session=%s admin=%s",
        session_id, session.role,
    )
    return RedirectResponse(
        url="/proxy/enrollments?flash=Enrollment+rejected&flash_kind=success",
        status_code=303,
    )


# ─────────────────────────────────────────────────────────────────────────────
# HTMX badge fragments
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/badge/agents")
async def badge_agents(request: Request):
    """Return agent count badge fragment."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.db import list_agents
    agents = await list_agents()
    active = sum(1 for a in agents if a["is_active"])
    if active:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-teal-500/20 text-teal-400">{active}</span>'
        )
    return HTMLResponse("")


@router.get("/badge/enrollments")
async def badge_enrollments(request: Request):
    """Return pending enrollment count badge fragment."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.db import get_db as _get_db
    from mcp_proxy.enrollment import service as _enrollment_service

    try:
        async with _get_db() as conn:
            pending = await _enrollment_service.list_pending(conn)
    except Exception:  # table may not exist in pre-migrated setups
        return HTMLResponse("")

    count = len(pending)
    if count:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-amber-500/20 text-amber-400">{count}</span>'
        )
    return HTMLResponse("")


@router.get("/badge/users")
async def badge_users(request: Request):
    """Return user-principal count badge fragment for the sidebar."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")
    try:
        from mcp_proxy.db import count_user_principals
        n = await count_user_principals()
    except Exception:  # table may not exist in pre-migrated setups
        return HTMLResponse("")
    if n:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-accent-500/15 text-accent-400">{n}</span>'
        )
    return HTMLResponse("")


# ─────────────────────────────────────────────────────────────────────────────
# Users — control plane (Mastio) over the credential data plane (Frontdesk)
#
# The Mastio is the identity authority: it holds the principal registry,
# audit attribution, and the cert authority. It does NOT hold passwords.
# When the admin creates / resets / deletes a user from this dashboard,
# we forward the call to the Frontdesk Ambassador admin API (which owns
# users.db, bcrypt, lifecycle). The plaintext password is generated on
# the Mastio just-in-time, sent to the Frontdesk once over the loopback,
# surfaced to the admin once, and never persisted on this side.
# ─────────────────────────────────────────────────────────────────────────────

# Single source of truth for "is the Frontdesk wiring configured?". Used
# by both the page template (to hide Create/Reset/Delete) and the POST
# handlers (to short-circuit with a clear error rather than crashing).
def _frontdesk_admin_target() -> tuple[str, str] | None:
    from mcp_proxy.config import get_settings
    s = get_settings()
    url = (s.frontdesk_ambassador_url or "").strip().rstrip("/")
    secret = (s.frontdesk_admin_secret or "").strip()
    if not url or not secret:
        return None
    return url, secret


def _generate_temp_password() -> str:
    """16-char unambiguous random temp password.

    The admin reads this off the dashboard banner and dictates it to
    the user out-of-band, so the alphabet excludes characters that
    are easy to confuse visually: ``0/O``, ``1/l/I``, ``-/_``. 16 chars
    over an alphabet of ~50 distinct symbols still gives ~90 bits of
    entropy, well over what a one-shot bcrypt-hashed temp credential
    needs (the user is forced to rotate at first sign-in anyway).
    """
    import secrets
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(16))


async def _fetch_frontdesk_users() -> dict[str, dict] | None:
    """Pull the canale's user list. Keyed by ``user_name`` for join.

    Returns ``None`` if the Frontdesk is not configured or unreachable
    — callers should fall back to the Mastio-local view in that case
    rather than rendering an empty page.
    """
    target = _frontdesk_admin_target()
    if target is None:
        return None
    url, secret = target
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                f"{url}/admin/users",
                headers={"X-Admin-Secret": secret},
            )
        if r.status_code != 200:
            _log.warning(
                "frontdesk admin list failed: status=%s",
                r.status_code,
            )
            return None
        body = r.json()
    except Exception as exc:  # noqa: BLE001 — wire-level failure
        _log.warning("frontdesk admin list error: %s", exc)
        return None
    return {u["user_name"]: u for u in body.get("users", [])}


async def _frontdesk_admin_call(
    method: str,
    path: str,
    *,
    json_body: dict | None = None,
) -> tuple[int, dict | None, str | None]:
    """Thin httpx wrapper. Returns ``(status, json_or_none, error_str)``.

    ``error_str`` is None on transport success regardless of HTTP status;
    callers inspect ``status`` for app-level outcomes. A ``None`` body
    + non-None error means the call did not complete (DNS, connect,
    timeout) — surface a generic message, do not stringify the
    exception into the browser.
    """
    target = _frontdesk_admin_target()
    if target is None:
        return 0, None, "frontdesk_not_configured"
    url, secret = target
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.request(
                method,
                f"{url}{path}",
                headers={
                    "X-Admin-Secret": secret,
                    "Content-Type": "application/json",
                },
                json=json_body,
            )
    except Exception as exc:  # noqa: BLE001
        _log.warning("frontdesk admin call %s %s failed: %s", method, path, exc)
        return 0, None, "transport_error"
    body: dict | None = None
    try:
        body = r.json() if r.content else None
    except Exception:
        body = None
    return r.status_code, body, None


async def _build_user_view() -> tuple[list[dict], bool]:
    """Merge Mastio principal registry + Frontdesk users.db.

    Mastio rows (``local_user_principals``) carry cert + last_active +
    surface. Frontdesk rows carry the credential state (has_password,
    must_change_password, disabled). One physical user shows up in both
    when they have signed in at least once; pre-seeded users live only
    on the Frontdesk side until first CSR. The merged view favours the
    Mastio row for principal_id / cert / surface and fills credential
    state from the Frontdesk.
    """
    try:
        from mcp_proxy.db import list_user_principals
        mastio_rows = await list_user_principals()
    except Exception as exc:  # noqa: BLE001
        _log.warning("users_page: list_user_principals failed: %s", exc)
        mastio_rows = []

    fd_users = await _fetch_frontdesk_users()
    fd_enabled = fd_users is not None
    fd_users = fd_users or {}

    # Derive org_id once so we can synthesize a principal_id for
    # Frontdesk-only rows. Read from the Mastio config; falls back to
    # an empty string if not yet configured (early first-boot path).
    from mcp_proxy.db import get_config
    try:
        org_id = await get_config("org_id") or ""
    except Exception:
        org_id = ""

    merged: list[dict] = []
    seen_user_names: set[str] = set()

    for row in mastio_rows:
        user_name = row.get("user_name") or ""
        seen_user_names.add(user_name)
        fd = fd_users.get(user_name, {})
        merged.append({
            "principal_id": row.get("principal_id"),
            "user_name": user_name,
            "display_name": fd.get("display_name") or row.get("display_name") or "",
            "reach": row.get("reach"),
            "surface": row.get("surface"),
            "cert_thumbprint": row.get("cert_thumbprint"),
            "pubkey_thumbprint": row.get("pubkey_thumbprint"),
            "created_at": row.get("created_at"),
            "last_active_at": row.get("last_active_at"),
            "in_frontdesk": user_name in fd_users,
            "has_password": bool(fd) if fd_enabled else False,
            "must_change_password": bool(fd.get("must_change_password")),
            "disabled": bool(fd.get("disabled")),
            "password_changed_at": fd.get("password_changed_at"),
        })

    # Frontdesk-only rows (no Mastio cert yet). Synthesize a placeholder
    # principal_id so the detail link works; once the user signs in and
    # the CSR endpoint fires, the real Mastio row supersedes this entry.
    for user_name, fd in fd_users.items():
        if user_name in seen_user_names:
            continue
        principal_id = f"{org_id}::user::{user_name}" if org_id else f"::user::{user_name}"
        merged.append({
            "principal_id": principal_id,
            "user_name": user_name,
            "display_name": fd.get("display_name", ""),
            "reach": "intra",
            "surface": "frontdesk",
            "cert_thumbprint": None,
            "pubkey_thumbprint": None,
            "created_at": fd.get("created_at"),
            "last_active_at": None,
            "in_frontdesk": True,
            "has_password": True,
            "must_change_password": bool(fd.get("must_change_password")),
            "disabled": bool(fd.get("disabled")),
            "password_changed_at": fd.get("password_changed_at"),
        })

    # Newest first.
    merged.sort(
        key=lambda u: u.get("created_at") or "",
        reverse=True,
    )
    return merged, fd_enabled


def _split_principal_id(principal_id: str) -> tuple[str, str]:
    """Pull ``(org_id, user_name)`` out of ``<org>::user::<name>``.

    Tolerates a missing org prefix (synthetic ids from frontdesk-only
    rows) and returns empty strings rather than raising so the caller
    can decide whether to 404.
    """
    if "::user::" in principal_id:
        head, name = principal_id.split("::user::", 1)
        return head, name
    return "", ""


@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    """Merged identity view: Mastio registry × Frontdesk Ambassador."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    users, fd_enabled = await _build_user_view()

    # Banners survive one render via query string (POST-redirect-GET).
    new_user_name = request.query_params.get("new_user")
    new_user_temp_password = request.query_params.get("new_pw")
    action_message = request.query_params.get("ok")
    error = request.query_params.get("error")

    return templates.TemplateResponse("users.html", _ctx(
        request, session,
        active="users",
        users=users,
        frontdesk_enabled=fd_enabled,
        new_user_name=new_user_name,
        new_user_temp_password=new_user_temp_password,
        action_message=action_message,
        error=error,
    ))


@router.post("/users/create")
async def users_create(request: Request):
    """Create a user. Two paths depending on the deployment topology:

    1. **Frontdesk Ambassador configured** (``MCP_PROXY_FRONTDESK_AMBASSADOR_URL``
       set): the Mastio mints a one-time temp password, forwards it to the
       Frontdesk together with the user metadata, surfaces it to the admin
       on the redirect, and forgets it. The Frontdesk's ``users.db`` holds
       the bcrypt hash; the Mastio never logs the value anywhere.

    2. **Registry-only fallback** (no Frontdesk, no SSO): writes a row in
       ``local_user_principals`` without any credential. Used when the
       deployment authenticates clients via ADR-027 ``culk_*`` API tokens
       — the admin pre-creates the user principal here, then mints a
       Bearer token from the user detail page's API Tokens tab. No
       password, no IdP, no temp credential to distribute. Workable for
       VPS demos where the customer points LibreChat / Cursor / Cherry
       Studio at the Mastio with token auth.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse("/proxy/users?error=csrf", status_code=303)

    form = await request.form()
    user_name = (form.get("user_name") or "").strip()
    display_name = (form.get("display_name") or "").strip()
    if not user_name:
        return RedirectResponse(
            "/proxy/users?error=user_name+is+required",
            status_code=303,
        )

    # Registry-only fallback path — no Frontdesk to delegate to.
    if _frontdesk_admin_target() is None:
        from urllib.parse import quote
        from mcp_proxy.db import get_config, get_db, log_audit
        from sqlalchemy import text
        try:
            # Prefer app.state.agent_manager.org_id (set at lifespan
            # start, source of truth), fall back to proxy_config table
            # for legacy deployments that pre-date the agent_manager
            # singleton.
            mgr = getattr(request.app.state, "agent_manager", None)
            org_id = getattr(mgr, "org_id", None) if mgr is not None else None
            if not org_id:
                org_id = await get_config("org_id") or ""
            if not org_id:
                return RedirectResponse(
                    "/proxy/users?error=Mastio+org_id+not+initialised",
                    status_code=303,
                )
            principal_id = f"{org_id}::user::{user_name}"
            async with get_db() as conn:
                result = await conn.execute(
                    text(
                        "SELECT 1 FROM local_user_principals "
                        "WHERE principal_id = :pid"
                    ),
                    {"pid": principal_id},
                )
                if result.first() is not None:
                    return RedirectResponse(
                        f"/proxy/users?error=User+{user_name}+already+exists",
                        status_code=303,
                    )
                await conn.execute(
                    text(
                        """
                        INSERT INTO local_user_principals
                        (principal_id, user_name, display_name, reach,
                         surface, created_at)
                        VALUES (:pid, :uname, :dname, 'intra', 'registry',
                                datetime('now'))
                        """
                    ),
                    {
                        "pid": principal_id,
                        "uname": user_name,
                        "dname": display_name,
                    },
                )
            await log_audit(
                agent_id=(
                    getattr(session, "principal_id", None)
                    or getattr(session, "username", None)
                    or "dashboard-admin"
                ),
                action="user.create",
                status="success",
                details={
                    "event": "user.create",
                    "source": "registry-only",
                    "principal_id": principal_id,
                    "user_name": user_name,
                    "display_name": display_name,
                },
            )
            return RedirectResponse(
                f"/proxy/users/{quote(principal_id, safe='')}"
                "?ok=Registry+row+created+-+mint+an+API+token+to+grant+access",
                status_code=303,
            )
        except Exception as exc:  # noqa: BLE001
            _log.exception("users_create registry-only failed: %s", exc)
            return RedirectResponse(
                "/proxy/users?error=Failed+to+create+registry+row",
                status_code=303,
            )

    temp_password = _generate_temp_password()
    status_code, body, transport_err = await _frontdesk_admin_call(
        "POST",
        "/admin/users",
        json_body={
            "user_name": user_name,
            "password": temp_password,
            "must_change_password": True,
            "display_name": display_name,
        },
    )
    if transport_err:
        return RedirectResponse(
            "/proxy/users?error=Frontdesk+unreachable",
            status_code=303,
        )
    if status_code == 409:
        return RedirectResponse(
            f"/proxy/users?error=User+{user_name}+already+exists",
            status_code=303,
        )
    if status_code >= 400:
        # Surface a generic message; the Frontdesk's own log carries the
        # detailed error, the Mastio worker log carries the status code.
        detail = (body or {}).get("detail") if isinstance(body, dict) else None
        _log.warning(
            "users_create: frontdesk rejected status=%s detail=%s",
            status_code, detail,
        )
        return RedirectResponse(
            "/proxy/users?error=Frontdesk+rejected+the+request",
            status_code=303,
        )

    # Pre-seed the Mastio row so the principal is visible immediately,
    # not just after the first CSR. The Frontdesk-only fallback in
    # ``_build_user_view`` already handles this, but writing a Mastio
    # row earlier keeps the cert thumbprint slot stable across reloads.
    # Use the same admin path the existing ``/v1/admin/users`` endpoint
    # would.
    org_id = ""
    try:
        from mcp_proxy.db import get_config, get_db
        from sqlalchemy import text
        org_id = await get_config("org_id") or ""
        if org_id:
            principal_id = f"{org_id}::user::{user_name}"
            async with get_db() as conn:
                await conn.execute(
                    text(
                        """
                        INSERT OR IGNORE INTO local_user_principals
                        (principal_id, user_name, display_name, reach, surface, created_at)
                        VALUES (:pid, :uname, :dname, 'intra', 'frontdesk', datetime('now'))
                        """
                    ),
                    {"pid": principal_id, "uname": user_name, "dname": display_name},
                )
    except Exception as exc:  # noqa: BLE001 — pre-seed is best-effort
        _log.warning("users_create: mastio pre-seed failed: %s", exc)

    # Redirect to the per-user detail page rather than the list — the
    # banner with the one-time temp password lands where the admin is
    # most likely to dwell. Wave B G2 (audit 2026-05-11): the cleartext
    # password used to ride in ``?new_pw=`` and landed in nginx logs +
    # browser history + Referer headers. Now the redirect carries an
    # opaque single-consume ticket; the detail page resolves it
    # server-side and renders the password without ever putting it on
    # the wire as a URL parameter.
    from urllib.parse import quote
    from mcp_proxy.dashboard._pwd_tickets import mint_password_ticket
    target_pid = f"{org_id}::user::{user_name}" if org_id else f"::user::{user_name}"
    ticket = mint_password_ticket(temp_password)
    return RedirectResponse(
        f"/proxy/users/{quote(target_pid, safe='')}?new_pw_ticket={quote(ticket)}",
        status_code=303,
    )


@router.get("/users/{principal_id:path}", response_class=HTMLResponse)
async def user_detail_page(principal_id: str, request: Request):
    """Per-user detail: Mastio attribution + Frontdesk credential state + audit."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    users, fd_enabled = await _build_user_view()
    user = next(
        (u for u in users if u.get("principal_id") == principal_id),
        None,
    )
    if user is None:
        return RedirectResponse(
            "/proxy/users?error=user+not+found",
            status_code=303,
        )

    # Audit rows attributed to this principal id.
    audit_entries: list[dict] = []
    try:
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            result = await conn.execute(
                text(
                    "SELECT timestamp, action, tool_name, status, detail "
                    "  FROM audit_log "
                    " WHERE agent_id = :pid "
                    " ORDER BY timestamp DESC LIMIT 20"
                ),
                {"pid": principal_id},
            )
            audit_entries = [dict(r) for r in result.mappings().all()]
    except Exception as exc:  # noqa: BLE001
        _log.warning("user_detail_page: audit query failed: %s", exc)

    from mcp_proxy.db import get_config
    try:
        org_id = await get_config("org_id") or ""
        trust_domain = await get_config("trust_domain") or "cullis.local"
    except Exception:
        org_id, trust_domain = "", "cullis.local"

    # Wave B G2 (audit 2026-05-11) — resolve the single-consume tickets
    # carried in the redirect URL. Tickets pop on read; a refresh of
    # this page does not re-render the cleartext. Pre-fix the
    # cleartext rode in ``?new_pw=`` / ``?reset_pw=`` and landed in
    # nginx logs / browser history / Referer headers.
    from mcp_proxy.dashboard._pwd_tickets import consume_password_ticket
    reset_temp_password = consume_password_ticket(
        request.query_params.get("reset_pw_ticket")
    )
    new_user_temp_password = consume_password_ticket(
        request.query_params.get("new_pw_ticket")
    )
    # Back-compat: if a stale page has the old URL shape, still render
    # the cleartext but log a warning so operators notice.
    if reset_temp_password is None and request.query_params.get("reset_pw"):
        _log.warning(
            "user_detail_page: legacy reset_pw URL parameter received "
            "(post-G2 the create-user/reset-pwd handlers should redirect "
            "with reset_pw_ticket instead)",
        )
        reset_temp_password = request.query_params.get("reset_pw")
    if new_user_temp_password is None and request.query_params.get("new_pw"):
        _log.warning(
            "user_detail_page: legacy new_pw URL parameter received",
        )
        new_user_temp_password = request.query_params.get("new_pw")
    action_message = request.query_params.get("ok")
    error = request.query_params.get("error")

    # ADR-027 — show this user's API tokens inline + render the
    # one-time cleartext banner when ``?new_token=`` is set (the mint
    # POST redirects back here with the freshly-minted token in the
    # URL exactly once; if the operator reloads the page, the query
    # param is gone and the banner does not re-render).
    api_tokens: list[dict] = []
    try:
        from mcp_proxy.db import list_user_api_tokens
        api_tokens = await list_user_api_tokens(principal_id)
    except Exception as exc:  # noqa: BLE001
        _log.warning("user_detail_page: api_tokens query failed: %s", exc)
    new_api_token = request.query_params.get("new_token")
    new_api_token_label = request.query_params.get("new_token_label")
    api_token_error = request.query_params.get("token_error")

    return templates.TemplateResponse("user_detail.html", _ctx(
        request, session,
        active="users",
        user=user,
        audit_entries=audit_entries,
        org_id=org_id,
        trust_domain=trust_domain,
        frontdesk_enabled=fd_enabled,
        reset_temp_password=reset_temp_password,
        new_user_temp_password=new_user_temp_password,
        action_message=action_message,
        error=error,
        api_tokens=api_tokens,
        new_api_token=new_api_token,
        new_api_token_label=new_api_token_label,
        api_token_error=api_token_error,
    ))


@router.post("/users/{principal_id:path}/reset-password")
async def users_reset_password(principal_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=csrf",
            status_code=303,
        )
    if _frontdesk_admin_target() is None:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+not+configured",
            status_code=303,
        )

    _, user_name = _split_principal_id(principal_id)
    if not user_name:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=invalid+principal+id",
            status_code=303,
        )

    new_pw = _generate_temp_password()
    status_code, body, transport_err = await _frontdesk_admin_call(
        "POST",
        f"/admin/users/{user_name}/reset-password",
        json_body={"new_password": new_pw},
    )
    if transport_err:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+unreachable",
            status_code=303,
        )
    if status_code == 404:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=User+not+found+on+Frontdesk",
            status_code=303,
        )
    if status_code >= 400:
        _log.warning(
            "users_reset_password: frontdesk rejected status=%s",
            status_code,
        )
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Reset+failed",
            status_code=303,
        )

    # Wave B G2 — single-consume ticket instead of cleartext in URL.
    from urllib.parse import quote
    from mcp_proxy.dashboard._pwd_tickets import mint_password_ticket
    ticket = mint_password_ticket(new_pw)
    return RedirectResponse(
        f"/proxy/users/{quote(principal_id)}?reset_pw_ticket={quote(ticket)}",
        status_code=303,
    )


@router.post("/users/{principal_id:path}/delete")
async def users_delete(principal_id: str, request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=csrf",
            status_code=303,
        )
    if _frontdesk_admin_target() is None:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+not+configured",
            status_code=303,
        )

    _, user_name = _split_principal_id(principal_id)
    if not user_name:
        return RedirectResponse(
            "/proxy/users?error=invalid+principal+id",
            status_code=303,
        )

    status_code, _, transport_err = await _frontdesk_admin_call(
        "DELETE",
        f"/admin/users/{user_name}",
    )
    if transport_err:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Frontdesk+unreachable",
            status_code=303,
        )
    # 404 on the Frontdesk side means the Frontdesk row was already gone;
    # we still scrub the Mastio attribution row so the dashboard reflects
    # reality.
    if status_code not in (204, 404):
        _log.warning(
            "users_delete: frontdesk rejected status=%s",
            status_code,
        )
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Delete+failed+on+Frontdesk",
            status_code=303,
        )

    try:
        from mcp_proxy.db import get_db
        from sqlalchemy import text
        async with get_db() as conn:
            await conn.execute(
                text(
                    "DELETE FROM local_user_principals WHERE principal_id = :pid"
                ),
                {"pid": principal_id},
            )
    except Exception as exc:  # noqa: BLE001
        _log.warning("users_delete: mastio cleanup failed: %s", exc)

    from urllib.parse import quote
    return RedirectResponse(
        f"/proxy/users?ok=Deleted+{quote(user_name)}",
        status_code=303,
    )


@router.post("/users/{principal_id:path}/reset-tofu-pin")
async def users_reset_tofu_pin(principal_id: str, request: Request):
    """Clear the TOFU-pinned pubkey for a user principal.

    Recovery path for the v0.1 keystore-loss case: Connector wiped
    its on-disk keypair, customer rebuilt the laptop, or an early
    Mastio (pre-PR #656) ran with in-memory keys and lost the pin
    on restart. Operator confirms identity out-of-band, hits this
    button, the next CSR from the user is accepted regardless of
    pubkey and the fresh thumb gets repinned at signature time.

    Mastio-local: the TOFU pin lives only in ``local_user_principals``
    (the Frontdesk doesn't carry it). No Frontdesk bridge required.
    Audit chain captures the reset with action=``reset_tofu_pin``
    so an attacker who flips a real user's pin to their own pubkey
    is recoverable forensically.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=csrf",
            status_code=303,
        )

    _, user_name = _split_principal_id(principal_id)
    if not user_name:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=invalid+principal+id",
            status_code=303,
        )

    from mcp_proxy.db import clear_user_principal_pubkey_thumbprint, log_audit
    try:
        cleared = await clear_user_principal_pubkey_thumbprint(principal_id)
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "users_reset_tofu_pin: clear failed for %s: %s",
            principal_id, exc,
        )
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=Reset+failed",
            status_code=303,
        )

    if not cleared:
        return RedirectResponse(
            f"/proxy/users/{principal_id}?error=No+pin+to+clear",
            status_code=303,
        )

    operator = (
        getattr(session, "principal_id", None)
        or getattr(session, "username", None)
        or "dashboard-admin"
    )
    try:
        await log_audit(
            agent_id=principal_id,
            action="reset_tofu_pin",
            status="success",
            details={
                "operator": operator,
                "user_name": user_name,
            },
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "users_reset_tofu_pin: audit append failed for %s: %s",
            principal_id, exc,
        )

    return RedirectResponse(
        f"/proxy/users/{principal_id}?ok=TOFU+pin+cleared",
        status_code=303,
    )


@router.get("/badge/audit")
async def badge_audit(request: Request):
    """Return recent audit count badge fragment."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from sqlalchemy import text

    from mcp_proxy.db import get_db

    async with get_db() as db:
        result = await db.execute(
            text("SELECT COUNT(*) as cnt FROM audit_log WHERE timestamp > datetime('now', '-1 hour')")
        )
        row = result.mappings().first()
        count = row["cnt"] if row else 0

    if count:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-teal-500/20 text-teal-400">{count}</span>'
        )
    return HTMLResponse("")


@router.get("/badge/updates")
async def badge_updates(request: Request):
    """Return federation-update pending count badge fragment.

    Tint encodes the most severe pending criticality on the proxy:
      - red  → at least one ``critical`` pending migration.
      - amber → only ``warning`` / ``info`` migrations pending.
      - empty → no pending migrations.

    Counts all pending migrations regardless of severity so operators
    see the workload at a glance; the tint signals urgency.
    """
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    try:
        from mcp_proxy.db import get_pending_updates
        from mcp_proxy.updates import discover
    except Exception:
        return HTMLResponse("")

    migrations = discover()
    try:
        rows_by_id = {
            r["migration_id"]: r for r in await get_pending_updates()
        }
    except Exception:
        # Table may not exist yet on a pre-0019 deploy; the badge is
        # observability, not a correctness signal — degrade silent.
        return HTMLResponse("")

    critical_pending = 0
    other_pending = 0
    for m in migrations:
        row = rows_by_id.get(m.migration_id)
        if row is None or row["status"] != "pending":
            continue
        if m.criticality == "critical":
            critical_pending += 1
        else:
            other_pending += 1

    total = critical_pending + other_pending
    if not total:
        return HTMLResponse("")

    tint_cls = (
        "bg-red-500/20 text-red-400"
        if critical_pending
        else "bg-amber-500/20 text-amber-400"
    )
    return HTMLResponse(
        f'<span class="px-1.5 py-0.5 rounded-full text-xs {tint_cls}">'
        f'{total}</span>'
    )


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


@router.get("/badge/version")
async def badge_version(request: Request):
    """HTMX fragment — single-pixel-thin banner that says "Update
    available: 0.3.0-rc3" and links to the modal with the copy-paste
    install command. Empty response when no update is pending so the
    sidebar stays clean.

    M-dash-3 audit fix: every interpolated value is HTML-escaped
    before reaching the response. ``release_url``, ``latest``, and
    ``install_command`` come from the GitHub Releases API (or a tag
    name that an attacker who compromises the GHCR repo could craft)
    and used to be embedded raw in ``href=...`` / ``title=...`` /
    text-content positions, giving a stored-XSS surface against any
    operator viewing the dashboard.
    """
    import html as _html

    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.version_check import check_for_updates
    status = await check_for_updates()
    if not status.update_available or not status.install_command:
        return HTMLResponse("")

    # ``quote=True`` escapes ``"`` so attribute-context interpolations
    # cannot break out into new attributes.
    cmd = _html.escape(status.install_command, quote=True)
    latest = _html.escape(status.latest or "", quote=True)
    current = _html.escape(str(status.current), quote=True)
    release_url = _html.escape(status.release_url or "", quote=True)
    return HTMLResponse(
        f'<a href="{release_url}" target="_blank" rel="noopener" '
        f'class="block px-3 py-2 rounded text-xs font-mono '
        f'bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 transition" '
        f'title="Run ``{cmd}`` on the Mastio host to upgrade. '
        f'See release notes on GitHub.">'
        f'⤴ Update: <span class="font-semibold">{latest}</span> '
        f'<span class="opacity-60">(running {current})</span>'
        f'</a>'
    )


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
# OIDC login (Sign-in with SSO)
# ─────────────────────────────────────────────────────────────────────────────

def _oidc_redirect_uri(request: Request) -> str:
    """Build the OIDC callback URL.

    Prefers oidc_redirect_uri_base (browser-reachable URL the IdP has
    registered), then proxy_public_url (legacy single-knob deploys),
    then the request base URL for dev/test. The first two are distinct
    because proxy_public_url pins DPoP htu to the internal TLS sidecar
    (e.g. mastio-nginx:9443), which is not browser-reachable nor
    registered on the IdP — using it as redirect_uri yields a 400
    ``Invalid parameter: redirect_uri`` from Keycloak.
    """
    from mcp_proxy.config import get_settings as _s
    settings = _s()
    base = settings.oidc_redirect_uri_base or settings.proxy_public_url
    if base:
        return base.rstrip("/") + "/proxy/oidc/callback"
    return str(request.base_url).rstrip("/") + "/proxy/oidc/callback"


@router.get("/oidc/start")
async def oidc_start(request: Request):
    """Initiate the OIDC authorization-code + PKCE flow."""
    from mcp_proxy.dashboard.oidc import (
        OidcError,
        build_authorization_url,
        create_oidc_state,
        load_oidc_config,
    )
    from mcp_proxy.dashboard.session import set_oidc_state

    cfg = await load_oidc_config()
    if not cfg["issuer_url"] or not cfg["client_id"]:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "SSO is not configured on this proxy. Ask an administrator.",
            "oidc_enabled": False,
            "display_name": await _load_display_name(),
        }, status_code=400)

    flow_state = create_oidc_state()
    redirect_uri = _oidc_redirect_uri(request)

    try:
        auth_url = await build_authorization_url(
            cfg["issuer_url"], cfg["client_id"], redirect_uri, flow_state,
        )
    except OidcError as exc:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": f"SSO error: {exc}",
            "oidc_enabled": True,
            "display_name": await _load_display_name(),
        }, status_code=502)

    response = RedirectResponse(url=auth_url, status_code=303)
    set_oidc_state(response, flow_state.to_dict())
    return response


@router.get("/oidc/callback")
async def oidc_callback(request: Request):
    """Handle the IdP redirect: verify state, exchange code, set session."""
    import hmac as _hmac

    from mcp_proxy.dashboard.oidc import (
        OidcError,
        OidcFlowState,
        exchange_code_for_identity,
        load_oidc_config,
    )
    from mcp_proxy.dashboard.session import clear_oidc_state, get_oidc_state
    from mcp_proxy.db import log_audit

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    err = request.query_params.get("error")
    err_desc = request.query_params.get("error_description")

    def _login_err(msg: str, status: int = 400):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": msg,
            "oidc_enabled": True,
        }, status_code=status)

    if err:
        return _login_err(f"SSO provider error: {err_desc or err}")
    if not code or not state:
        return _login_err("Missing authorization code or state from SSO provider.")

    flow_data = get_oidc_state(request)
    if not flow_data:
        return _login_err("SSO session expired or invalid. Please try again.")
    if not _hmac.compare_digest(state, flow_data.get("state", "")):
        return _login_err("SSO state mismatch — possible CSRF attack.", status=403)

    cfg = await load_oidc_config()
    if not cfg["issuer_url"] or not cfg["client_id"]:
        return _login_err("SSO is not configured on this proxy.")

    flow_state = OidcFlowState.from_dict(flow_data)
    redirect_uri = _oidc_redirect_uri(request)

    try:
        identity = await exchange_code_for_identity(
            cfg["issuer_url"], cfg["client_id"], cfg["client_secret"] or None,
            redirect_uri, code, flow_state,
        )
    except OidcError as exc:
        _log.warning("OIDC callback failed: %s", exc)
        await log_audit(
            agent_id="admin",
            action="auth.oidc_login",
            status="error",
            detail=str(exc)[:200],
        )
        return _login_err(f"SSO authentication failed: {exc}", status=401)

    await log_audit(
        agent_id="admin",
        action="auth.oidc_login",
        status="success",
        detail=f"sub={identity.sub}, email={identity.email or '?'}, issuer={identity.issuer}",
    )

    response = RedirectResponse(url=await _post_login_redirect(), status_code=303)
    clear_oidc_state(response)
    set_session(response, role="admin")
    return response


async def _load_display_name() -> str:
    """Safe helper: org display name for the login page header."""
    from mcp_proxy.db import get_config
    try:
        return (await get_config("display_name")) or ""
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Federated-agents partial (accordion expansion) — REMOVED.
# The ``/proxy/agents`` accordion that consumed this partial was
# deleted in the reach-UX refactor (PR #224). Peer-org discovery
# now lives on ``/proxy/network``. The helper ``_federated_agents_rows``
# template was removed alongside.
# ─────────────────────────────────────────────────────────────────────────────
