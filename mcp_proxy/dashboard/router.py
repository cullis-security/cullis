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
    """Generate self-signed Org CA. Returns (cert_pem, key_pem)."""
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
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
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
    oidc_enabled = await is_oidc_configured()
    display_name = await _load_display_name()

    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
        "oidc_enabled": oidc_enabled,
        "display_name": display_name,
    })


@router.post("/login")
async def login_submit(request: Request):
    # State guard: if no password is set, you can't sign in — go register first.
    if not await is_admin_password_set():
        return RedirectResponse(url="/proxy/register", status_code=303)

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
        from mcp_proxy.db import log_audit
        await log_audit(
            agent_id="admin",
            action="auth.login",
            status="error",
            detail="invalid password",
        )
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid password.",
        }, status_code=401)

    from mcp_proxy.db import log_audit
    await log_audit(
        agent_id="admin",
        action="auth.login",
        status="success",
    )

    response = RedirectResponse(url=await _post_login_redirect(), status_code=303)
    set_session(response, role="admin")
    return response


@router.post("/logout")
async def logout(request: Request):
    session = get_session(request)
    if session and session.logged_in:
        await verify_csrf(request, session)
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
        detail="admin password initialized",
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

    from mcp_proxy.db import get_config
    broker_url    = await get_config("broker_url") or ""
    invite_token  = await get_config("invite_token") or ""
    org_id        = await get_config("org_id") or ""
    display_name  = await get_config("display_name") or ""
    contact_email = await get_config("contact_email") or ""
    webhook_url   = await get_config("webhook_url") or ""
    has_ca        = bool(await get_config("org_ca_cert"))
    vault_addr    = await get_config("vault_addr") or ""
    vault_enabled = bool(vault_addr)

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

    from mcp_proxy.db import set_config, get_config, log_audit

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


@router.post("/setup/test-connection")
async def setup_test_connection(request: Request):
    """HTMX endpoint: test broker connectivity."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return HTMLResponse('<span class="text-red-400">Not authenticated</span>')

    form = await request.form()
    broker_url = str(form.get("broker_url", "")).strip()

    if not broker_url:
        return HTMLResponse(
            '<span class="text-red-400">Enter a broker URL first</span>'
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
            f'<span class="text-red-400">Connection failed: {exc}</span>'
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

    # Federated peers grouped by org. Read-only view over the Phase 4b
    # cache — safe to show even when the subscriber is not running (rows
    # are simply stale, not wrong). Accordion expansion is wired via a
    # HTMX partial at /proxy/agents/federated/{org}.
    own_org_id = await get_config("org_id") or ""
    federated_orgs = await _load_federated_orgs(exclude_org=own_org_id)
    open_orgs = _parse_open_orgs(request.query_params.get("open"))

    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        org_status=org_status,
        has_ca=has_ca,
        new_api_key=None,
        new_agent_id=None,
        federated_orgs=federated_orgs,
        open_orgs=open_orgs,
    ))


def _parse_open_orgs(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {p.strip() for p in raw.split(",") if p.strip()}


async def _load_federated_orgs(exclude_org: str = "") -> list[dict]:
    """Aggregate cached federated agents by org_id.

    Returns a list of dicts: {org_id, display_name, agent_count, last_updated_at}.
    Display name falls back to the org_id when the cache has no display
    name cached (Phase 4b only stores agent-level names).
    """
    from sqlalchemy import text as _text

    from mcp_proxy.db import get_db as _get_db

    try:
        async with _get_db() as conn:
            result = await conn.execute(
                _text(
                    "SELECT org_id, COUNT(*) AS agent_count, "
                    "MAX(updated_at) AS last_updated_at "
                    "FROM cached_federated_agents "
                    "WHERE revoked = 0 AND org_id != :own "
                    "GROUP BY org_id ORDER BY org_id"
                ),
                {"own": exclude_org},
            )
            rows = result.mappings().all()
    except Exception:
        return []

    return [
        {
            "org_id": r["org_id"],
            "display_name": r["org_id"],
            "agent_count": int(r["agent_count"] or 0),
            "last_updated_at": r["last_updated_at"],
        }
        for r in rows
    ]


@router.post("/agents/create")
async def agents_create(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import list_agents, create_agent as db_create_agent, log_audit, get_config
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
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
            new_api_key=None,
            new_agent_id=None,
        ))

    capabilities = [c.strip() for c in capabilities_raw.split(",") if c.strip()]

    # Determine org_id from config or settings
    org_id = await get_config("org_id") or get_settings().org_id

    # Try to use AgentManager with full x509 cert generation
    try:
        mgr = AgentManager(org_id=org_id)
        ca_loaded = await mgr.load_org_ca_from_config()

        if ca_loaded:
            # Full creation: x509 cert + API key + Vault storage + broker registration
            agent_info, raw_key = await mgr.create_agent(agent_name, display_name, capabilities)
            agent_id = agent_info["agent_id"]
            creation_mode = "x509+api_key"
        else:
            # Fallback: API key only (no cert — CA not configured)
            raw_key = generate_api_key(agent_name)
            key_hash = hash_api_key(raw_key)
            agent_id = f"{org_id}::{agent_name}" if org_id else f"proxy::{agent_name}"
            await db_create_agent(
                agent_id=agent_id,
                display_name=display_name,
                capabilities=capabilities,
                api_key_hash=key_hash,
            )
            creation_mode = "api_key_only"
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
            new_api_key=None,
            new_agent_id=None,
        ))

    await log_audit(
        agent_id=agent_id,
        action="agent.create",
        status="success",
        detail=f"display_name={display_name}, capabilities={capabilities}, mode={creation_mode}",
    )

    # Register agent with broker and create binding (best-effort)
    broker_url = await get_config("broker_url")
    org_id_cfg = await get_config("org_id")
    org_secret = await get_config("org_secret")

    if broker_url and org_id_cfg and org_secret:
        headers = {"X-Org-Id": org_id_cfg, "X-Org-Secret": org_secret}
        try:
            from mcp_proxy.config import broker_tls_verify
            async with httpx.AsyncClient(
                verify=broker_tls_verify(get_settings()), timeout=10.0,
            ) as http:
                # 1. Register agent
                await http.post(f"{broker_url}/v1/registry/agents", json={
                    "agent_id": agent_id,
                    "org_id": org_id_cfg,
                    "display_name": display_name,
                    "capabilities": capabilities,
                }, headers=headers)

                # 2. Create binding
                resp = await http.post(f"{broker_url}/v1/registry/bindings", json={
                    "org_id": org_id_cfg,
                    "agent_id": agent_id,
                    "scope": capabilities,
                }, headers=headers)

                # 3. Auto-approve binding
                if resp.status_code == 201:
                    binding_data = resp.json()
                    binding_id = binding_data.get("id")
                    if binding_id:
                        await http.post(
                            f"{broker_url}/v1/registry/bindings/{binding_id}/approve",
                            headers=headers,
                        )

                await log_audit(
                    agent_id=agent_id,
                    action="agent.broker_bind",
                    status="success",
                    detail=f"broker={broker_url}",
                )
        except Exception as exc:
            _log.warning("Broker binding for %s failed: %s", agent_id, exc)
            await log_audit(
                agent_id=agent_id,
                action="agent.broker_bind",
                status="error",
                detail=f"broker={broker_url}, error={exc}",
            )

    agents = await list_agents()
    org_status = await get_config("org_status") or ""
    has_ca = bool(await get_config("org_ca_cert"))
    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        org_status=org_status,
        has_ca=has_ca,
        new_api_key=raw_key,
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
    api_key_display = f"sk_local_{agent_name}_..."

    return templates.TemplateResponse("agent_detail.html", _ctx(
        request, session,
        active="agents",
        agent=agent,
        audit_entries=audit_entries,
        new_api_key=None,
        proxy_url=proxy_url,
        broker_url=broker_url,
        org_id=org_id,
        agent_name=agent_name,
        api_key_display=api_key_display,
    ))


@router.post("/agents/{agent_id:path}/rotate-key")
async def agent_rotate_key(request: Request, agent_id: str):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import get_agent, get_config, get_db, log_audit
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Extract the base name from agent_id (proxy::name -> name)
    base_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id
    raw_key = generate_api_key(base_name)
    key_hash = hash_api_key(raw_key)

    from sqlalchemy import text

    async with get_db() as db:
        await db.execute(
            text("UPDATE internal_agents SET api_key_hash = :api_key_hash WHERE agent_id = :agent_id"),
            {"api_key_hash": key_hash, "agent_id": agent_id},
        )

    await log_audit(
        agent_id=agent_id,
        action="agent.rotate_key",
        status="success",
    )

    # Re-fetch agent and audit
    agent = await get_agent(agent_id)
    async with get_db() as db:
        result = await db.execute(
            text("SELECT * FROM audit_log WHERE agent_id = :agent_id ORDER BY timestamp DESC LIMIT 20"),
            {"agent_id": agent_id},
        )
        audit_entries = [dict(row) for row in result.mappings().all()]

    # Extra context for integration snippets (show real key after rotation)
    from mcp_proxy.config import get_settings
    settings = get_settings()
    proxy_url = settings.proxy_public_url or f"http://localhost:{settings.port}"
    broker_url = await get_config("broker_url") or ""
    org_id = await get_config("org_id") or settings.org_id
    agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id
    api_key_display = raw_key  # Show real key in snippets right after rotation

    return templates.TemplateResponse("agent_detail.html", _ctx(
        request, session,
        active="agents",
        agent=agent,
        audit_entries=audit_entries,
        new_api_key=raw_key,
        proxy_url=proxy_url,
        broker_url=broker_url,
        org_id=org_id,
        agent_name=agent_name,
        api_key_display=api_key_display,
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
CULLIS_PROXY_URL={proxy_url}
CULLIS_API_KEY=sk_local_{agent_name}_YOUR_KEY_HERE
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

    from mcp_proxy.db import get_agent, get_config, get_db, log_audit

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

    # Best-effort: unregister from broker
    broker_url = await get_config("broker_url")
    org_id = await get_config("org_id")
    org_secret = await get_config("org_secret")
    if broker_url and org_id and org_secret:
        try:
            from mcp_proxy.config import get_settings as _s, broker_tls_verify
            async with httpx.AsyncClient(
                verify=broker_tls_verify(_s()), timeout=5.0,
            ) as http:
                await http.delete(
                    f"{broker_url}/v1/registry/agents/{agent_id}",
                    headers={"X-Org-Id": org_id, "X-Org-Secret": org_secret},
                )
        except Exception:
            pass

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
    include_own_org = request.query_params.get("include_own_org") == "on"
    querier = (request.query_params.get("querier") or "").strip() or None
    submitted = any(k in request.query_params for k in ("q", "pattern", "org_id", "capabilities"))

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

    if submitted:
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
        submitted=submitted,
        agents=agents,
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
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return HTMLResponse('<span class="text-red-400">Not authenticated</span>')

    form = await request.form()
    webhook_url = str(form.get("pdp_url", "")).strip()

    if not webhook_url:
        return HTMLResponse('<span class="text-red-400">Enter a webhook URL first</span>')

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
            f'<span class="text-red-400">Connection failed: {exc}</span>'
        )


# ─────────────────────────────────────────────────────────────────────────────
# Audit
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_db, list_agents

    # Query parameters
    agent_filter = request.query_params.get("agent", "")
    action_filter = request.query_params.get("action", "")
    status_filter = request.query_params.get("status", "")
    page = int(request.query_params.get("page", "1"))
    per_page = 50

    # Build query
    from sqlalchemy import text

    conditions: list[str] = []
    params: dict[str, object] = {}
    if agent_filter:
        conditions.append("agent_id = :agent_id")
        params["agent_id"] = agent_filter
    if action_filter:
        conditions.append("action = :action")
        params["action"] = action_filter
    if status_filter:
        conditions.append("status = :status")
        params["status"] = status_filter

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    async with get_db() as db:
        # Count total
        result = await db.execute(
            text(f"SELECT COUNT(*) as cnt FROM audit_log{where}"), params,
        )
        row = result.mappings().first()
        total = row["cnt"] if row else 0

        # Fetch page
        offset = (page - 1) * per_page
        page_params = {**params, "limit": per_page, "offset": offset}
        result = await db.execute(
            text(f"SELECT * FROM audit_log{where} ORDER BY timestamp DESC LIMIT :limit OFFSET :offset"),
            page_params,
        )
        entries = [dict(r) for r in result.mappings().all()]

    # Distinct agents and actions for filter dropdowns
    agents = await list_agents()
    agent_ids = sorted(set(a["agent_id"] for a in agents))

    total_pages = max(1, (total + per_page - 1) // per_page)

    return templates.TemplateResponse("audit.html", _ctx(
        request, session,
        active="audit",
        entries=entries,
        agent_ids=agent_ids,
        agent_filter=agent_filter,
        action_filter=action_filter,
        status_filter=status_filter,
        page=page,
        total_pages=total_pages,
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
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return HTMLResponse('<span class="text-red-400">Not authenticated</span>')

    form = await request.form()
    vault_addr = str(form.get("vault_addr", "")).strip()
    vault_token = str(form.get("vault_token", "")).strip()

    if not vault_addr:
        return HTMLResponse('<span class="text-red-400">Enter a Vault address first</span>')

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
    return HTMLResponse(f'<span class="text-red-400">{msg}</span>')


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

    from mcp_proxy.dashboard.oidc import load_oidc_config

    cfg = await load_oidc_config()
    return templates.TemplateResponse("settings.html", _ctx(
        request, session,
        active="settings",
        issuer_url=cfg["issuer_url"],
        client_id=cfg["client_id"],
        has_client_secret=bool(cfg["client_secret"]),
        error=None,
        success=None,
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
        cfg = await load_oidc_config()
        return templates.TemplateResponse("settings.html", _ctx(
            request, session,
            active="settings",
            issuer_url=issuer_url or cfg["issuer_url"],
            client_id=client_id or cfg["client_id"],
            has_client_secret=bool(cfg["client_secret"]),
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

    cfg = await load_oidc_config()
    return templates.TemplateResponse("settings.html", _ctx(
        request, session,
        active="settings",
        issuer_url=cfg["issuer_url"],
        client_id=cfg["client_id"],
        has_client_secret=bool(cfg["client_secret"]),
        error=None,
        success="OIDC configuration saved.",
    ))


# ─────────────────────────────────────────────────────────────────────────────
# OIDC login (Sign-in with SSO)
# ─────────────────────────────────────────────────────────────────────────────

def _oidc_redirect_uri(request: Request) -> str:
    """Build the OIDC callback URL.

    Prefers the configured proxy_public_url (so the IdP sees a stable
    externally-reachable URL), falls back to the request base URL for
    dev/test environments.
    """
    from mcp_proxy.config import get_settings as _s
    pub = _s().proxy_public_url
    if pub:
        return pub.rstrip("/") + "/proxy/oidc/callback"
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
# Federated-agents partial (accordion expansion)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/federated/{org_id}", response_class=HTMLResponse)
async def federated_org_agents(request: Request, org_id: str):
    """HTMX partial: list the cached federated agents for a given peer org.

    Rendered inside the accordion row when the user expands it. Returns
    an empty fragment (never an error page) on missing cache or unknown
    org so the accordion degrades gracefully.
    """
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("", status_code=401)

    from sqlalchemy import text as _text
    from mcp_proxy.db import get_db as _get_db

    rows: list[dict] = []
    try:
        async with _get_db() as conn:
            result = await conn.execute(
                _text(
                    "SELECT agent_id, display_name, capabilities, revoked, updated_at "
                    "FROM cached_federated_agents WHERE org_id = :org "
                    "ORDER BY agent_id"
                ),
                {"org": org_id},
            )
            for r in result.mappings().all():
                try:
                    caps = json.loads(r["capabilities"] or "[]")
                except Exception:
                    caps = []
                rows.append({
                    "agent_id": r["agent_id"],
                    "display_name": r["display_name"] or r["agent_id"],
                    "capabilities": caps,
                    "revoked": bool(r["revoked"]),
                    "updated_at": r["updated_at"],
                })
    except Exception:
        rows = []

    return templates.TemplateResponse("_federated_agents_rows.html", {
        "request": request,
        "agents": rows,
        "org_id": org_id,
    })
