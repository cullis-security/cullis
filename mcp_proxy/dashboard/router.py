"""
MCP Proxy Dashboard — admin control plane for managing agents, tools, and policies.

Routes:
  /proxy/login          — Login with broker URL + invite token
  /proxy/logout         — Clear session
  /proxy/register       — Org registration (CA generation, broker onboarding)
  /proxy/setup          — First-time setup wizard (broker URL, org ID, org secret, CA, Vault)
  /proxy/agents         — Internal agent management
  /proxy/tools          — Tool registry viewer
  /proxy/policies       — Policy editor
  /proxy/audit          — Audit log viewer
  /proxy/pki            — PKI overview (Org CA info, agent cert stats)
  /proxy/vault          — Vault connection management
  /proxy/org-status     — HTMX org status polling
"""
import json
import logging
import pathlib
import re
import secrets
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
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
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
    path = f"secret/data/mcp-proxy/{org_id}/org-ca"
    url = f"{vault_addr.rstrip('/')}/v1/{path}"
    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
        resp = await client.post(
            url,
            json={"data": {"key_pem": key_pem}},
            headers={"X-Vault-Token": vault_token},
        )
        resp.raise_for_status()


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    session = get_session(request)
    if session.logged_in:
        from mcp_proxy.db import get_config
        org_id = await get_config("org_id")
        if org_id:
            return RedirectResponse(url="/proxy/agents", status_code=303)
        return RedirectResponse(url="/proxy/register", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login_submit(request: Request):
    from mcp_proxy.db import set_config, get_config

    form = await request.form()
    broker_url = str(form.get("broker_url", "")).strip().rstrip("/")
    invite_token = str(form.get("invite_token", "")).strip()

    if not broker_url:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Broker URL is required.",
        })
    if not invite_token:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invite token is required.",
        })

    # Test broker connectivity
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            resp = await client.get(f"{broker_url}/.well-known/jwks.json")
            if resp.status_code != 200:
                return templates.TemplateResponse("login.html", {
                    "request": request,
                    "error": f"Broker returned HTTP {resp.status_code}. Check the URL.",
                })
    except Exception:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Cannot reach broker at this URL.",
        })

    # Save broker config
    await set_config("broker_url", broker_url)
    await set_config("invite_token", invite_token)

    # Set session
    org_id = await get_config("org_id")
    if org_id:
        redirect_url = "/proxy/agents"
    else:
        redirect_url = "/proxy/register"

    response = RedirectResponse(url=redirect_url, status_code=303)
    set_session(response, role="admin")
    return response


@router.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(url="/proxy/login", status_code=303)
    clear_session(response)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Organization Registration
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import get_config
    # Already registered? Go to agents.
    org_id = await get_config("org_id")
    if org_id:
        return RedirectResponse(url="/proxy/agents", status_code=303)

    return templates.TemplateResponse("register.html", _ctx(
        request, session,
        error=None,
    ))


@router.post("/register")
async def register_submit(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import set_config, get_config, log_audit

    form = await request.form()
    org_id = str(form.get("org_id", "")).strip().lower()
    display_name = str(form.get("display_name", "")).strip()
    contact_email = str(form.get("contact_email", "")).strip()
    webhook_url = str(form.get("webhook_url", "")).strip()

    # If no webhook URL provided, use the built-in PDP from config/env
    if not webhook_url:
        import os
        webhook_url = os.environ.get("MCP_PROXY_PDP_URL", "")
        if not webhook_url:
            webhook_url = await get_config("pdp_webhook_url") or ""

    # Validate
    errors: list[str] = []
    if not org_id:
        errors.append("Organization ID is required.")
    elif not re.match(r"^[a-z][a-z0-9_-]*$", org_id):
        errors.append("Org ID must start with a letter and contain only lowercase letters, digits, hyphens, underscores.")
    if not display_name:
        errors.append("Display name is required.")
    if not contact_email:
        errors.append("Contact email is required.")

    if errors:
        return templates.TemplateResponse("register.html", _ctx(
            request, session,
            error=" ".join(errors),
            form_org_id=org_id,
            form_display_name=display_name,
            form_contact_email=contact_email,
            form_webhook_url=webhook_url,
        ))

    # Generate org secret and CA
    org_secret = secrets.token_urlsafe(32)
    ca_cert_pem, ca_key_pem = generate_org_ca(org_id)

    # Save locally first
    await set_config("org_id", org_id)
    await set_config("org_secret", org_secret)
    await set_config("org_ca_cert", ca_cert_pem)
    await set_config("org_ca_key", ca_key_pem)

    await log_audit(
        agent_id="admin",
        action="ca.generate",
        status="success",
        detail=f"org_id={org_id}, self-signed RSA-4096, valid 10 years",
    )

    # Call broker /onboarding/join
    broker_url = await get_config("broker_url")
    invite_token = await get_config("invite_token")

    if not broker_url or not invite_token:
        return templates.TemplateResponse("register.html", _ctx(
            request, session,
            error="Broker URL or invite token not configured. Please log in again.",
        ))

    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as http:
            resp = await http.post(f"{broker_url}/v1/onboarding/join", json={
                "org_id": org_id,
                "display_name": display_name,
                "secret": org_secret,
                "ca_certificate": ca_cert_pem,
                "contact_email": contact_email,
                "webhook_url": webhook_url,
                "invite_token": invite_token,
            })

            if resp.status_code == 202:
                await set_config("org_status", "pending")
                await log_audit(
                    agent_id="admin",
                    action="org.register",
                    status="success",
                    detail=f"org_id={org_id}, broker={broker_url}, status=pending",
                )
                return RedirectResponse(url="/proxy/agents", status_code=303)
            elif resp.status_code == 403:
                error_msg = "Invalid or expired invite token."
            elif resp.status_code == 409:
                error_msg = "Organization already registered on this broker."
            else:
                error_msg = f"Broker returned HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as exc:
        error_msg = f"Cannot reach broker: {exc}"

    await log_audit(
        agent_id="admin",
        action="org.register",
        status="error",
        detail=f"org_id={org_id}, error={error_msg}",
    )

    return templates.TemplateResponse("register.html", _ctx(
        request, session,
        error=error_msg,
        form_org_id=org_id,
        form_display_name=display_name,
        form_contact_email=contact_email,
        form_webhook_url=webhook_url,
    ))


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
        async with httpx.AsyncClient(verify=False, timeout=5.0) as http:
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
    broker_url = await get_config("broker_url") or ""
    org_id = await get_config("org_id") or ""
    has_ca = bool(await get_config("org_ca_cert"))
    vault_addr = await get_config("vault_addr") or ""
    vault_enabled = bool(vault_addr)

    return templates.TemplateResponse("setup.html", _ctx(
        request, session,
        active="setup",
        broker_url=broker_url,
        org_id=org_id,
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

    from mcp_proxy.db import set_config, get_config, log_audit

    form = await request.form()
    broker_url = str(form.get("broker_url", "")).strip()
    org_id = str(form.get("org_id", "")).strip()
    org_secret = str(form.get("org_secret", "")).strip()
    org_ca_mode = str(form.get("org_ca_mode", "skip")).strip()
    ca_key_pem = str(form.get("ca_key_pem", "")).strip()
    ca_cert_pem = str(form.get("ca_cert_pem", "")).strip()
    vault_enabled = bool(form.get("vault_enabled"))
    vault_addr = str(form.get("vault_addr", "")).strip()
    vault_token = str(form.get("vault_token", "")).strip()

    errors: list[str] = []
    if not broker_url:
        errors.append("Broker URL is required.")
    if not org_id:
        errors.append("Organization ID is required.")
    if not org_secret:
        errors.append("Organization secret is required.")

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
            org_id=org_id,
            has_ca=has_ca,
            vault_addr=vault_addr,
            vault_enabled=vault_enabled,
            errors=errors,
        ))

    # Save broker + org config
    await set_config("broker_url", broker_url)
    await set_config("org_id", org_id)
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
        action="setup.complete",
        status="success",
        detail=f"broker_url={broker_url}, org_id={org_id}, ca_mode={org_ca_mode}, vault={'yes' if vault_enabled else 'no'}",
    )

    has_ca = bool(await get_config("org_ca_cert"))
    return templates.TemplateResponse("setup.html", _ctx(
        request, session,
        active="setup",
        broker_url=broker_url,
        org_id=org_id,
        has_ca=has_ca,
        vault_addr=vault_addr if vault_enabled else "",
        vault_enabled=vault_enabled,
        success=True,
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

@router.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.db import list_agents, get_config
    agents = await list_agents()
    org_status = await get_config("org_status") or ""
    has_ca = bool(await get_config("org_ca_cert"))

    return templates.TemplateResponse("agents.html", _ctx(
        request, session,
        active="agents",
        agents=agents,
        org_status=org_status,
        has_ca=has_ca,
        new_api_key=None,
        new_agent_id=None,
    ))


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
            async with httpx.AsyncClient(verify=False, timeout=10.0) as http:
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
    from mcp_proxy.db import get_db
    import aiosqlite
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 20",
            (agent_id,),
        )
        rows = await cursor.fetchall()
        audit_entries = [dict(row) for row in rows]

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

    import aiosqlite
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        await db.execute(
            "UPDATE internal_agents SET api_key_hash = ? WHERE agent_id = ?",
            (key_hash, agent_id),
        )
        await db.commit()

    await log_audit(
        agent_id=agent_id,
        action="agent.rotate_key",
        status="success",
    )

    # Re-fetch agent and audit
    agent = await get_agent(agent_id)
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 20",
            (agent_id,),
        )
        rows = await cursor.fetchall()
        audit_entries = [dict(row) for row in rows]

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

    from mcp_proxy.db import get_agent, get_db, log_audit, get_config
    import aiosqlite

    agent = await get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Delete from local DB
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        await db.execute("DELETE FROM internal_agents WHERE agent_id = ?", (agent_id,))
        # Also remove stored key from proxy_config if present
        await db.execute("DELETE FROM proxy_config WHERE key = ?", (f"agent_key:{agent_id}",))
        await db.commit()

    # Best-effort: unregister from broker
    broker_url = await get_config("broker_url")
    org_id = await get_config("org_id")
    org_secret = await get_config("org_secret")
    if broker_url and org_id and org_secret:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as http:
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
    conditions: list[str] = []
    params: list[str] = []
    if agent_filter:
        conditions.append("agent_id = ?")
        params.append(agent_filter)
    if action_filter:
        conditions.append("action = ?")
        params.append(action_filter)
    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    import aiosqlite
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        # Count total
        cursor = await db.execute(f"SELECT COUNT(*) as cnt FROM audit_log{where}", params)
        row = await cursor.fetchone()
        total = row["cnt"] if row else 0

        # Fetch page
        offset = (page - 1) * per_page
        cursor = await db.execute(
            f"SELECT * FROM audit_log{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            [*params, per_page, offset],
        )
        rows = await cursor.fetchall()
        entries = [dict(r) for r in rows]

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
    import aiosqlite
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM proxy_config WHERE key LIKE 'agent_key:%'"
        )
        row = await cursor.fetchone()
        local_key_count = row["cnt"] if row else 0

    # Test vault status if configured
    vault_status = None
    vault_key_count = 0
    if vault_addr and vault_token:
        import httpx
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
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

    # Find all agent keys stored in proxy_config (agent_key:* pattern)
    import aiosqlite
    migrated = 0
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT key, value FROM proxy_config WHERE key LIKE 'agent_key:%'"
        )
        rows = await cursor.fetchall()

    for row in rows:
        agent_id = row["key"].replace("agent_key:", "", 1)
        key_pem = row["value"]
        path = f"secret/data/mcp-proxy/agents/{agent_id}"
        url = f"{vault_addr.rstrip('/')}/v1/{path}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
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


@router.get("/badge/audit")
async def badge_audit(request: Request):
    """Return recent audit count badge fragment."""
    session = get_session(request)
    if not session.logged_in:
        return HTMLResponse("")

    from mcp_proxy.db import get_db
    import aiosqlite
    import time as _time
    one_hour_ago = _time.time() - 3600

    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM audit_log WHERE timestamp > datetime('now', '-1 hour')"
        )
        row = await cursor.fetchone()
        count = row["cnt"] if row else 0

    if count:
        return HTMLResponse(
            f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-teal-500/20 text-teal-400">{count}</span>'
        )
    return HTMLResponse("")
