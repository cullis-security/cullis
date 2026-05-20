"""Mastio dashboard — Setup wizard sub-router.

Sprint F-B-201 PR-3 of 10. Extracts the broker-uplink wizard surface
(``/proxy/setup`` GET + POST + ``/proxy/setup/test-connection`` HTMX)
from ``mcp_proxy/dashboard/router.py``.

Mounted via ``router.include_router(setup_routes.router)``.

Routes (3):

  GET  /proxy/setup                   wizard form (broker uplink + org details)
  POST /proxy/setup                   submit handler with standalone branch
  POST /proxy/setup/test-connection   HTMX connectivity probe

ADR-014 PR-E1: standalone Mastio derives ``org_id`` from the in-memory
CA, never from the form. Federation flow (broker_url + invite_token +
``/onboarding``) is out of scope here; PR-E2 moves it to its own surface.

Shared helpers ``generate_org_ca``, ``_test_vault_connectivity``,
``_store_ca_key_in_vault``, ``_ctx``, ``_enforce_safe_outbound_url``,
``_load_display_name`` live in ``mcp_proxy/dashboard/_helpers.py``
(F-B-201 PR-1 / PR-2 / PR-3).
"""
from __future__ import annotations

import logging
import pathlib

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._helpers import (
    _ctx,
    _enforce_safe_outbound_url,
    _load_display_name,
    _store_ca_key_in_vault,
    _test_vault_connectivity,
    generate_org_ca,
)
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
    verify_csrf,
)

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-setup"])


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
