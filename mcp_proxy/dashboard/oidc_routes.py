"""Mastio dashboard — OIDC sub-router.

Sprint F-B-201 PR-9 of 10. Extracts the OIDC handshake (authorization-code +
PKCE start + IdP callback) from the ``mcp_proxy/dashboard/router.py``
god-object. Two routes total.

The OIDC primitives (state machine, token exchange, JWKS verify) live in
the sibling ``mcp_proxy/dashboard/oidc.py`` module — this file only wires
those primitives into the dashboard HTTP surface.

Mounted via ``router.include_router(oidc_routes.router)``.

Routes (2):

  GET /proxy/oidc/start     redirect the admin browser to the IdP authn URL
  GET /proxy/oidc/callback  verify IdP redirect, exchange code, set session
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Request
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard._helpers import _load_display_name, _post_login_redirect
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import set_session

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-oidc"])


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
