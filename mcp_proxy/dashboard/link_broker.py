"""Runtime uplink from a standalone proxy to a broker (ADR-006 Fase 2 / PR #6).

The ``/setup`` flow in ``router.py`` handles the first-boot wizard and
*requires a pod restart* to actually activate the BrokerBridge. For the
Trojan Horse upsell — an operator flipping an already-running standalone
proxy into federated mode — that restart is the difference between "try
it, it just works" and "file a ticket for the devops team".

This module adds ``POST /v1/admin/link-broker`` (admin-auth + CSRF) and a
dashboard form ``GET /proxy/link-broker``. The handler runs the same
attach-ca HTTP call the setup wizard uses, persists the config, then
**hot-swaps** the BrokerBridge in ``app.state`` so every subsequent
request sees the uplinked bridge — without the asgi process ever
restarting.

Invariants kept during hot-swap:
  - The old BrokerBridge's CullisClient cache is drained via
    ``bridge.shutdown()`` before the new one takes its place.
  - The old reverse-proxy httpx client (if any) is closed before being
    replaced. One leaked AsyncClient per swap would bloat memory on
    every link/unlink cycle.
  - ``app.state.org_id`` is kept in sync with the broker's response
    (attach-ca may return an org_id that matches what the admin
    pasted — verified at invite-consume time on the broker).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from mcp_proxy.config import get_settings
from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
    verify_csrf,
)
from mcp_proxy.db import get_config, log_audit, set_config

_log = logging.getLogger("mcp_proxy.dashboard.link_broker")

import pathlib as _pl
_TEMPLATE_DIR = _pl.Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


dashboard_router = APIRouter(prefix="/proxy", tags=["dashboard-link-broker"])
admin_router = APIRouter(prefix="/v1/admin", tags=["admin-link-broker"])


def _ctx(request: Request, session: ProxyDashboardSession, **kwargs) -> dict:
    return {"request": request, "session": session, "csrf_token": session.csrf_token, **kwargs}


async def _attach_ca_to_broker(
    *,
    broker_url: str,
    invite_token: str,
    org_ca_cert_pem: str,
    org_secret: str,
    verify_tls: bool,
) -> tuple[bool, dict[str, Any] | str]:
    """Run the broker attach-ca call. Returns (ok, body_or_err_msg)."""
    try:
        async with httpx.AsyncClient(verify=verify_tls, timeout=10.0) as http:
            resp = await http.post(
                f"{broker_url.rstrip('/')}/v1/onboarding/attach",
                json={
                    "ca_certificate": org_ca_cert_pem,
                    "invite_token": invite_token,
                    "secret": org_secret,
                },
            )
    except Exception as exc:
        return False, f"cannot reach broker: {exc}"

    if resp.status_code == 200:
        try:
            return True, resp.json()
        except Exception:
            return True, {"status": "attached"}
    if resp.status_code == 403:
        return False, "invalid or expired invite token"
    if resp.status_code == 404:
        return False, "target organization not found on broker"
    if resp.status_code == 409:
        return False, "organization already has a CA attached on broker"
    return False, f"broker rejected link (HTTP {resp.status_code}): {resp.text[:200]}"


async def _swap_broker_bridge(app, *, broker_url: str, org_id: str) -> None:
    """Close the old bridge + reverse-proxy client, then install fresh ones.

    Called only after the attach-ca call succeeded, so we know the
    broker accepts us. A failure *here* leaves the proxy in a broken
    hybrid state — but that is strictly better than leaking a client
    across every retry. Admins can recover by clicking Link Broker
    again (idempotent on the broker side; the config is already set).
    """
    settings = get_settings()

    # Close existing bridge. shutdown() is safe to call on a fresh instance.
    old_bridge = getattr(app.state, "broker_bridge", None)
    if old_bridge is not None:
        try:
            await old_bridge.shutdown()
        except Exception as exc:
            _log.warning("old bridge shutdown raised (continuing): %s", exc)

    # Close existing reverse-proxy client so we don't leak one per uplink.
    old_client = getattr(app.state, "reverse_proxy_client", None)
    if old_client is not None:
        try:
            await old_client.aclose()
        except Exception as exc:
            _log.warning("old reverse_proxy_client aclose raised: %s", exc)

    # Install a fresh reverse-proxy client matched to the new broker URL.
    app.state.reverse_proxy_broker_url = broker_url
    app.state.reverse_proxy_client = httpx.AsyncClient(
        timeout=30.0,
        verify=settings.broker_verify_tls,
        follow_redirects=False,
    )

    # Build a fresh BrokerBridge around the running AgentManager (the
    # Org CA doesn't change at uplink time — the broker trusts *our*
    # CA via attach-ca).
    from mcp_proxy.egress.broker_bridge import BrokerBridge

    agent_mgr = app.state.agent_manager
    bridge = BrokerBridge(
        broker_url=broker_url,
        org_id=org_id,
        agent_manager=agent_mgr,
        verify_tls=settings.broker_verify_tls,
        trust_domain=settings.trust_domain,
        intra_org_routing=settings.intra_org_routing,
    )
    app.state.broker_bridge = bridge
    app.state.org_id = org_id
    _log.info("broker_bridge hot-swapped — broker=%s org=%s", broker_url, org_id)


# ── Dashboard pages ──────────────────────────────────────────────────────────

@dashboard_router.get("/link-broker", response_class=HTMLResponse)
async def link_broker_form(request: Request):
    """Render the link-broker form — admin pastes broker_url + invite_token.

    Hidden in federated mode (already linked) unless ``?force=1`` so an
    operator can intentionally re-link (e.g. moving to a different
    broker cluster).
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    settings = get_settings()
    current_broker = await get_config("broker_url") or ""
    already_linked = bool(current_broker)
    force = request.query_params.get("force") == "1"

    if already_linked and not force:
        return RedirectResponse(url="/proxy/overview", status_code=303)

    # Surface the deterministic org_id the admin must paste into the
    # broker invite. Re-derive from the loaded CA so a tampered
    # proxy_config row can't convince the admin the id is different.
    agent_mgr = getattr(request.app.state, "agent_manager", None)
    org_id_from_ca = agent_mgr.derive_org_id_from_ca() if agent_mgr else None
    org_id = org_id_from_ca or await get_config("org_id") or settings.org_id

    return templates.TemplateResponse("link_broker.html", _ctx(
        request, session,
        active="link_broker",
        org_id=org_id,
        current_broker=current_broker,
        already_linked=already_linked,
    ))


class LinkBrokerRequest(BaseModel):
    broker_url: str
    invite_token: str


# ── Admin API ────────────────────────────────────────────────────────────────

@admin_router.post("/link-broker")
async def link_broker_endpoint(request: Request):
    """Attach to the broker and hot-swap the BrokerBridge in one call.

    Form POST (dashboard) OR JSON POST (programmatic / CI). Admin session
    cookie is required either way; CSRF is required for the form path.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        raise HTTPException(status_code=401, detail="login required")

    # Parse both form and JSON bodies — the dashboard posts form-encoded,
    # the smoke scripts post JSON.
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body")
        broker_url = str(payload.get("broker_url", "")).strip()
        invite_token = str(payload.get("invite_token", "")).strip()
    else:
        if not await verify_csrf(request, session):
            raise HTTPException(status_code=403, detail="invalid CSRF token")
        form = await request.form()
        broker_url = str(form.get("broker_url", "")).strip()
        invite_token = str(form.get("invite_token", "")).strip()

    if not broker_url or not invite_token:
        raise HTTPException(
            status_code=400,
            detail="broker_url and invite_token are required",
        )
    if not (broker_url.startswith("http://") or broker_url.startswith("https://")):
        raise HTTPException(status_code=400, detail="broker_url must be http(s)://")

    settings = get_settings()
    org_ca_cert_pem = await get_config("org_ca_cert")
    if not org_ca_cert_pem:
        raise HTTPException(
            status_code=400,
            detail=(
                "proxy has no Org CA — generate one first "
                "(standalone first-boot, or run /proxy/setup)"
            ),
        )

    # Mint an org_secret on demand if the proxy never ran the setup
    # wizard. Standalone first-boot creates the Org CA but not this
    # token; the attach-ca flow needs it (broker pins it as the
    # authenticator for subsequent ops).
    org_secret = await get_config("org_secret")
    if not org_secret:
        import secrets as _secrets
        org_secret = _secrets.token_urlsafe(32)
        await set_config("org_secret", org_secret)

    ok, body_or_err = await _attach_ca_to_broker(
        broker_url=broker_url,
        invite_token=invite_token,
        org_ca_cert_pem=org_ca_cert_pem,
        org_secret=org_secret,
        verify_tls=settings.broker_verify_tls,
    )
    if not ok:
        await log_audit(
            agent_id="admin",
            action="admin.link_broker",
            status="error",
            detail=f"broker={broker_url} error={body_or_err}",
        )
        raise HTTPException(status_code=502, detail=body_or_err)

    # attach returns org_id in the body — trust what the broker says so
    # downstream queries line up with the server's view.
    org_id = str(body_or_err.get("org_id")) if isinstance(body_or_err, dict) else ""
    if not org_id:
        # Older broker builds may omit org_id on 200 — fall back to the
        # value we have locally (deterministic from CA pubkey).
        agent_mgr = getattr(request.app.state, "agent_manager", None)
        org_id = (
            (agent_mgr and agent_mgr.derive_org_id_from_ca())
            or await get_config("org_id")
            or settings.org_id
        )

    await set_config("broker_url", broker_url)
    await set_config("org_id", org_id)
    await set_config("invite_token", invite_token)
    final_status = (
        body_or_err.get("status") if isinstance(body_or_err, dict) else None
    ) or "attached"
    await set_config("org_status", final_status)

    await _swap_broker_bridge(request.app, broker_url=broker_url, org_id=org_id)

    await log_audit(
        agent_id="admin",
        action="admin.link_broker",
        status="success",
        detail=f"broker={broker_url} org_id={org_id} status={final_status}",
    )

    if "application/json" in content_type:
        return {
            "status": "linked",
            "broker_url": broker_url,
            "org_id": org_id,
            "org_status": final_status,
        }
    return RedirectResponse(url="/proxy/overview", status_code=303)
