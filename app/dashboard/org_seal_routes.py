"""Court dashboard — Org seal / unseal-reauth sub-router (audit F-B-2).

Sprint 2 / F-B-202 PR-6 of 10. Extracts the per-org re-auth challenge
+ manual seal/unseal flow (section 20 of the audit) into a
per-feature sub-router.

Flow (audit F-B-2):

  - GET  /orgs/{org_id}/unseal-reauth  → password prompt form
  - POST /orgs/{org_id}/unseal-reauth  → verify admin password, stamp
                                          a REAUTH_TTL_SECONDS-scoped
                                          token onto the session cookie,
                                          redirect back with
                                          ``reauth=<org_id>`` flash
  - POST /orgs/{org_id}/seal           → force-seal an unsealed org
                                          (no re-auth needed — sealing
                                          ADDS protection)
  - POST /orgs/{org_id}/unseal         → unseal a sealed org. Gated:
                                          unsealing REMOVES protection,
                                          so the admin proves per-org
                                          scope right now.

Routes (5):

  GET  /dashboard/orgs/{org_id}/unseal-reauth
  POST /dashboard/orgs/{org_id}/unseal-reauth
  POST /dashboard/orgs/{org_id}/seal
  POST /dashboard/orgs/{org_id}/unseal
  (+ form responses share the same template)
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.dashboard._helpers import (
    _ctx, _require_sealed_reauth, _safe_redirect,
)
from app.dashboard._template_env import build_templates
from app.dashboard.session import (
    REAUTH_TTL_SECONDS, add_reauth_scope, require_login, verify_csrf,
)
from app.db.audit import log_event
from app.db.database import get_db
from app.registry.org_store import get_org_by_id, set_org_sealed

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-org-seal"])


@router.get("/orgs/{org_id}/unseal-reauth", response_class=HTMLResponse)
async def org_unseal_reauth_form(request: Request, org_id: str,
                                 db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    org = await get_org_by_id(db, org_id)
    if org is None:
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    next_url = _safe_redirect(
        request.query_params.get("next"), fallback="/dashboard/orgs"
    )
    return templates.TemplateResponse(
        "org_unseal_reauth.html",
        _ctx(request, session, active="orgs", org=org, next_url=next_url,
             error=None, ttl_seconds=REAUTH_TTL_SECONDS),
    )


@router.post("/orgs/{org_id}/unseal-reauth", response_class=HTMLResponse)
async def org_unseal_reauth_submit(request: Request, org_id: str,
                                   db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    org = await get_org_by_id(db, org_id)
    if org is None:
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    from app.kms.admin_secret import (
        get_admin_secret_hash, verify_admin_password,
    )
    form_data = await request.form()
    password = form_data.get("password", "")
    # Validate the redirect target (H-IO-1): reject protocol-relative and
    # absolute URLs to prevent open-redirect after admin re-auth.
    next_url = _safe_redirect(
        form_data.get("next"), fallback="/dashboard/orgs"
    )

    stored_hash = await get_admin_secret_hash()
    if not password or not verify_admin_password(password, stored_hash):
        await log_event(db, "admin.unseal_reauth_failed", "denied",
                        org_id=org_id, details={"source": "dashboard"})
        return templates.TemplateResponse(
            "org_unseal_reauth.html",
            _ctx(request, session, active="orgs", org=org,
                 next_url=next_url, error="Incorrect password.",
                 ttl_seconds=REAUTH_TTL_SECONDS),
            status_code=403,
        )

    response = RedirectResponse(url=next_url, status_code=303)
    add_reauth_scope(response, session, org_id)
    await log_event(db, "admin.unseal_reauth_granted", "ok",
                    org_id=org_id,
                    details={"source": "dashboard",
                             "ttl_seconds": REAUTH_TTL_SECONDS})
    return response


@router.post("/orgs/{org_id}/seal", response_class=HTMLResponse)
async def org_seal(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    """Manually flip the tenant-sealed flag ON for an org.

    Always safe without re-auth: sealing *adds* protection, so an admin
    who controls the cookie can only make the situation more restrictive.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    org = await get_org_by_id(db, org_id)
    if org and not org.sealed:
        await set_org_sealed(db, org_id, True)
        await log_event(db, "registry.org_sealed", "ok", org_id=org_id,
                        details={"source": "dashboard_admin", "sealed": True})
    return RedirectResponse(url="/dashboard/orgs", status_code=303)


@router.post("/orgs/{org_id}/unseal", response_class=HTMLResponse)
async def org_unseal(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    """Permanently unseal an org.

    Gated: because unsealing REMOVES protection (future mutations skip
    the re-auth challenge), the admin has to prove per-org scope right
    now. Effectively this means "provide the password one more time".
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    org = await get_org_by_id(db, org_id)
    await _require_sealed_reauth(request, org)
    if org and org.sealed:
        await set_org_sealed(db, org_id, False)
        await log_event(db, "registry.org_unsealed", "ok", org_id=org_id,
                        details={"source": "dashboard_admin_with_reauth",
                                 "sealed": False})
    return RedirectResponse(url="/dashboard/orgs", status_code=303)
