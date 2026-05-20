"""Court dashboard — admin settings sub-router.

Sprint 2 / F-B-202 PR-3 of 10. Extracts the network-admin settings
surface (change password) and the demo-mode policy enforcement toggle
into a per-feature sub-router.

Mounted via ``router.include_router(admin_settings_routes.router)``
in ``router.py`` so the outer ``/dashboard`` prefix is inherited; route
paths in this file are relative to that prefix.

Routes (3):

  GET  /dashboard/admin/settings           settings page (kms backend,
                                           hash presence, change-pw form)
  POST /dashboard/admin/settings/password  change admin password
  POST /dashboard/admin/policy-toggle      flip policy enforcement
                                           (demo / sandbox only — production
                                           refuses the runtime flip via
                                           ``set_policy_enforcement`` guard)

The change-password endpoint here is the second of the two
``bcrypt.gensalt(rounds=12)`` hardcodes the F-B-202 audit flagged;
the first lives in ``auth_routes.py::admin_setup_submit``. Both stay
as literals for now — a future micro-refactor consolidates them into
``app.kms.admin_secret.BCRYPT_COST`` (out of scope for this PR; the
goal here is the route move, not the cost-tuning knob).
"""
from __future__ import annotations

import logging
import pathlib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.dashboard._helpers import _ctx
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login, verify_csrf
from app.db.audit import log_event
from app.db.database import get_db

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-admin-settings"])


@router.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    from app.kms.admin_secret import get_admin_secret_hash
    from app.config import get_settings
    stored_hash = await get_admin_secret_hash()
    return templates.TemplateResponse("admin_settings.html",
        _ctx(request, session, active="admin_settings", error=None, success=None,
             kms_backend=get_settings().kms_backend, hash_present=stored_hash is not None))


@router.post("/admin/settings/password", response_class=HTMLResponse)
async def admin_change_password(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/admin/settings", status_code=303)

    from app.config import get_settings
    settings = get_settings()

    form = await request.form()
    current_password = form.get("current_password", "")
    new_password = form.get("new_password", "")
    confirm_password = form.get("confirm_password", "")

    def _err(msg: str):
        return templates.TemplateResponse("admin_settings.html",
            _ctx(request, session, active="admin_settings", error=msg, success=None,
                 kms_backend=settings.kms_backend, hash_present=True))

    if not current_password or not new_password or not confirm_password:
        return _err("All fields are required.")

    if new_password != confirm_password:
        return _err("New passwords do not match.")

    if len(new_password) < 12:
        return _err("Password must be at least 12 characters.")

    # Verify current password
    from app.kms.admin_secret import get_admin_secret_hash, verify_admin_password, set_admin_secret_hash
    stored_hash = await get_admin_secret_hash()
    if not verify_admin_password(current_password, stored_hash):
        # Fallback to .env if no hash in backend
        if stored_hash is not None:
            return _err("Current password is incorrect.")
        import hmac as _hmac
        if not _hmac.compare_digest(current_password, settings.admin_secret):
            return _err("Current password is incorrect.")

    # Hash and store
    import bcrypt
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(rounds=12)).decode()
    await set_admin_secret_hash(new_hash)

    await log_event(db, "admin.password_changed", "ok",
                    details={"source": "dashboard"})

    return templates.TemplateResponse("admin_settings.html",
        _ctx(request, session, active="admin_settings", error=None,
             success="Admin password updated successfully.",
             kms_backend=settings.kms_backend, hash_present=True))


@router.post("/admin/policy-toggle", response_class=HTMLResponse)
async def admin_policy_toggle(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard", status_code=303)

    from app.config import is_policy_enforced, set_policy_enforcement
    new_state = not is_policy_enforced()
    set_policy_enforcement(new_state)
    state_label = "enabled" if new_state else "disabled"
    await log_event(db, "admin.policy_toggle", "ok", details={"enforcement": state_label})
    return RedirectResponse(url="/dashboard", status_code=303)
