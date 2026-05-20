"""Court dashboard — Organizations sub-router.

Sprint 2 / F-B-202 PR-5 of 10. Extracts the orgs CRUD + invites +
approve/reject/suspend/delete/unlock-CA/upload-CA surface (sections
9+10+19+21 of the audit). Eleven routes in total — the biggest
single-PR extraction so far.

Mounted via ``router.include_router(orgs_routes.router)``.

Routes (11):

  GET  /dashboard/orgs                            list (org table + invites)
  POST /dashboard/invites/generate                mint network-admin invite
  POST /dashboard/orgs/{id}/attach-invite         mint attach-CA invite per-org
  POST /dashboard/invites/{id}/revoke             revoke invite
  POST /dashboard/orgs/{id}/approve               approve onboarding (sealed-gate)
  POST /dashboard/orgs/{id}/reject                reject onboarding (sealed-gate)
  POST /dashboard/orgs/{id}/suspend               suspend active org (sealed-gate)
  POST /dashboard/orgs/{id}/delete                delete org + cascade agents (sealed-gate)
  POST /dashboard/orgs/{id}/unlock-ca             clear ca_locked flag (sealed-gate)
  GET  /dashboard/orgs/{id}/upload-ca             CA upload form
  POST /dashboard/orgs/{id}/upload-ca             CA upload submit (sealed-gate)

All state-changing routes verify CSRF and gate on
``_require_sealed_reauth`` (audit F-B-2). The sealed gate is the
load-bearing security control on this surface — without it a network
admin can mutate any tenant's identity plane without per-org consent.
"""
from __future__ import annotations

import datetime
import json as _json
import logging
import pathlib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.dashboard._helpers import (
    _ctx, _is_sealed, _require_sealed_reauth, _sealed_mutation_details,
)
from app.dashboard._template_env import build_templates
from app.dashboard.session import get_session, require_login, verify_csrf
from app.db.audit import log_event
from app.db.database import get_db
from app.registry.binding_store import (
    get_binding_by_org_agent, revoke_binding,
)
from app.registry.org_store import (
    OrganizationRecord, get_org_by_id, set_org_status, update_org_ca_cert,
)
from app.registry.store import AgentRecord

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-orgs"])


# ── Organizations list ─────────────────────────────────────────────


@router.get("/orgs", response_class=HTMLResponse)
async def orgs_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    result = await db.execute(select(OrganizationRecord).order_by(OrganizationRecord.org_id))
    orgs = result.scalars().all()

    agent_counts = {}
    count_q = select(AgentRecord.org_id, func.count(AgentRecord.agent_id)).group_by(AgentRecord.org_id)
    for row in (await db.execute(count_q)).all():
        agent_counts[row[0]] = row[1]

    # Audit F-B-2 — expose the sealed flag + the current session's per-org
    # re-auth status so the template can paint badges and enable/disable
    # mutation buttons. ``reauth_active`` is recomputed against the live
    # session (not the org record) so an expiring token flips the UI to
    # "needs re-auth" without a round-trip.
    active_session = get_session(request)
    org_list = []
    for org in orgs:
        sealed = bool(getattr(org, "sealed", False))
        # Mastio-pushed fleet stats land in metadata_json["stats"] via
        # POST /v1/federation/publish-stats (ADR-010 Phase 3 companion).
        # Orgs that haven't pushed yet (or predate the publisher) render
        # as dashes — never blank — so the operator can spot missing
        # telemetry without mistaking it for a zero-agent fleet.
        mastio_stats = None
        try:
            meta = org.extra  # parses metadata_json
            raw_stats = meta.get("stats") if isinstance(meta, dict) else None
            if isinstance(raw_stats, dict):
                mastio_stats = raw_stats
        except (ValueError, TypeError):
            pass
        org_list.append({
            "org_id": org.org_id,
            "display_name": org.display_name,
            "status": org.status,
            "webhook_url": org.webhook_url,
            "ca_certificate": org.ca_certificate,
            "agent_count": agent_counts.get(org.org_id, 0),
            "mastio_stats": mastio_stats,
            "sealed": sealed,
            "reauth_active": (
                sealed and active_session.has_reauth_scope(org.org_id)
            ),
        })

    # Load invite tokens for admin
    from app.onboarding.invite_store import list_invites
    invites_raw = await list_invites(db)
    _now_utc = datetime.datetime.now(datetime.timezone.utc)

    def _aware(dt):
        # SQLite drops tzinfo; normalize to UTC-aware for comparisons.
        if dt is not None and dt.tzinfo is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    invites = [
        {
            "id": inv.id,
            "label": inv.label,
            "created_at": _aware(inv.created_at),
            "expires_at": _aware(inv.expires_at),
            "used": inv.used,
            "used_by_org_id": inv.used_by_org_id,
            "revoked": inv.revoked,
            "invite_type": inv.invite_type,
            "linked_org_id": inv.linked_org_id,
            "expired": _aware(inv.expires_at) < _now_utc,
        }
        for inv in invites_raw
    ]

    return templates.TemplateResponse("orgs.html",
        _ctx(request, session, active="orgs", orgs=org_list, invites=invites)
    )


# ── Invite Token Dashboard Actions ─────────────────────────────────


@router.post("/invites/generate", response_class=HTMLResponse)
async def dashboard_generate_invite(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    form_data = await request.form()
    label = (form_data.get("label", "") or "").strip()
    ttl_hours = int(form_data.get("ttl_hours", "72") or "72")

    from app.onboarding.invite_store import create_invite
    record, plaintext = await create_invite(db, label=label, ttl_hours=ttl_hours)
    await log_event(db, "admin.invite_created", "ok",
                    details={"invite_id": record.id, "label": label, "source": "dashboard"})

    # Show the plaintext token once via flash-style redirect
    return templates.TemplateResponse("invite_created.html",
        _ctx(request, session, active="orgs",
             invite_token=plaintext, invite_label=label, invite_id=record.id))


@router.post("/orgs/{org_id}/attach-invite", response_class=HTMLResponse)
async def dashboard_generate_attach_invite(
    request: Request, org_id: str, db: AsyncSession = Depends(get_db),
):
    """
    Generate an attach-ca invite for a pre-registered org. Usable only from
    the broker dashboard by an admin. The org must exist and must not
    already have a CA on file.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    from app.registry.org_store import get_org_by_id as _get_org
    from app.onboarding.invite_store import create_invite, INVITE_TYPE_ATTACH_CA

    org = await _get_org(db, org_id)
    if org is None:
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    if org.ca_certificate:
        # Nothing to attach — silently redirect; rotation is a separate flow.
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    form_data = await request.form()
    label = (form_data.get("label", "") or "").strip() or f"attach-ca for {org_id}"
    ttl_hours = int(form_data.get("ttl_hours", "72") or "72")

    record, plaintext = await create_invite(
        db, label=label, ttl_hours=ttl_hours,
        invite_type=INVITE_TYPE_ATTACH_CA,
        linked_org_id=org_id,
    )
    await log_event(db, "admin.attach_invite_created", "ok",
                    org_id=org_id,
                    details={"invite_id": record.id, "label": label,
                             "source": "dashboard"})

    return templates.TemplateResponse("invite_created.html",
        _ctx(request, session, active="orgs",
             invite_token=plaintext, invite_label=label, invite_id=record.id,
             invite_type="attach-ca", linked_org_id=org_id))


@router.post("/invites/{invite_id}/revoke", response_class=HTMLResponse)
async def dashboard_revoke_invite(request: Request, invite_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    from app.onboarding.invite_store import revoke_invite
    await revoke_invite(db, invite_id)
    await log_event(db, "admin.invite_revoked", "ok",
                    details={"invite_id": invite_id, "source": "dashboard"})
    return RedirectResponse(url="/dashboard/orgs", status_code=303)


# ── Approve / Reject / Suspend / Delete / Unlock-CA ────────────────


@router.post("/orgs/{org_id}/approve", response_class=HTMLResponse)
async def org_approve(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    org = await get_org_by_id(db, org_id)
    # Audit F-B-2 — sealed orgs require a per-org re-auth scope.
    await _require_sealed_reauth(request, org)
    if org and org.status == "pending":
        await set_org_status(db, org_id, "active")
        await log_event(db, "onboarding.approved", "ok", org_id=org_id,
                        details=_sealed_mutation_details(org))
    return RedirectResponse(url="/dashboard/orgs", status_code=303)


@router.post("/orgs/{org_id}/reject", response_class=HTMLResponse)
async def org_reject(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    org = await get_org_by_id(db, org_id)
    # Audit F-B-2 — sealed orgs require a per-org re-auth scope.
    await _require_sealed_reauth(request, org)
    if org and org.status in ("pending", "active"):
        await set_org_status(db, org_id, "rejected")
        await log_event(db, "onboarding.rejected", "denied", org_id=org_id,
                        details=_sealed_mutation_details(org))
    return RedirectResponse(url="/dashboard/orgs", status_code=303)


@router.post("/orgs/{org_id}/suspend", response_class=HTMLResponse)
async def org_suspend(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)
    org = await get_org_by_id(db, org_id)
    # Audit F-B-2 — sealed orgs require a per-org re-auth scope.
    await _require_sealed_reauth(request, org)
    if org and org.status == "active":
        await set_org_status(db, org_id, "suspended")
        await log_event(db, "onboarding.suspended", "ok", org_id=org_id,
                        details=_sealed_mutation_details(org))
    return RedirectResponse(url="/dashboard/orgs", status_code=303)


@router.post("/orgs/{org_id}/delete", response_class=HTMLResponse)
async def org_delete(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    org = await get_org_by_id(db, org_id)
    # Audit F-B-2 — sealed orgs require a per-org re-auth scope. Delete
    # cascades into agents+bindings so the gate protects the whole op.
    await _require_sealed_reauth(request, org)
    if org:
        was_sealed = _is_sealed(org)
        # Delete all agents belonging to this org
        agents = await db.execute(
            select(AgentRecord).where(AgentRecord.org_id == org_id)
        )
        for agent in agents.scalars().all():
            binding = await get_binding_by_org_agent(db, org_id, agent.agent_id)
            if binding and binding.status != "revoked":
                await revoke_binding(db, binding.id)
            await db.delete(agent)

        # Delete the org
        await db.delete(org)
        await db.commit()
        await log_event(
            db, "registry.org_deleted", "ok", org_id=org_id,
            details={
                "source": "dashboard_admin_with_reauth" if was_sealed else "dashboard_admin",
                "sealed": was_sealed,
            },
        )

    return RedirectResponse(url="/dashboard/orgs", status_code=303)


@router.post("/orgs/{org_id}/unlock-ca", response_class=HTMLResponse)
async def org_unlock_ca(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    org = await get_org_by_id(db, org_id)
    # Audit F-B-2 — sealed orgs require a per-org re-auth scope. Unlock-CA
    # is the literal finding from the audit: without this gate, an admin
    # can clear the CA lock flag on any tenant and follow up with
    # upload-ca to swap in their own CA.
    await _require_sealed_reauth(request, org)
    if org:
        meta = _json.loads(org.metadata_json or "{}")
        meta["ca_locked"] = False
        org.metadata_json = _json.dumps(meta)
        await db.commit()
        await log_event(db, "registry.ca_certificate_unlocked", "ok",
                        org_id=org_id, details=_sealed_mutation_details(org))

    return RedirectResponse(url="/dashboard/orgs", status_code=303)


# ── Admin — Upload CA certificate for an org ───────────────────────


@router.get("/orgs/{org_id}/upload-ca", response_class=HTMLResponse)
async def org_upload_ca_form(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    org = await get_org_by_id(db, org_id)
    if not org:
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    return templates.TemplateResponse("org_upload_ca.html",
        _ctx(request, session, active="orgs", org=org, error=None, success=None))


@router.post("/orgs/{org_id}/upload-ca", response_class=HTMLResponse)
async def org_upload_ca_submit(request: Request, org_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    org = await get_org_by_id(db, org_id)
    if not org:
        return RedirectResponse(url="/dashboard/orgs", status_code=303)

    if not await verify_csrf(request, session):
        return templates.TemplateResponse("org_upload_ca.html",
            _ctx(request, session, active="orgs", org=org,
                 error="Invalid CSRF token.", success=None))

    # Audit F-B-2 — uploading a CA on a sealed org effectively rewrites
    # the tenant's root of trust. Require the per-org re-auth gate.
    await _require_sealed_reauth(request, org)

    form_data = await request.form()
    ca_pem = form_data.get("ca_certificate", "").strip()

    if not ca_pem or "-----BEGIN CERTIFICATE-----" not in ca_pem:
        return templates.TemplateResponse("org_upload_ca.html",
            _ctx(request, session, active="orgs", org=org,
                 error="Invalid certificate. Paste a valid PEM certificate.", success=None))

    try:
        from cryptography.x509 import load_pem_x509_certificate
        load_pem_x509_certificate(ca_pem.encode())
    except Exception:
        return templates.TemplateResponse("org_upload_ca.html",
            _ctx(request, session, active="orgs", org=org,
                 error="Could not parse the certificate. Ensure it is valid PEM format.", success=None))

    await update_org_ca_cert(db, org_id, ca_pem)

    meta = _json.loads(org.metadata_json or "{}")
    meta["ca_locked"] = True
    org.metadata_json = _json.dumps(meta)
    await db.commit()

    await log_event(db, "registry.ca_certificate_uploaded", "ok",
                    org_id=org_id,
                    details=_sealed_mutation_details(org))

    org = await get_org_by_id(db, org_id)
    return templates.TemplateResponse("org_upload_ca.html",
        _ctx(request, session, active="orgs", org=org,
             error=None, success="CA certificate uploaded and locked."))
