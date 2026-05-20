"""Court dashboard — Agents lifecycle sub-router.

Sprint 2 / F-B-202 PR-7a of 10. Extracts the agent register / manage /
delete surface (section 22 of the audit) into a per-feature sub-router.

Routes (5):

  GET  /dashboard/agents/register             register form
  POST /dashboard/agents/register             register submit (mints binding,
                                              optional cert pin, sealed-gate)
  GET  /dashboard/agents/{id}/manage          unified settings form
  POST /dashboard/agents/{id}/manage          update profile OR upload-cert
                                              (sealed-gate)
  POST /dashboard/agents/{id}/delete          delete + revoke binding (sealed-gate)

Sibling sub-router ``agents_credentials_routes.py`` (PR-7b) covers the
developer-portal detail page + the cert/bundle download flow.
"""
from __future__ import annotations

import json as _json
import logging
import pathlib
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.broker.ws_manager import ws_manager
from app.dashboard._helpers import (
    _ctx, _is_sealed, _require_sealed_reauth, _sealed_mutation_details,
    _validate_id,
)
from app.dashboard._template_env import build_templates
from app.dashboard.session import get_session, require_login, verify_csrf
from app.db.audit import log_event
from app.db.database import get_db
from app.registry.binding_store import (
    approve_binding, create_binding, get_binding_by_org_agent, revoke_binding,
)
from app.registry.org_store import OrganizationRecord, get_org_by_id
from app.registry.store import AgentRecord, register_agent, rotate_agent_cert

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-agents-lifecycle"])

# Constants duplicated from router.py for self-containment; future
# micro-refactor can promote to ``app/dashboard/_helpers.py``.
_CAPABILITY_MAX_LEN = 64
_CAPABILITY_MAX_COUNT = 50


@router.get("/agents/register", response_class=HTMLResponse)
async def agent_register_form(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
    orgs = (await db.execute(q)).scalars().all()

    return templates.TemplateResponse("agent_register.html",
        _ctx(request, session, active="agents", form={}, orgs=orgs, error=None, success=None))


@router.post("/agents/register", response_class=HTMLResponse)
async def agent_register_submit(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        q = select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
        orgs = (await db.execute(q)).scalars().all()
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form={}, orgs=orgs,
                 error="Invalid CSRF token. Please try again.", success=None),
            status_code=403)
    form_data = await request.form()
    org_id      = form_data.get("org_id", "").strip()
    agent_name  = form_data.get("agent_name", "").strip()
    display_name = form_data.get("display_name", "").strip()
    description  = form_data.get("description", "").strip()
    capabilities_raw = form_data.get("capabilities", "").strip()
    # Build full agent_id from org + name
    agent_id = f"{org_id}::{agent_name}" if org_id and agent_name else ""
    if not display_name:
        display_name = agent_name.replace("-", " ").replace("_", " ").title()

    cert_pem = form_data.get("cert_pem", "").strip()

    form = {
        "org_id": org_id,
        "agent_name": agent_name,
        "display_name": display_name,
        "description": description,
        "capabilities": capabilities_raw,
        "cert_pem": cert_pem,
    }

    result = await db.execute(
        select(OrganizationRecord)
        .where(OrganizationRecord.status == "active")
        .order_by(OrganizationRecord.org_id)
    )
    orgs = result.scalars().all()

    # Org user can only register agents for their own org
    if not session.is_admin and org_id != session.org_id:
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form=form, orgs=orgs,
                 error="You can only register agents for your own organization.", success=None))

    if not org_id or not agent_name:
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form=form, orgs=orgs,
                 error="Organization and agent name are required.", success=None))

    for val, lbl in [(org_id, "Organization ID"), (agent_name, "Agent name")]:
        id_err = _validate_id(val, lbl)
        if id_err:
            return templates.TemplateResponse("agent_register.html",
                _ctx(request, session, active="agents", form=form, orgs=orgs, error=id_err, success=None))

    existing = await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )
    if existing.scalar_one_or_none():
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form=form, orgs=orgs,
                 error=f"Agent '{agent_id}' already exists.", success=None))

    # Audit F-B-2 — registering an agent on a sealed org implicitly
    # auto-approves a binding and may pin a cert, both of which are
    # tenant-identity-plane mutations. Require the re-auth gate.
    target_org = await get_org_by_id(db, org_id)
    if _is_sealed(target_org):
        reauth_session = get_session(request)
        if not reauth_session.has_reauth_scope(org_id):
            return templates.TemplateResponse(
                "agent_register.html",
                _ctx(request, session, active="agents", form=form, orgs=orgs,
                     error=(f"Org '{org_id}' is tenant-sealed. "
                            f"Re-authenticate for this org before registering agents."),
                     success=None),
                status_code=403,
            )

    caps = [c.strip() for c in capabilities_raw.split(",") if c.strip()] if capabilities_raw else []
    if len(caps) > _CAPABILITY_MAX_COUNT:
        return templates.TemplateResponse("agent_register.html",
            _ctx(request, session, active="agents", form=form, orgs=orgs,
                 error=f"Maximum {_CAPABILITY_MAX_COUNT} capabilities allowed.", success=None))
    for cap in caps:
        if len(cap) > _CAPABILITY_MAX_LEN or not re.match(r"^[a-zA-Z0-9._:\-]+$", cap):
            return templates.TemplateResponse("agent_register.html",
                _ctx(request, session, active="agents", form=form, orgs=orgs,
                     error=f"Invalid capability '{cap}'. Use alphanumeric, dots, colons, hyphens (max {_CAPABILITY_MAX_LEN} chars).",
                     success=None))

    await register_agent(
        db, agent_id=agent_id, org_id=org_id,
        display_name=display_name, capabilities=caps,
        metadata={}, description=description,
    )
    await log_event(db, "registry.agent_registered", "ok",
                    agent_id=agent_id, org_id=org_id,
                    details=_sealed_mutation_details(
                        target_org, extra={"capabilities": caps}))

    # Auto-create and auto-approve binding. approved_by carries the
    # sealed-vs-unsealed context for downstream forensics.
    approved_by = (
        "dashboard-admin-with-reauth" if _is_sealed(target_org) else "dashboard-admin"
    )
    existing_binding = await get_binding_by_org_agent(db, org_id, agent_id)
    if existing_binding and existing_binding.status != "approved":
        await approve_binding(db, existing_binding.id, approved_by=approved_by)
    elif not existing_binding:
        binding = await create_binding(db, org_id, agent_id, scope=caps)
        await approve_binding(db, binding.id, approved_by=approved_by)

    # If a certificate was provided, validate and pin it
    cert_msg = ""
    if cert_pem:
        if "-----BEGIN CERTIFICATE-----" not in cert_pem:
            cert_msg = " Certificate ignored: invalid PEM format."
        else:
            try:
                from cryptography.x509 import load_pem_x509_certificate
                from cryptography.x509.oid import NameOID
                cert_obj = load_pem_x509_certificate(cert_pem.encode())
                cn_attrs = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if not cn_attrs or cn_attrs[0].value != agent_id:
                    cert_msg = f" Certificate ignored: CN '{cn_attrs[0].value if cn_attrs else '(none)'}' does not match agent ID."
                else:
                    # Verify against org CA if available
                    org = await get_org_by_id(db, org_id)
                    ca_ok = True
                    if org and org.ca_certificate:
                        try:
                            from cryptography.hazmat.primitives.asymmetric import padding
                            ca_cert = load_pem_x509_certificate(org.ca_certificate.encode())
                            ca_cert.public_key().verify(
                                cert_obj.signature, cert_obj.tbs_certificate_bytes,
                                padding.PKCS1v15(), cert_obj.signature_hash_algorithm,
                            )
                        except Exception:
                            ca_ok = False
                            cert_msg = " Certificate ignored: not signed by organization CA."
                    if ca_ok:
                        await rotate_agent_cert(db, agent_id, cert_pem)
                        await log_event(
                            db, "registry.agent_cert_uploaded", "ok",
                            agent_id=agent_id, org_id=org_id,
                            details=_sealed_mutation_details(
                                target_org, extra={"method": "register"}),
                        )
                        cert_msg = " Certificate pinned."
            except Exception:
                cert_msg = " Certificate ignored: could not parse PEM."

    return templates.TemplateResponse("agent_register.html",
        _ctx(request, session, active="agents", form={}, orgs=orgs, error=None,
             success=f"Agent '{agent_id}' registered. Binding approved.{cert_msg}"))


@router.get("/agents/{agent_id:path}/manage", response_class=HTMLResponse)
async def agent_manage_form(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    agent = (await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one_or_none()
    if not agent:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    if not session.is_admin and agent.org_id != session.org_id:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    binding = await get_binding_by_org_agent(db, agent.org_id, agent_id)
    ws_connected = ws_manager.is_connected(agent_id)
    return templates.TemplateResponse("agent_manage.html",
        _ctx(request, session, active="agents",
             agent=agent, binding=binding, ws_connected=ws_connected,
             error=None, success=None))


@router.post("/agents/{agent_id:path}/manage", response_class=HTMLResponse)
async def agent_manage_submit(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    agent = (await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one_or_none()
    if not agent:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    if not session.is_admin and agent.org_id != session.org_id:
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    form_data = await request.form()
    action = form_data.get("action", "")
    binding = await get_binding_by_org_agent(db, agent.org_id, agent_id)
    ws_connected = ws_manager.is_connected(agent_id)

    def _render(error=None, success=None, status_code=200):
        return templates.TemplateResponse(
            "agent_manage.html",
            _ctx(request, session, active="agents",
                 agent=agent, binding=binding, ws_connected=ws_connected,
                 error=error, success=success),
            status_code=status_code,
        )

    # Audit F-B-2 — mutating an agent record on a sealed org requires the
    # per-org re-auth scope. Check once here so both update_profile and
    # upload_cert branches are covered.
    owner_org = await get_org_by_id(db, agent.org_id)
    if _is_sealed(owner_org) and action in ("update_profile", "upload_cert"):
        session_live = get_session(request)
        if not session_live.has_reauth_scope(agent.org_id):
            return _render(
                error=(f"Org '{agent.org_id}' is tenant-sealed. "
                       f"Re-authenticate for this org before mutating its agents."),
                status_code=403,
            )

    if action == "update_profile":
        display_name = form_data.get("display_name", "").strip()
        description = form_data.get("description", "").strip()
        capabilities_raw = form_data.get("capabilities", "").strip()
        caps = [c.strip() for c in capabilities_raw.split(",") if c.strip()] if capabilities_raw else []

        if not display_name:
            return _render(error="Display name is required.")

        for cap in caps:
            if len(cap) > 64 or not re.match(r"^[a-zA-Z0-9._:\-]+$", cap):
                return _render(error=f"Invalid capability '{cap}'.")

        agent.display_name = display_name
        agent.description = description
        agent.capabilities_json = _json.dumps(caps)

        # Update binding scope to match capabilities
        if binding:
            binding.scope_json = _json.dumps(caps)

        await db.commit()
        await log_event(
            db, "registry.agent_updated", "ok",
            agent_id=agent_id, org_id=agent.org_id,
            details=_sealed_mutation_details(
                owner_org,
                extra={"fields": ["display_name", "description", "capabilities"]},
            ),
        )
        return _render(success="Agent profile updated.")

    elif action == "upload_cert":
        cert_pem = form_data.get("cert_pem", "").strip()
        if not cert_pem or "-----BEGIN CERTIFICATE-----" not in cert_pem:
            return _render(error="Invalid certificate. Paste a valid PEM certificate.")
        try:
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.x509.oid import NameOID
            cert = load_pem_x509_certificate(cert_pem.encode())
        except Exception:
            return _render(error="Could not parse the certificate.")
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attrs or cn_attrs[0].value != agent_id:
            return _render(error=f"Certificate CN does not match agent ID '{agent_id}'.")
        # Verify against org CA if available
        org = await get_org_by_id(db, agent.org_id)
        if org and org.ca_certificate:
            try:
                from cryptography.hazmat.primitives.asymmetric import padding as _pad, ec as _ec
                ca_cert = load_pem_x509_certificate(org.ca_certificate.encode())
                ca_pub = ca_cert.public_key()
                from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
                if isinstance(ca_pub, _rsa.RSAPublicKey):
                    ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                                  _pad.PKCS1v15(), cert.signature_hash_algorithm)
                elif isinstance(ca_pub, _ec.EllipticCurvePublicKey):
                    ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                                  _ec.ECDSA(cert.signature_hash_algorithm))
            except Exception:
                return _render(error="Certificate not signed by organization CA.")
        new_thumbprint = await rotate_agent_cert(db, agent_id, cert_pem)
        await log_event(db, "registry.agent_cert_uploaded", "ok",
                        agent_id=agent_id, org_id=agent.org_id,
                        details=_sealed_mutation_details(owner_org))
        # Refresh agent
        agent = (await db.execute(
            select(AgentRecord).where(AgentRecord.agent_id == agent_id)
        )).scalar_one_or_none()
        return _render(success=f"Certificate uploaded. Thumbprint: {new_thumbprint[:16]}...")

    return _render(error="Unknown action.")


@router.post("/agents/{agent_id:path}/delete", response_class=HTMLResponse)
async def agent_delete(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    agent = await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))
    record = agent.scalar_one_or_none()
    if record:
        # Audit F-B-2 — deleting an agent on a sealed org revokes its
        # binding and nukes its directory entry. Gate on re-auth.
        owner_org = await get_org_by_id(db, record.org_id)
        await _require_sealed_reauth(request, owner_org)

        # Revoke binding if exists
        binding = await get_binding_by_org_agent(db, record.org_id, agent_id)
        if binding and binding.status != "revoked":
            await revoke_binding(db, binding.id)

        # Delete the agent
        await db.delete(record)
        await db.commit()
        await log_event(db, "registry.agent_deleted", "ok",
                        agent_id=agent_id, org_id=record.org_id,
                        details=_sealed_mutation_details(owner_org))

    return RedirectResponse(url="/dashboard/agents", status_code=303)
