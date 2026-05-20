"""Court dashboard — Agents credentials + dev-portal sub-router.

Sprint 2 / F-B-202 PR-7b of 10. Extracts the developer-portal detail
page + cert upload + credentials/bundle download + rotate flows
(sections 23+24 of the audit) into a per-feature sub-router.

Routes (7):

  GET  /dashboard/agents/{id}                 developer portal detail page
  GET  /dashboard/agents/{id}/upload-cert     cert upload form
  POST /dashboard/agents/{id}/upload-cert     cert upload submit (sealed-gate)
  POST /dashboard/agents/{id}/credentials    download credentials zip (sealed-gate)
  POST /dashboard/agents/{id}/bundle          download full deploy bundle (sealed-gate)
  GET  /dashboard/agents/{id}/rotate-cert     cert rotate form
  POST /dashboard/agents/{id}/rotate-cert     cert rotate submit (sealed-gate)
"""
from __future__ import annotations

import datetime
import io
import logging
import pathlib
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.broker.ws_manager import ws_manager
from app.dashboard._helpers import (
    _broker_url_from_request, _ctx, _generate_agent_cert,
    _require_sealed_reauth, _sealed_mutation_details,
)
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login, verify_csrf
from app.db.audit import log_event
from app.db.database import get_db
from app.registry.binding_store import get_binding_by_org_agent
from app.registry.org_store import get_org_by_id
from app.registry.store import AgentRecord, rotate_agent_cert

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-agents-credentials"])


# NB: ``{agent_id}`` (default str converter) — NOT ``{agent_id:path}``.
# Routes are evaluated in declaration order, and this detail handler is
# declared above the sub-action routes (``/upload-cert``, ``/rotate-cert``,
# ``/credentials``, ``/bundle``). With the ``:path`` converter the
# detail route greedily captured ``orga::agent-a/rotate-cert`` as
# agent_id, looked it up in the registry, found nothing, and returned
# 404 ``Agent not found`` for every sub-action page — silently breaking
# every cert-management button in the dashboard.
#
# The default str converter refuses to cross a ``/`` so the detail
# handler can no longer eat sub-action suffixes. Agent IDs never
# contain ``/`` (canonical form is ``<org>::<name>``), so no real path
# is lost. Sister-file: declare the most specific routes first OR use
# the default converter on broad ones — pick one rule.
@router.get("/agents/{agent_id}", response_class=HTMLResponse)
async def agent_detail(request: Request, agent_id: str,
                       db: AsyncSession = Depends(get_db)):
    """Developer portal page for a single agent."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    agent = (await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if not session.is_admin and agent.org_id != session.org_id:
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    # Binding
    binding = await get_binding_by_org_agent(db, agent.org_id, agent_id)

    # WebSocket status
    ws_connected = ws_manager.is_connected(agent_id)

    # Certificate expiry
    cert_expiry = None
    if agent.cert_pem:
        try:
            from cryptography.x509 import load_pem_x509_certificate
            cert = load_pem_x509_certificate(agent.cert_pem.encode())
            cert_expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        except Exception:
            pass

    # Recent audit events
    from app.db.audit import AuditLog
    q = (select(AuditLog)
         .where(AuditLog.agent_id == agent_id)
         .order_by(AuditLog.id.desc())
         .limit(10))
    audit_events = (await db.execute(q)).scalars().all()

    broker_url = _broker_url_from_request(request)

    return templates.TemplateResponse("agent_detail.html",
        _ctx(request, session, active="agents",
             agent=agent, binding=binding, ws_connected=ws_connected,
             cert_expiry=cert_expiry, audit_events=audit_events,
             broker_url=broker_url))


@router.get("/agents/{agent_id:path}/upload-cert", response_class=HTMLResponse)
async def agent_upload_cert_form(request: Request, agent_id: str,
                                  db: AsyncSession = Depends(get_db)):
    """Show the standalone certificate upload form."""
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
    return templates.TemplateResponse("cert_upload.html",
        _ctx(request, session, active="agents", agent=agent, error=None, success=None))


@router.post("/agents/{agent_id:path}/upload-cert", response_class=HTMLResponse)
async def agent_upload_cert(request: Request, agent_id: str,
                            db: AsyncSession = Depends(get_db)):
    """Upload an externally signed agent certificate (BYOCA production flow)."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    agent = (await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not session.is_admin and agent.org_id != session.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Audit F-B-2 — pinning a cert on a sealed org's agent rewrites an
    # identity. Gate on the per-org re-auth scope.
    owner_org = await get_org_by_id(db, agent.org_id)
    await _require_sealed_reauth(request, owner_org)

    form_data = await request.form()
    cert_pem = form_data.get("cert_pem", "").strip()

    # Helper to re-render the upload page with an error
    def _render_error(error_msg):
        return templates.TemplateResponse("cert_upload.html",
            _ctx(request, session, active="agents",
                 agent=agent, error=error_msg, success=None))

    if not cert_pem or "-----BEGIN CERTIFICATE-----" not in cert_pem:
        return _render_error("Invalid certificate. Paste a valid PEM certificate.")

    # Parse and validate the certificate
    try:
        from cryptography.x509 import load_pem_x509_certificate
        cert = load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        return _render_error("Could not parse the certificate. Ensure it is valid PEM format.")

    # Verify CN matches agent_id
    from cryptography.x509.oid import NameOID
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs or cn_attrs[0].value != agent_id:
        return _render_error(
            f"Certificate CN '{cn_attrs[0].value if cn_attrs else '(none)'}' "
            f"does not match agent ID '{agent_id}'.")

    # Verify cert is signed by the org's CA (if CA is uploaded). Use the
    # org record we already fetched above for the sealed check.
    #
    # Sister-file with the rotate-cert verifier (same file, lines below):
    # ``public_key().verify`` is keytype-specific — RSA needs a padding
    # argument, EC needs an ECDSA(hash) wrapper. The shipped code only
    # handled RSA, so any tenant with an ECDSA org CA (the 2026-era
    # bootstrap default) silently failed verification on every upload.
    if owner_org and owner_org.ca_certificate:
        try:
            from cryptography.x509 import load_pem_x509_certificate as _load_cert
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
            ca_cert = _load_cert(owner_org.ca_certificate.encode())
            ca_pub = ca_cert.public_key()
            if isinstance(ca_pub, rsa.RSAPublicKey):
                ca_pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            elif isinstance(ca_pub, ec.EllipticCurvePublicKey):
                ca_pub.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            else:
                return _render_error(
                    "Unsupported organization CA key type.")
        except Exception:
            return _render_error(
                "Certificate signature verification failed. "
                "The certificate must be signed by your organization's CA.")

    # Pin the certificate
    new_thumbprint = await rotate_agent_cert(db, agent_id, cert_pem)

    await log_event(
        db, "registry.agent_cert_uploaded", "ok",
        agent_id=agent_id, org_id=agent.org_id,
        details=_sealed_mutation_details(owner_org, extra={"method": "upload"}),
    )

    # Re-read the agent to show updated thumbprint
    agent = (await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one_or_none()
    return templates.TemplateResponse("cert_upload.html",
        _ctx(request, session, active="agents", agent=agent, error=None,
             success=f"Certificate uploaded. Thumbprint: {new_thumbprint[:16]}..."))


@router.post("/agents/{agent_id:path}/credentials")
async def agent_credentials_download(request: Request, agent_id: str,
                                     db: AsyncSession = Depends(get_db)):
    """Generate and download credentials-only bundle (cert + key + env)."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    agent = (await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not session.is_admin and agent.org_id != session.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    org_id = agent.org_id

    # Audit F-B-2 — this endpoint mints fresh (key, cert) material for an
    # agent and pins the cert thumbprint in the DB. If the owning org is
    # sealed, the admin must clear the per-org re-auth gate first.
    owner_org = await get_org_by_id(db, org_id)
    await _require_sealed_reauth(request, owner_org)

    # Load org CA
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate

    certs_dir = pathlib.Path(__file__).parent.parent.parent / "certs"
    org_ca_key_path = certs_dir / org_id / "ca-key.pem"
    org_ca_cert_path = certs_dir / org_id / "ca.pem"

    if not org_ca_key_path.exists() or not org_ca_cert_path.exists():
        raise HTTPException(status_code=500,
            detail=f"Org CA not found for '{org_id}'. Upload CA certificate first.")

    org_ca_key = load_pem_private_key(org_ca_key_path.read_bytes(), password=None)
    org_ca_cert = load_pem_x509_certificate(org_ca_cert_path.read_bytes())

    # Generate cert + key
    key_pem, cert_pem = _generate_agent_cert(agent_id, org_id, org_ca_key, org_ca_cert)

    # Pin cert in DB
    await rotate_agent_cert(db, agent_id, cert_pem.decode())

    broker_url = _broker_url_from_request(request)

    # Minimal env — just connection essentials
    env_content = (
        f"# Cullis — credentials\n"
        f"# Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
        f"BROKER_URL={broker_url}\n"
        f"AGENT_ID={agent_id}\n"
        f"ORG_ID={org_id}\n"
        f"CAPABILITIES={','.join(agent.capabilities)}\n"
    )

    # Build credentials-only zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("agent.pem", cert_pem)
        zf.writestr("agent-key.pem", key_pem)
        zf.writestr("agent.env", env_content)

    buf.seek(0)
    safe_name = agent_id.replace("::", "__")

    await log_event(db, "registry.agent_credentials_generated", "ok",
                    agent_id=agent_id, org_id=org_id,
                    details=_sealed_mutation_details(owner_org))

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}-credentials.zip"'},
    )


@router.post("/agents/{agent_id:path}/bundle")
async def agent_bundle_download(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    """Generate and download a deploy bundle (zip) for an agent."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    # Load agent record
    agent = (await db.execute(
        select(AgentRecord).where(AgentRecord.agent_id == agent_id)
    )).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Org user can only download own agents
    if not session.is_admin and agent.org_id != session.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    org_id = agent.org_id
    caps = agent.capabilities

    # Audit F-B-2 — this endpoint mints fresh (key, cert) material and
    # pins the thumbprint in the DB. Same threat model as /credentials
    # above — sealed orgs need the per-org re-auth gate.
    owner_org = await get_org_by_id(db, org_id)
    await _require_sealed_reauth(request, owner_org)

    # Load org CA to sign agent cert
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate

    certs_dir = pathlib.Path(__file__).parent.parent.parent / "certs"
    org_ca_key_path = certs_dir / org_id / "ca-key.pem"
    org_ca_cert_path = certs_dir / org_id / "ca.pem"

    if not org_ca_key_path.exists() or not org_ca_cert_path.exists():
        raise HTTPException(status_code=500,
            detail=f"Org CA not found for '{org_id}'. Run join.py first.")

    org_ca_key = load_pem_private_key(org_ca_key_path.read_bytes(), password=None)
    org_ca_cert = load_pem_x509_certificate(org_ca_cert_path.read_bytes())

    # Generate agent cert + key
    key_pem, cert_pem = _generate_agent_cert(agent_id, org_id, org_ca_key, org_ca_cert)

    # Pin cert in DB
    await rotate_agent_cert(db, agent_id, cert_pem.decode())

    # Determine broker URL from request
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.hostname)
    port = request.url.port
    if scheme == "https" and port and port != 443:
        broker_url = f"{scheme}://{host}:{port}"
    elif scheme == "http" and port and port != 80:
        broker_url = f"{scheme}://{host}:{port}"
    else:
        broker_url = f"{scheme}://{host}"

    # Build .env content
    safe_name = agent_id.replace("::", "__")
    env_content = (
        f"# Cullis — deploy bundle\n"
        f"# Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
        f"BROKER_URL={broker_url}\n"
        f"AGENT_ID={agent_id}\n"
        f"ORG_ID={org_id}\n"
        f"DISPLAY_NAME={agent.display_name}\n"
        f"AGENT_CERT_PATH=./{safe_name}.pem\n"
        f"AGENT_KEY_PATH=./{safe_name}-key.pem\n"
        f"ORG_SECRET={org_id}\n"
        f"CAPABILITIES={','.join(caps)}\n"
        f"POLL_INTERVAL=2\n"
        f"MAX_TURNS=20\n"
        f"\n"
        f"# LLM backend\n"
        f"LLM_MODEL=claude-sonnet-4-6\n"
        f"ANTHROPIC_API_KEY=\n"
    )

    # Build start.sh — authenticates agent and connects to the network
    start_sh = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'cd "$(dirname "$0")"\n'
        'echo "Connecting agent to ATN broker..."\n'
        "python agent_node.py --config agent.env \"$@\"\n"
    )

    # Read the demo scripts to include in bundle
    demo_dir = pathlib.Path(__file__).parent.parent.parent / "demo"
    sdk_path = pathlib.Path(__file__).parent.parent.parent / "agents" / "sdk.py"

    # Build the zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Cert and key
        zf.writestr(f"{safe_name}.pem", cert_pem)
        zf.writestr(f"{safe_name}-key.pem", key_pem)

        # Env
        zf.writestr("agent.env", env_content)

        # start.sh (executable)
        info = zipfile.ZipInfo("start.sh")
        info.external_attr = 0o755 << 16
        zf.writestr(info, start_sh)

        # SDK
        if sdk_path.exists():
            zf.writestr("agents/sdk.py", sdk_path.read_text())
            zf.writestr("agents/__init__.py", "")

        # All demo scripts — the user decides what to run
        for name in ("agent_node.py", "buyer_agent.py", "supplier_agent.py",
                      "inventory_watcher.py", "inventory.json"):
            path = demo_dir / name
            if path.exists():
                zf.writestr(name, path.read_text())

    buf.seek(0)
    filename = f"{safe_name}-bundle.zip"

    await log_event(db, "registry.agent_bundle_downloaded", "ok",
                    agent_id=agent_id, org_id=org_id,
                    details={"source": "dashboard"})

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/agents/{agent_id:path}/rotate-cert", response_class=HTMLResponse)
async def cert_rotate_form(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    agent = (await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))).scalar_one_or_none()
    if not agent:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    if not session.is_admin and agent.org_id != session.org_id:
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    return templates.TemplateResponse("cert_rotate.html",
        _ctx(request, session, active="agents", agent=agent, error=None, success=None))


@router.post("/agents/{agent_id:path}/rotate-cert", response_class=HTMLResponse)
async def cert_rotate_submit(request: Request, agent_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    agent = (await db.execute(select(AgentRecord).where(AgentRecord.agent_id == agent_id))).scalar_one_or_none()
    if not agent:
        return RedirectResponse(url="/dashboard/agents", status_code=303)
    if not session.is_admin and agent.org_id != session.org_id:
        return RedirectResponse(url="/dashboard/agents", status_code=303)

    # Audit F-B-2 — rotating a cert on a sealed org's agent rewrites its
    # identity. Gate on the per-org re-auth scope.
    owner_org = await get_org_by_id(db, agent.org_id)
    await _require_sealed_reauth(request, owner_org)

    form_data = await request.form()
    cert_pem = form_data.get("certificate", "").strip()

    if not cert_pem:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error="Certificate PEM is required.", success=None))

    # Validate the certificate
    from cryptography import x509 as crypto_x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import NameOID

    try:
        cert = crypto_x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error="Invalid PEM certificate.", success=None))

    # Verify CN matches agent_id
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs or cn_attrs[0].value != agent_id:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error=f"Certificate CN does not match agent '{agent_id}'.",
                 success=None))

    # Verify signed by org CA (if CA is configured). Reuse owner_org from
    # the sealed-check step above so we don't hit the DB twice.
    #
    # ``public_key().verify(...)`` is keytype-specific: RSA wants a
    # padding argument, EC wants an ECDSA(hash) wrapper. The earlier
    # shipped code hard-coded the RSA shape (``padding.PKCS1v15()``)
    # which made every EC-CA tenant fall into the generic
    # ``except Exception`` branch and saw "Certificate verification
    # failed" no matter how good the cert was. Bootstrap CAs in
    # 2026-era stacks are ECDSA P-256 by default, so this affected
    # every modern org.
    if owner_org and owner_org.ca_certificate:
        try:
            org_ca = crypto_x509.load_pem_x509_certificate(owner_org.ca_certificate.encode())
            ca_pub = org_ca.public_key()
            if isinstance(ca_pub, rsa.RSAPublicKey):
                ca_pub.verify(
                    cert.signature, cert.tbs_certificate_bytes,
                    padding.PKCS1v15(), cert.signature_hash_algorithm,
                )
            elif isinstance(ca_pub, ec.EllipticCurvePublicKey):
                ca_pub.verify(
                    cert.signature, cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            else:
                return templates.TemplateResponse("cert_rotate.html",
                    _ctx(request, session, active="agents", agent=agent,
                         error="Unsupported organization CA key type.", success=None))
        except InvalidSignature:
            return templates.TemplateResponse("cert_rotate.html",
                _ctx(request, session, active="agents", agent=agent,
                     error="Certificate is not signed by the organization CA.", success=None))
        except Exception:
            return templates.TemplateResponse("cert_rotate.html",
                _ctx(request, session, active="agents", agent=agent,
                     error="Certificate verification failed. Please check the certificate is valid and signed by the organization CA.", success=None))

    old_thumbprint = agent.cert_thumbprint
    new_thumbprint = await rotate_agent_cert(db, agent_id, cert_pem)

    await log_event(db, "agent.cert_rotated", "ok",
                    agent_id=agent_id, org_id=agent.org_id,
                    details=_sealed_mutation_details(
                        owner_org,
                        extra={"old_thumbprint": old_thumbprint,
                               "new_thumbprint": new_thumbprint},
                    ))

    return templates.TemplateResponse("cert_rotate.html",
        _ctx(request, session, active="agents", agent=agent, error=None,
             success=f"Certificate rotated. New thumbprint: {new_thumbprint[:16]}…"))
