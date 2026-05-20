"""Mastio dashboard — PKI sub-router.

Sprint F-B-201 PR-8 of 10. Extracts the PKI overview surface
(``/proxy/pki`` page + ``/proxy/pki/export-ca`` download +
``/proxy/pki/rotate-ca`` rotation) from
``mcp_proxy/dashboard/router.py``.

Mounted via ``router.include_router(pki_routes.router)``.

Routes (3):

  GET  /proxy/pki              CA info + agent cert table + Vault status
  POST /proxy/pki/export-ca    download Org CA public cert (CSRF-gated)
  POST /proxy/pki/rotate-ca    regenerate Org CA (CSRF + approval-hook gate)

Shared helpers ``generate_org_ca``, ``_test_vault_connectivity``,
``_store_ca_key_in_vault``, ``_ctx`` live in
``mcp_proxy/dashboard/_helpers.py`` since F-B-201 PR-1 / PR-3. The
approval-hook intercept on ``rotate-ca`` and the CA private-key
handling are preserved verbatim.
"""
from __future__ import annotations

import logging
import pathlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_PKI_ROTATE_CA,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import (
    _ctx,
    _store_ca_key_in_vault,
    _test_vault_connectivity,
    generate_org_ca,
)
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-pki"])


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

    intercept = await maybe_intercept_for_approval(
        session=session, action_type=ACTION_PKI_ROTATE_CA, payload={},
        request=request,
    )
    if intercept is not None:
        return intercept

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
