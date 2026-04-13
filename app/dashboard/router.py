"""
Dashboard — role-based HTML views of the broker state.

Two roles:
  - admin:  sees all orgs, agents, sessions, audit. Can onboard orgs, approve/reject.
  - org:    sees only own agents, own sessions, own audit. Can register agents.

Authentication via signed cookie set at /dashboard/login.
"""
import asyncio
import io
import re
import json as _json
import pathlib
import zipfile
import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.dashboard.session import (
    get_session, set_session, clear_session, require_login, verify_csrf,
    DashboardSession,
)

from app.db.database import get_db
from app.db.audit import AuditLog, log_event
from app.registry.store import AgentRecord, register_agent, rotate_agent_cert
from app.registry.org_store import (
    OrganizationRecord, register_org, get_org_by_id,
    update_org_ca_cert, set_org_status,
)
from app.registry.binding_store import (
    BindingRecord, create_binding, approve_binding, revoke_binding, get_binding_by_org_agent,
)
from app.policy.store import PolicyRecord, create_policy, get_policy, deactivate_policy
from app.broker.db_models import SessionRecord, SessionMessageRecord, RfqRecord, RfqResponseRecord
from app.broker.ws_manager import ws_manager
from app.auth.transaction_token import create_transaction_token, compute_payload_hash

import logging
_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# ─────────────────────────────────────────────────────────────────────────────
# Login / Logout
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    session = get_session(request)
    if session.logged_in:
        return RedirectResponse(url="/dashboard", status_code=303)
    from app.config import get_settings as _gs
    _s = _gs()
    admin_oidc_enabled = bool(_s.admin_oidc_issuer_url and _s.admin_oidc_client_id)
    return templates.TemplateResponse("login.html", {
        "request": request, "error": None, "admin_oidc_enabled": admin_oidc_enabled,
    })


@router.post("/login")
async def login_submit(request: Request, db: AsyncSession = Depends(get_db)):
    from app.rate_limit.limiter import rate_limiter
    client_ip = request.client.host if request.client else "unknown"
    await rate_limiter.check(client_ip, "dashboard.login")

    form = await request.form()
    user_id = form.get("user_id", "").strip().lower()
    password = form.get("password", "")

    if not user_id or not password:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "User and password are required.",
        })

    # Check if it's the admin
    if user_id == "admin":
        from app.kms.admin_secret import (
            get_admin_secret_hash, verify_admin_password,
            is_admin_password_user_set,
        )
        stored_hash = await get_admin_secret_hash()
        user_set = await is_admin_password_user_set()

        # Path 1 — password has been chosen via /dashboard/setup:
        # only the stored bcrypt hash is trusted. The .env ADMIN_SECRET
        # is no longer accepted (shake-out P0-06).
        if user_set:
            if verify_admin_password(password, stored_hash):
                response = RedirectResponse(url="/dashboard", status_code=303)
                set_session(response, role="admin")
                return response
            return templates.TemplateResponse("login.html", {
                "request": request, "error": "Invalid credentials.",
                "admin_oidc_enabled": False,
            })

        # Path 2 — first-boot bootstrap: no user-set password yet.
        # Accept either the stored hash (bootstrapped in a previous
        # deploy before this change) or the .env ADMIN_SECRET, then
        # force the admin through /dashboard/setup before they can
        # use the rest of the dashboard.
        import hmac as _hmac
        from app.config import get_settings
        ok = False
        if stored_hash and verify_admin_password(password, stored_hash):
            ok = True
        elif _hmac.compare_digest(password, get_settings().admin_secret):
            ok = True
        if ok:
            response = RedirectResponse(url="/dashboard/setup", status_code=303)
            set_session(response, role="admin")
            return response

    # Otherwise try as org
    from app.registry.org_store import verify_org_credentials
    org = await get_org_by_id(db, user_id)
    if verify_org_credentials(org, password):
        response = RedirectResponse(url="/dashboard", status_code=303)
        set_session(response, role="org", org_id=user_id)
        return response

    return templates.TemplateResponse("login.html", {
        "request": request, "error": "Invalid credentials.",
    })


@router.post("/logout")
async def logout(request: Request):
    session = get_session(request)
    if session.logged_in:
        if not await verify_csrf(request, session):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
    response = RedirectResponse(url="/dashboard/login", status_code=303)
    clear_session(response)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# First-boot admin password setup (shake-out P0-06)
# ─────────────────────────────────────────────────────────────────────────────
#
# Flow:
#   1. Fresh deploy: no hash, no user_set flag.
#   2. Admin logs in with .env ADMIN_SECRET. login_submit issues a session
#      but redirects straight to /dashboard/setup instead of /dashboard.
#   3. Admin submits a new password + confirm on /dashboard/setup. The
#      password is bcrypt-hashed, stored in the KMS backend, and the
#      user_set flag is flipped to true.
#   4. Future logins accept only the stored hash — .env ADMIN_SECRET is
#      no longer a valid dashboard credential.
#
# MIN_ADMIN_PASSWORD_LENGTH mirrors the proxy dashboard's policy and is
# intentionally lax: we enforce length only, no complexity rules (per
# NIST SP 800-63B guidance and the P0-06 product directive).

MIN_ADMIN_PASSWORD_LENGTH = 12


@router.get("/setup", response_class=HTMLResponse)
async def admin_setup_page(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    from app.kms.admin_secret import is_admin_password_user_set
    if await is_admin_password_user_set():
        # Already set up; send the admin to the normal change-password flow.
        return RedirectResponse(url="/dashboard/admin/settings", status_code=303)

    return templates.TemplateResponse("admin_setup.html", {
        "request": request,
        "csrf_token": session.csrf_token,
        "min_length": MIN_ADMIN_PASSWORD_LENGTH,
        "error": None,
    })


@router.post("/setup", response_class=HTMLResponse)
async def admin_setup_submit(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    from app.kms.admin_secret import (
        is_admin_password_user_set,
        set_admin_secret_hash,
        mark_admin_password_user_set,
    )
    if await is_admin_password_user_set():
        return RedirectResponse(url="/dashboard/admin/settings", status_code=303)

    if not await verify_csrf(request, session):
        return templates.TemplateResponse("admin_setup.html", {
            "request": request, "csrf_token": session.csrf_token,
            "min_length": MIN_ADMIN_PASSWORD_LENGTH,
            "error": "Invalid CSRF token.",
        }, status_code=400)

    form = await request.form()
    password = str(form.get("password", ""))
    confirm = str(form.get("password_confirm", ""))

    def _err(msg: str, status: int = 400):
        return templates.TemplateResponse("admin_setup.html", {
            "request": request, "csrf_token": session.csrf_token,
            "min_length": MIN_ADMIN_PASSWORD_LENGTH, "error": msg,
        }, status_code=status)

    if not password or not confirm:
        return _err("Both fields are required.")
    if len(password) < MIN_ADMIN_PASSWORD_LENGTH:
        return _err(
            f"Password must be at least {MIN_ADMIN_PASSWORD_LENGTH} characters."
        )
    if password != confirm:
        return _err("The two passwords do not match.")

    import bcrypt
    new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    try:
        await set_admin_secret_hash(new_hash)
        await mark_admin_password_user_set()
    except Exception as exc:
        _log.error("Failed to persist admin password during setup: %s", exc)
        return _err(
            "Failed to save the new password. Check the broker logs "
            "for details (KMS backend may be unreachable).",
            status=500,
        )

    await log_event(db, "admin.first_boot_password_set", "ok",
                    details={"source": "dashboard", "actor": "admin"})

    # Force a fresh sign-in with the newly chosen password, so the
    # existing session (issued from the .env fallback) cannot be
    # reused to skip the setup wall on any future state changes.
    response = RedirectResponse(url="/dashboard/login", status_code=303)
    clear_session(response)
    return response


# ─────────────────────────────────────────────────────────────────────────────
# Public Organization Registration (no login required)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {
        "request": request, "error": None, "success": None, "form": {},
    })


@router.post("/register", response_class=HTMLResponse)
async def register_submit(request: Request, db: AsyncSession = Depends(get_db)):
    from app.rate_limit.limiter import rate_limiter
    client_ip = request.client.host if request.client else "unknown"
    await rate_limiter.check(client_ip, "dashboard.login")

    form_data = await request.form()
    org_id = form_data.get("org_id", "").strip().lower()
    display_name = form_data.get("display_name", "").strip()
    secret = form_data.get("secret", "")
    secret_confirm = form_data.get("secret_confirm", "")

    invite_code = form_data.get("invite_token", "").strip()
    form = {"org_id": org_id, "display_name": display_name}

    if not org_id or not display_name or not secret:
        return templates.TemplateResponse("register.html", {
            "request": request, "form": form,
            "error": "All fields are required.", "success": None,
        })

    # Validate invite token — required to prevent unsolicited registrations
    if not invite_code:
        return templates.TemplateResponse("register.html", {
            "request": request, "form": form,
            "error": "An invite token is required to register.", "success": None,
        })
    from app.onboarding.invite_store import validate_and_consume
    invite_record = await validate_and_consume(db, invite_code, org_id)
    if not invite_record:
        return templates.TemplateResponse("register.html", {
            "request": request, "form": form,
            "error": "Invalid or expired invite token.", "success": None,
        })

    if secret != secret_confirm:
        return templates.TemplateResponse("register.html", {
            "request": request, "form": form,
            "error": "Passwords do not match.", "success": None,
        })

    if len(secret) < 6:
        return templates.TemplateResponse("register.html", {
            "request": request, "form": form,
            "error": "Password must be at least 6 characters.", "success": None,
        })

    id_err = _validate_id(org_id, "Organization ID")
    if id_err:
        return templates.TemplateResponse("register.html", {
            "request": request, "form": form,
            "error": id_err, "success": None,
        })

    existing = await get_org_by_id(db, org_id)
    if existing:
        return templates.TemplateResponse("register.html", {
            "request": request, "form": form,
            "error": f"Organization '{org_id}' already exists.", "success": None,
        })

    await register_org(db, org_id=org_id, display_name=display_name,
                       secret=secret, metadata={"source": "self-registration"},
                       status="pending")
    await log_event(db, "onboarding.self_registration", "ok", org_id=org_id,
                    details={"display_name": display_name, "source": "dashboard"})

    return templates.TemplateResponse("register.html", {
        "request": request, "form": {}, "error": None,
        "success": org_id,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Admin Settings (change admin password)
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Organization Settings (CA certificate upload)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    org = await get_org_by_id(db, session.org_id)
    if not org:
        return RedirectResponse(url="/dashboard/login", status_code=303)

    meta = _json.loads(org.metadata_json or "{}")
    ca_locked = bool(org.ca_certificate) and meta.get("ca_locked", False)
    oidc_mapping = meta.get("oidc_role_mapping") or {}

    return templates.TemplateResponse("settings.html",
        _ctx(request, session, active="settings", org=org, ca_locked=ca_locked,
             oidc_mapping=oidc_mapping,
             error=None, success=None))


@router.post("/settings/ca", response_class=HTMLResponse)
async def settings_upload_ca(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        org = await get_org_by_id(db, session.org_id)
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org,
                 error="Invalid CSRF token.", success=None))

    form_data = await request.form()
    ca_pem = form_data.get("ca_certificate", "").strip()

    org = await get_org_by_id(db, session.org_id)
    if not org:
        return RedirectResponse(url="/dashboard/login", status_code=303)

    # Check if already locked
    meta = _json.loads(org.metadata_json or "{}")
    if bool(org.ca_certificate) and meta.get("ca_locked", False):
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org, ca_locked=True,
                 error="CA certificate is locked. Contact admin to unlock.", success=None))

    if not ca_pem or "-----BEGIN CERTIFICATE-----" not in ca_pem:
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org, ca_locked=False,
                 error="Invalid certificate. Paste a valid PEM certificate.", success=None))

    # Validate the PEM — must be a CA certificate
    try:
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.x509.oid import ExtensionOID
        _ca_cert = load_pem_x509_certificate(ca_pem.encode())
        # Verify BasicConstraints CA=true
        try:
            _bc = _ca_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            if not _bc.value.ca:
                return templates.TemplateResponse("settings.html",
                    _ctx(request, session, active="settings", org=org,
                         error="Certificate is not a CA (BasicConstraints CA=false).", success=None))
        except Exception:
            return templates.TemplateResponse("settings.html",
                _ctx(request, session, active="settings", org=org,
                     error="Certificate missing BasicConstraints extension. Must be a CA certificate.", success=None))
    except Exception:
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org,
                 error="Could not parse the certificate. Ensure it is valid PEM format.", success=None))

    await update_org_ca_cert(db, session.org_id, ca_pem)

    # Lock the CA field
    meta["ca_locked"] = True
    org.metadata_json = _json.dumps(meta)
    await db.commit()

    await log_event(db, "registry.ca_certificate_uploaded", "ok",
                    org_id=session.org_id,
                    details={"source": "dashboard"})

    org = await get_org_by_id(db, session.org_id)
    return templates.TemplateResponse("settings.html",
        _ctx(request, session, active="settings", org=org, ca_locked=True,
             error=None, success="CA certificate uploaded and locked."))


@router.post("/settings/generate-ca", response_class=HTMLResponse)
async def settings_generate_ca(request: Request, db: AsyncSession = Depends(get_db)):
    """Generate a demo CA certificate for the organization.

    The CA private key is stored in the broker's Vault instance.
    This is NOT secure for production — the broker should never hold
    org CA private keys.  Use BYOCA (Bring Your Own CA) in production.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        org = await get_org_by_id(db, session.org_id)
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org,
                 error="Invalid CSRF token.", success=None))

    org = await get_org_by_id(db, session.org_id)
    if not org:
        return RedirectResponse(url="/dashboard/login", status_code=303)

    # Refuse if CA already exists
    meta = _json.loads(org.metadata_json or "{}")
    if org.ca_certificate and meta.get("ca_locked", False):
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org, ca_locked=True,
                 error="CA certificate is already locked.", success=None))

    # Generate org CA using the same logic as generate_certs.py
    import datetime as _dt
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ec as _ec, rsa as _rsa
    from cryptography.x509.oid import NameOID as _NameOID

    form = await request.form()
    key_type = (form.get("key_type") or "rsa").strip().lower()
    if key_type == "ec":
        ca_key = _ec.generate_private_key(_ec.SECP256R1())
    elif key_type == "rsa":
        ca_key = _rsa.generate_private_key(public_exponent=65537, key_size=4096)
    else:
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org,
                 error=f"Unsupported key type {key_type!r}.", success=None))
    now = _dt.datetime.now(_dt.timezone.utc)
    subject = _x509.Name([
        _x509.NameAttribute(_NameOID.COMMON_NAME, f"{org.display_name} CA"),
        _x509.NameAttribute(_NameOID.ORGANIZATION_NAME, session.org_id),
    ])
    ca_cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=365 * 5))
        .add_extension(_x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            _x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, _hashes.SHA256())
    )

    ca_key_pem = ca_key.private_bytes(
        encoding=_ser.Encoding.PEM,
        format=_ser.PrivateFormat.PKCS8,  # TraditionalOpenSSL only encodes RSA
        encryption_algorithm=_ser.NoEncryption(),
    ).decode()
    ca_cert_pem = ca_cert.public_bytes(_ser.Encoding.PEM).decode()

    # Store private key in Vault at secret/data/org/{org_id}
    import os
    import httpx
    vault_addr = os.environ.get("VAULT_ADDR", "http://localhost:8200")
    vault_token = os.environ.get("VAULT_TOKEN", "dev-root-token")
    vault_path = f"secret/data/org/{session.org_id}"
    vault_payload = {"data": {"private_key_pem": ca_key_pem, "ca_cert_pem": ca_cert_pem}}

    try:
        allow_http = os.environ.get("VAULT_ALLOW_HTTP", "").lower() == "true"
        async with httpx.AsyncClient(verify=not allow_http) as client:
            resp = await client.post(
                f"{vault_addr}/v1/{vault_path}",
                headers={"X-Vault-Token": vault_token, "Content-Type": "application/json"},
                json=vault_payload,
                timeout=10,
            )
            if resp.status_code not in (200, 204):
                raise RuntimeError(f"Vault returned HTTP {resp.status_code}")
    except Exception as exc:
        # Fallback: save to disk (dev only)
        import logging
        logging.getLogger("agent_trust").warning(
            "Vault unavailable for org CA storage, falling back to disk: %s", exc)
        certs_dir = pathlib.Path(__file__).parent.parent.parent / "certs" / session.org_id
        certs_dir.mkdir(parents=True, exist_ok=True)
        (certs_dir / "ca-key.pem").write_text(ca_key_pem)
        (certs_dir / "ca-key.pem").chmod(0o600)
        (certs_dir / "ca.pem").write_text(ca_cert_pem)

    # Also save to disk so bundle download works
    certs_dir = pathlib.Path(__file__).parent.parent.parent / "certs" / session.org_id
    certs_dir.mkdir(parents=True, exist_ok=True)
    (certs_dir / "ca-key.pem").write_text(ca_key_pem)
    (certs_dir / "ca-key.pem").chmod(0o600)
    (certs_dir / "ca.pem").write_text(ca_cert_pem)

    # Store public cert in org record and lock
    await update_org_ca_cert(db, session.org_id, ca_cert_pem)
    meta["ca_locked"] = True
    meta["ca_source"] = "broker-generated-demo"
    org.metadata_json = _json.dumps(meta)
    await db.commit()

    await log_event(db, "registry.ca_certificate_generated", "ok",
                    org_id=session.org_id,
                    details={"source": "dashboard", "mode": "demo",
                             "warning": "CA private key stored on broker — not for production"})

    org = await get_org_by_id(db, session.org_id)
    return templates.TemplateResponse("settings.html",
        _ctx(request, session, active="settings", org=org, ca_locked=True,
             error=None,
             success="Demo CA generated. WARNING: The private key is stored on this broker. "
                     "Use Bring Your Own CA (BYOCA) for production deployments."))


@router.post("/settings/oidc-mapping", response_class=HTMLResponse)
async def settings_oidc_mapping(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Update the org's OIDC role mapping (claim_path / admin_values / default_role).

    Empty form values clear the mapping (org reverts to legacy behavior:
    any IdP-authenticated user becomes org admin).
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        org = await get_org_by_id(db, session.org_id)
        meta = _json.loads(org.metadata_json or "{}") if org else {}
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org,
                 ca_locked=bool(org and org.ca_certificate) and meta.get("ca_locked", False),
                 error="Invalid CSRF token.", success=None))

    form_data = await request.form()
    claim_path = form_data.get("claim_path", "").strip()
    admin_values_raw = form_data.get("admin_values", "").strip()
    default_role = form_data.get("default_role", "deny").strip()
    request_scopes_raw = form_data.get("request_scopes", "").strip()

    org = await get_org_by_id(db, session.org_id)
    if not org:
        return RedirectResponse(url="/dashboard/login", status_code=303)
    meta = _json.loads(org.metadata_json or "{}")
    ca_locked = bool(org.ca_certificate) and meta.get("ca_locked", False)

    from app.registry.org_store import update_org_oidc_role_mapping

    # Clear mapping if both fields are empty
    if not claim_path and not admin_values_raw:
        await update_org_oidc_role_mapping(db, session.org_id, None)
        await log_event(db, "dashboard.oidc_mapping_cleared", "ok",
                        org_id=session.org_id)
        org = await get_org_by_id(db, session.org_id)
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org, ca_locked=ca_locked,
                 error=None,
                 success="OIDC role mapping cleared. Org reverts to legacy behavior."))

    # Both fields required when configuring
    if not claim_path or not admin_values_raw:
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org, ca_locked=ca_locked,
                 error="Both claim path and admin values are required.", success=None))

    if default_role not in ("deny", "org"):
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org, ca_locked=ca_locked,
                 error="Default role must be 'deny' or 'org'.", success=None))

    # Parse comma-separated lists
    admin_values = [v.strip() for v in admin_values_raw.split(",") if v.strip()]
    if not admin_values:
        return templates.TemplateResponse("settings.html",
            _ctx(request, session, active="settings", org=org, ca_locked=ca_locked,
                 error="At least one admin value is required.", success=None))

    request_scopes = [s.strip() for s in request_scopes_raw.split(",") if s.strip()]

    mapping = {
        "claim_path": claim_path,
        "admin_values": admin_values,
        "default_role": default_role,
    }
    if request_scopes:
        mapping["request_scopes"] = request_scopes

    await update_org_oidc_role_mapping(db, session.org_id, mapping)
    await log_event(db, "dashboard.oidc_mapping_updated", "ok",
                    org_id=session.org_id,
                    details={"claim_path": claim_path,
                             "admin_values_count": len(admin_values),
                             "default_role": default_role})

    org = await get_org_by_id(db, session.org_id)
    return templates.TemplateResponse("settings.html",
        _ctx(request, session, active="settings", org=org, ca_locked=ca_locked,
             error=None, success="OIDC role mapping updated."))


# ─────────────────────────────────────────────────────────────────────────────
# OIDC federation login
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/oidc/start")
async def oidc_start(
    request: Request,
    role: str = Query(...),
    org_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Initiate OIDC authorization code flow with PKCE."""
    from app.config import get_settings
    from app.dashboard.oidc import create_oidc_state, build_authorization_url, OidcError
    from app.dashboard.session import set_oidc_state

    settings = get_settings()
    if not settings.broker_public_url:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "OIDC requires BROKER_PUBLIC_URL to be configured.",
            "admin_oidc_enabled": False,
        })

    redirect_uri = settings.broker_public_url.rstrip("/") + "/dashboard/oidc/callback"

    if role == "org":
        if not org_id:
            return templates.TemplateResponse("login.html", {
                "request": request, "error": "Organization ID is required for SSO login.",
                "admin_oidc_enabled": False,
            })
        org = await get_org_by_id(db, org_id)
        if not org or not org.oidc_enabled:
            return templates.TemplateResponse("login.html", {
                "request": request, "error": f"Organization '{org_id}' does not have SSO configured.",
                "admin_oidc_enabled": False,
            })
        if org.status != "active":
            return templates.TemplateResponse("login.html", {
                "request": request, "error": f"Organization is '{org.status}', not active.",
                "admin_oidc_enabled": False,
            })
        issuer_url = org.oidc_issuer_url
        client_id = org.oidc_client_id
    elif role == "admin":
        if not settings.admin_oidc_issuer_url or not settings.admin_oidc_client_id:
            return templates.TemplateResponse("login.html", {
                "request": request, "error": "Admin SSO is not configured.",
                "admin_oidc_enabled": False,
            })
        issuer_url = settings.admin_oidc_issuer_url
        client_id = settings.admin_oidc_client_id
    else:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid SSO role.",
            "admin_oidc_enabled": False,
        })

    # If the org has a role mapping configured and it requests extra OIDC
    # scopes (e.g. "groups" for Okta/AzureAD), pass them to the IdP.
    additional_scopes: list[str] | None = None
    if role == "org":
        from app.registry.org_store import get_oidc_role_mapping
        mapping = get_oidc_role_mapping(org)
        if mapping:
            extra = mapping.get("request_scopes")
            if isinstance(extra, list) and extra:
                additional_scopes = [str(s) for s in extra if s]

    flow_state = create_oidc_state(role, org_id)
    try:
        auth_url = await build_authorization_url(
            issuer_url, client_id, redirect_uri, flow_state,
            additional_scopes=additional_scopes,
        )
    except OidcError as e:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": f"SSO error: {e}",
            "admin_oidc_enabled": bool(settings.admin_oidc_issuer_url),
        })

    response = RedirectResponse(url=auth_url, status_code=303)
    set_oidc_state(response, flow_state.to_dict())
    return response


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    """Handle OIDC provider redirect after user authentication."""
    import hmac as _hmac
    from app.config import get_settings
    from app.dashboard.oidc import OidcFlowState, exchange_code_for_identity, OidcError
    from app.dashboard.session import get_oidc_state, clear_oidc_state
    from app.rate_limit.limiter import rate_limiter

    settings = get_settings()
    admin_oidc_enabled = bool(settings.admin_oidc_issuer_url and settings.admin_oidc_client_id)

    client_ip = request.client.host if request.client else "unknown"
    await rate_limiter.check(client_ip, "dashboard.login")

    def _login_error(msg: str):
        return templates.TemplateResponse("login.html", {
            "request": request, "error": msg, "admin_oidc_enabled": admin_oidc_enabled,
        })

    if error:
        return _login_error(f"SSO provider error: {error_description or error}")

    if not code or not state:
        return _login_error("Missing authorization code or state from SSO provider.")

    flow_data = get_oidc_state(request)
    if not flow_data:
        return _login_error("SSO session expired or invalid. Please try again.")

    if not _hmac.compare_digest(state, flow_data.get("state", "")):
        return _login_error("SSO state mismatch — possible CSRF attack.")

    flow_state = OidcFlowState.from_dict(flow_data)
    redirect_uri = settings.broker_public_url.rstrip("/") + "/dashboard/oidc/callback"

    # Determine OIDC config
    if flow_state.role == "org":
        org = await get_org_by_id(db, flow_state.org_id)
        if not org or not org.oidc_enabled:
            return _login_error("Organization SSO configuration not found.")
        issuer_url = org.oidc_issuer_url
        client_id = org.oidc_client_id
        from app.registry.org_store import get_org_oidc_secret
        client_secret = await get_org_oidc_secret(org)
    elif flow_state.role == "admin":
        issuer_url = settings.admin_oidc_issuer_url
        client_id = settings.admin_oidc_client_id
        client_secret = settings.admin_oidc_client_secret or None
    else:
        return _login_error("Invalid SSO role.")

    try:
        identity = await exchange_code_for_identity(
            issuer_url, client_id, client_secret, redirect_uri, code, flow_state
        )
    except OidcError as e:
        _log.warning("OIDC callback failed: %s", e)
        return _login_error(f"SSO authentication failed: {e}")

    # Per-org role mapping: validate IdP claims against the org's policy.
    # If the org has not configured a mapping, the legacy behavior applies
    # (any user authenticated through the org's IdP becomes "org admin").
    if flow_state.role == "org":
        from app.dashboard.oidc import validate_role_mapping
        from app.registry.org_store import get_oidc_role_mapping

        mapping = get_oidc_role_mapping(org)
        allowed, reason = validate_role_mapping(mapping, identity.claims)
        if not allowed:
            await log_event(
                db, "dashboard.oidc_login", "denied",
                org_id=flow_state.org_id,
                details={
                    "role": flow_state.role,
                    "sub": identity.sub,
                    "email": identity.email,
                    "issuer": identity.issuer,
                    "deny_reason": reason,
                },
            )
            _log.warning(
                "OIDC role mapping denied: org=%s sub=%s reason=%s",
                flow_state.org_id, identity.sub, reason,
            )
            return _login_error(
                "You are not authorized to access this organization. "
                "Contact your administrator."
            )

    # Create session
    response = RedirectResponse(url="/dashboard", status_code=303)
    clear_oidc_state(response)

    if flow_state.role == "admin":
        set_session(response, role="admin")
    else:
        set_session(response, role="org", org_id=flow_state.org_id)

    await log_event(db, "dashboard.oidc_login", "ok",
                    org_id=flow_state.org_id,
                    details={
                        "role": flow_state.role,
                        "sub": identity.sub,
                        "email": identity.email,
                        "issuer": identity.issuer,
                    })

    return response


# ─────────────────────────────────────────────────────────────────────────────
# Helper — require login on every page
# ─────────────────────────────────────────────────────────────────────────────

def _ctx(request: Request, session: DashboardSession, **kwargs) -> dict:
    """Build template context with session info and CSRF token."""
    from app.config import get_settings
    _s = get_settings()
    _parsed = urlparse(_s.otel_exporter_otlp_endpoint or "http://localhost:4317")
    _jaeger_host = _parsed.hostname or "localhost"
    _jaeger_scheme = _parsed.scheme or "http"
    jaeger_url = f"{_jaeger_scheme}://{_jaeger_host}:16686"
    return {"request": request, "session": session, "csrf_token": session.csrf_token,
            "jaeger_url": jaeger_url, **kwargs}


# Alphanumeric, hyphens, underscores, colons, dots — max 128 chars
_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:@\-]{0,127}$")
_DISPLAY_NAME_MAX = 256
_CAPABILITY_MAX_LEN = 64
_CAPABILITY_MAX_COUNT = 50


def _validate_id(value: str, field_name: str) -> str | None:
    """Return an error message if the ID is invalid, else None."""
    if not value:
        return None  # emptiness checked elsewhere
    if not _ID_PATTERN.match(value):
        return f"{field_name} must be alphanumeric (hyphens, underscores, colons, dots allowed), max 128 characters."
    return None


def _validate_webhook_url(url: str) -> str | None:
    """Return an error message if the webhook URL is invalid, else None."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        return "Webhook URL must use https:// or http:// scheme."
    if not parsed.hostname:
        return "Webhook URL must have a valid hostname."
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Policy enforcement toggle (admin only, demo mode)
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Overview
# ─────────────────────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def overview(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    # Shake-out P0-06: an admin who logged in via the .env bootstrap
    # credential must set a real password before reaching the overview.
    if session.is_admin:
        from app.kms.admin_secret import is_admin_password_user_set
        if not await is_admin_password_user_set():
            return RedirectResponse(url="/dashboard/setup", status_code=303)

    org_filter = session.org_id  # None for admin = all

    # Stats — scoped by role
    if session.is_admin:
        orgs_total = (await db.execute(select(func.count(OrganizationRecord.org_id)))).scalar() or 0
        orgs_active = (await db.execute(
            select(func.count(OrganizationRecord.org_id)).where(OrganizationRecord.status == "active")
        )).scalar() or 0
    else:
        orgs_total = 1
        orgs_active = 1

    agents_q = select(func.count(AgentRecord.agent_id))
    agents_active_q = select(func.count(AgentRecord.agent_id)).where(AgentRecord.is_active.is_(True))
    if org_filter:
        agents_q = agents_q.where(AgentRecord.org_id == org_filter)
        agents_active_q = agents_active_q.where(AgentRecord.org_id == org_filter)
    agents_total = (await db.execute(agents_q)).scalar() or 0
    agents_active = (await db.execute(agents_active_q)).scalar() or 0

    sessions_q = select(func.count(SessionRecord.session_id)).where(SessionRecord.status == "active")
    if org_filter:
        sessions_q = sessions_q.where(or_(
            SessionRecord.initiator_org_id == org_filter,
            SessionRecord.target_org_id == org_filter,
        ))
    sessions_active = (await db.execute(sessions_q)).scalar() or 0

    audit_q = select(func.count(AuditLog.id))
    if org_filter:
        audit_q = audit_q.where(AuditLog.org_id == org_filter)
    audit_events = (await db.execute(audit_q)).scalar() or 0

    # Recent events
    recent_q = select(AuditLog).order_by(AuditLog.id.desc()).limit(15)
    if org_filter:
        recent_q = recent_q.where(AuditLog.org_id == org_filter)
    recent_events = (await db.execute(recent_q)).scalars().all()

    stats = {
        "orgs": orgs_total, "orgs_active": orgs_active,
        "agents": agents_total, "agents_active": agents_active,
        "sessions_active": sessions_active,
        "audit_events": audit_events,
    }

    from app.config import is_policy_enforced
    return templates.TemplateResponse("overview.html",
        _ctx(request, session, active="overview", stats=stats, recent_events=recent_events,
             policy_enforced=is_policy_enforced())
    )


# ─────────────────────────────────────────────────────────────────────────────
# Organizations
# ─────────────────────────────────────────────────────────────────────────────

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

    org_list = []
    for org in orgs:
        org_list.append({
            "org_id": org.org_id,
            "display_name": org.display_name,
            "status": org.status,
            "webhook_url": org.webhook_url,
            "ca_certificate": org.ca_certificate,
            "oidc_enabled": org.oidc_enabled,
            "agent_count": agent_counts.get(org.org_id, 0),
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


# ─────────────────────────────────────────────────────────────────────────────
# Invite Token Dashboard Actions
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Agents
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/agents", response_class=HTMLResponse)
async def agents_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(AgentRecord).order_by(AgentRecord.org_id, AgentRecord.agent_id)
    if not session.is_admin:
        q = q.where(AgentRecord.org_id == session.org_id)
    agents = (await db.execute(q)).scalars().all()

    binding_statuses = {}
    binding_q = select(BindingRecord.agent_id, BindingRecord.status).order_by(BindingRecord.id.desc())
    for row in (await db.execute(binding_q)).all():
        if row[0] not in binding_statuses:
            binding_statuses[row[0]] = row[1]

    agent_list = []
    for agent in agents:
        agent_list.append({
            "agent_id": agent.agent_id,
            "org_id": agent.org_id,
            "display_name": agent.display_name,
            "is_active": agent.is_active,
            "capabilities": agent.capabilities,
            "binding_status": binding_statuses.get(agent.agent_id),
            "ws_connected": ws_manager.is_connected(agent.agent_id),
            "cert_thumbprint": agent.cert_thumbprint,
        })

    return templates.TemplateResponse("agents.html",
        _ctx(request, session, active="agents", agents=agent_list)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Sessions
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/sessions", response_class=HTMLResponse)
async def sessions_list(
    request: Request,
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(SessionRecord).order_by(SessionRecord.created_at.desc())
    if status:
        q = q.where(SessionRecord.status == status)
    if not session.is_admin:
        q = q.where(or_(
            SessionRecord.initiator_org_id == session.org_id,
            SessionRecord.target_org_id == session.org_id,
        ))
    q = q.limit(100)

    result = await db.execute(q)
    sessions = result.scalars().all()

    # Count messages per session
    msg_counts = {}
    if sessions:
        session_ids = [s.session_id for s in sessions]
        count_q = (
            select(SessionMessageRecord.session_id, func.count(SessionMessageRecord.id))
            .where(SessionMessageRecord.session_id.in_(session_ids))
            .group_by(SessionMessageRecord.session_id)
        )
        for row in (await db.execute(count_q)).all():
            msg_counts[row[0]] = row[1]

    session_list = []
    for s in sessions:
        session_list.append({
            "session_id": s.session_id,
            "initiator_agent_id": s.initiator_agent_id,
            "initiator_org_id": s.initiator_org_id,
            "target_agent_id": s.target_agent_id,
            "target_org_id": s.target_org_id,
            "status": s.status,
            "message_count": msg_counts.get(s.session_id, 0),
            "created_at": s.created_at,
        })

    return templates.TemplateResponse("sessions.html",
        _ctx(request, session, active="sessions", sessions=session_list, status_filter=status)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────────────────────────────

_AUDIT_LIMIT = 200

@router.get("/audit", response_class=HTMLResponse)
async def audit_log(
    request: Request,
    q: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    query = select(AuditLog).order_by(AuditLog.id.desc())
    if not session.is_admin:
        query = query.where(AuditLog.org_id == session.org_id)

    if q:
        q = q[:100]  # Limit search term length to prevent expensive LIKE queries
        # Escape LIKE wildcards in user input to prevent pattern abuse
        _escaped = q.replace("%", r"\%").replace("_", r"\_")
        pattern = f"%{_escaped}%"
        query = query.where(or_(
            AuditLog.event_type.ilike(pattern),
            AuditLog.agent_id.ilike(pattern),
            AuditLog.org_id.ilike(pattern),
            AuditLog.result.ilike(pattern),
            AuditLog.details.ilike(pattern),
        ))

    query = query.limit(_AUDIT_LIMIT)
    result = await db.execute(query)
    events = result.scalars().all()

    # Use timestamp field (named 'timestamp' in the model)
    event_list = []
    for e in events:
        event_list.append({
            "event_type": e.event_type,
            "result": e.result,
            "agent_id": e.agent_id,
            "org_id": e.org_id,
            "details": e.details,
            "created_at": e.timestamp,
            "entry_hash": e.entry_hash,
        })

    return templates.TemplateResponse("audit.html",
        _ctx(request, session, active="audit", events=event_list, query=q or "", limit=_AUDIT_LIMIT)
    )


@router.post("/audit/verify", response_class=HTMLResponse)
async def verify_audit_chain(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin-only: verify the cryptographic integrity of the audit log chain."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from app.db.audit import verify_chain
    is_valid, total, broken_id = await verify_chain(db)

    verify_result = {"valid": is_valid, "total": total, "broken_id": broken_id}

    # Re-render audit page with verification result
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(_AUDIT_LIMIT)
    result = await db.execute(query)
    events = result.scalars().all()
    event_list = [{
        "event_type": e.event_type, "result": e.result,
        "agent_id": e.agent_id, "org_id": e.org_id,
        "details": e.details, "created_at": e.timestamp,
        "entry_hash": e.entry_hash,
    } for e in events]

    return templates.TemplateResponse("audit.html",
        _ctx(request, session, active="audit", events=event_list, query="",
             limit=_AUDIT_LIMIT, verify_result=verify_result)
    )


# ─────────────────────────────────────────────────────────────────────────────
# RFQ Detail & Approval
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/rfqs", response_class=HTMLResponse)
async def rfq_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(RfqRecord).order_by(RfqRecord.created_at.desc()).limit(100)
    if not session.is_admin:
        q = q.where(RfqRecord.initiator_org_id == session.org_id)
    rfqs = (await db.execute(q)).scalars().all()

    return templates.TemplateResponse("rfqs.html",
        _ctx(request, session, active="rfq", rfqs=rfqs)
    )


@router.get("/rfq/{rfq_id}", response_class=HTMLResponse)
async def rfq_detail(request: Request, rfq_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    rfq = (await db.execute(
        select(RfqRecord).where(RfqRecord.rfq_id == rfq_id)
    )).scalar_one_or_none()
    if not rfq:
        raise HTTPException(status_code=404, detail="RFQ not found")

    if not session.is_admin and rfq.initiator_org_id != session.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    responses = (await db.execute(
        select(RfqResponseRecord).where(RfqResponseRecord.rfq_id == rfq_id)
    )).scalars().all()

    return templates.TemplateResponse("rfq_detail.html",
        _ctx(request, session, active="rfq", rfq=rfq, responses=responses,
             success=None, error=None)
    )


@router.post("/rfq/{rfq_id}/approve", response_class=HTMLResponse)
async def rfq_approve(request: Request, rfq_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    rfq = (await db.execute(
        select(RfqRecord).where(RfqRecord.rfq_id == rfq_id)
    )).scalar_one_or_none()
    if not rfq:
        raise HTTPException(status_code=404, detail="RFQ not found")

    if not session.is_admin and rfq.initiator_org_id != session.org_id:
        raise HTTPException(status_code=403, detail="Access denied")

    form = await request.form()
    response_id = form.get("response_id")
    responder_agent_id = form.get("responder_agent_id", "")

    if not response_id:
        raise HTTPException(status_code=400, detail="Missing response_id")

    quote = (await db.execute(
        select(RfqResponseRecord).where(
            RfqResponseRecord.id == int(response_id),
            RfqResponseRecord.rfq_id == rfq_id,
        )
    )).scalar_one_or_none()
    if not quote:
        raise HTTPException(status_code=404, detail="Quote not found")

    payload_hash = compute_payload_hash(quote.payload)
    token_id, token_record = await create_transaction_token(
        db,
        agent_id=rfq.initiator_agent_id,
        org_id=rfq.initiator_org_id,
        txn_type="CREATE_ORDER",
        resource_id=rfq_id,
        payload_hash=payload_hash,
        approved_by=session.org_id if not session.is_admin else "admin",
        rfq_id=rfq_id,
        target_agent_id=responder_agent_id,
    )

    rfq.status = "approved"
    await db.commit()

    try:
        await ws_manager.send_to_agent(rfq.initiator_agent_id, {
            "type": "transaction_token",
            "token_id": token_id,
            "rfq_id": rfq_id,
            "txn_type": "CREATE_ORDER",
            "target_agent_id": responder_agent_id,
            "payload_hash": payload_hash,
        })
    except Exception:
        _log.warning("Could not deliver transaction token to agent %s via WS",
                      rfq.initiator_agent_id)

    await log_event(db, "rfq.approved", "ok",
                    agent_id=rfq.initiator_agent_id, org_id=rfq.initiator_org_id,
                    details={"rfq_id": rfq_id, "approved_quote_id": response_id,
                             "responder_agent_id": responder_agent_id, "token_id": token_id})

    responses = (await db.execute(
        select(RfqResponseRecord).where(RfqResponseRecord.rfq_id == rfq_id)
    )).scalars().all()
    await db.refresh(rfq)

    return templates.TemplateResponse("rfq_detail.html",
        _ctx(request, session, active="rfq", rfq=rfq, responses=responses,
             success=f"Quote approved. Transaction token issued to agent {rfq.initiator_agent_id}.",
             error=None)
    )


# ─────────────────────────────────────────────────────────────────────────────
# HTMX badge fragments — auto-refreshed every 10s
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/badge/pending-orgs", response_class=HTMLResponse)
async def badge_pending_orgs(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    if not session.logged_in or not session.is_admin:
        return ""
    count = (await db.execute(
        select(func.count(OrganizationRecord.org_id))
        .where(OrganizationRecord.status == "pending")
    )).scalar() or 0
    if count > 0:
        return f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-yellow-500/20 text-yellow-400">{count}</span>'
    return ""


@router.get("/badge/pending-sessions", response_class=HTMLResponse)
async def badge_pending_sessions(request: Request, db: AsyncSession = Depends(get_db)):
    session = get_session(request)
    if not session.logged_in:
        return ""
    count_q = select(func.count(SessionRecord.session_id)).where(SessionRecord.status == "pending")
    if not session.is_admin:
        count_q = count_q.where(or_(
            SessionRecord.initiator_org_id == session.org_id,
            SessionRecord.target_org_id == session.org_id,
        ))
    count = (await db.execute(count_q)).scalar() or 0
    if count > 0:
        return f'<span class="px-1.5 py-0.5 rounded-full text-xs bg-yellow-500/20 text-yellow-400">{count}</span>'
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# SSE — real-time dashboard updates
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/sse")
async def dashboard_sse(request: Request):
    session = get_session(request)
    if not session.logged_in:
        raise HTTPException(status_code=401)

    from app.dashboard.sse import sse_manager

    client_id, queue = sse_manager.connect(org_id=session.org_id, is_admin=session.is_admin)

    async def event_stream():
        try:
            yield "event: connected\ndata: ok\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"event: update\ndata: {data}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            sse_manager.disconnect(client_id)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ═════════════════════════════════════════════════════════════════════════════
# OPERATIONS — forms and actions
# ═════════════════════════════════════════════════════════════════════════════


# ─────────────────────────────────────────────────────────────────────────────
# Onboard Organization
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/orgs/onboard/generate-ca")
async def org_onboard_generate_ca(request: Request):
    """Generate a self-signed ECDSA-P256 CA for an org being onboarded.

    Shake-out P1-08: a user without openssl knowledge couldn't paste a CA PEM
    to create their first test org. This endpoint returns a fresh keypair
    (admin-only, CSRF-protected); the UI shows the private key in a modal so
    the user can copy or download it. The key is NOT persisted server-side —
    once the modal is dismissed the private key is unrecoverable.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        # JSON fallback for the HTMX call
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if not session.is_admin:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "admin only"}, status_code=403)
    if not await verify_csrf(request, session):
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "invalid CSRF token"}, status_code=403)

    # Lightweight rate limit per admin session — cheap defense against an
    # accidental autoclicker. 20 generations per 60s is ample for real use.
    # Endpoint is already gated by admin auth + CSRF.
    try:
        from fastapi import HTTPException
        from app.rate_limit.limiter import SlidingWindowLimiter
        global _onboard_ca_limiter  # type: ignore[name-defined]
        if "_onboard_ca_limiter" not in globals():
            _lim = SlidingWindowLimiter()
            _lim.register("onboard-generate-ca", window_seconds=60, max_requests=20)
            globals()["_onboard_ca_limiter"] = _lim
        await globals()["_onboard_ca_limiter"].check(
            subject=session.org_id or "admin", bucket="onboard-generate-ca",
        )
    except HTTPException as _e:
        if _e.status_code == 429:
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "rate limited"}, status_code=429)
        raise
    except Exception:
        # Limiter unavailable (shouldn't happen, in-memory fallback exists).
        # Fail open — we've already checked auth + CSRF.
        pass

    form = await request.form()
    display_name = (form.get("display_name") or "").strip() or "Cullis Test Org"
    # Truncate over-long CN — x509 CN technically allows 64 chars.
    display_name = display_name[:64]

    import datetime as _dt
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID as _NameOID

    ca_key = _ec.generate_private_key(_ec.SECP256R1())
    now = _dt.datetime.now(_dt.timezone.utc)
    subject = _x509.Name([
        _x509.NameAttribute(_NameOID.COMMON_NAME, f"{display_name} CA"),
        _x509.NameAttribute(_NameOID.ORGANIZATION_NAME, display_name),
    ])
    ca_cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))  # tolerate minor clock skew
        .not_valid_after(now + _dt.timedelta(days=365 * 2))
        .add_extension(_x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            _x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, _hashes.SHA256())
    )
    key_pem = ca_key.private_bytes(
        encoding=_ser.Encoding.PEM,
        format=_ser.PrivateFormat.PKCS8,
        encryption_algorithm=_ser.NoEncryption(),
    ).decode()
    cert_pem = ca_cert.public_bytes(_ser.Encoding.PEM).decode()

    _log.info(
        "onboard.generate_ca role=%s display_name=%s serial=%d",
        session.role, display_name, ca_cert.serial_number,
    )
    from fastapi.responses import JSONResponse
    return JSONResponse({"cert_pem": cert_pem, "key_pem": key_pem})


@router.get("/orgs/onboard", response_class=HTMLResponse)
async def org_onboard_form(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("org_onboard.html",
        _ctx(request, session, active="orgs", form={}, error=None, success=None)
    )


@router.post("/orgs/onboard", response_class=HTMLResponse)
async def org_onboard_submit(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form={}, error="Invalid CSRF token. Please try again.", success=None),
            status_code=403)
    form_data = await request.form()
    form = {
        "org_id": form_data.get("org_id", "").strip(),
        "display_name": form_data.get("display_name", "").strip(),
        "secret": form_data.get("secret", ""),
        "contact_email": form_data.get("contact_email", "").strip(),
        "webhook_url": form_data.get("webhook_url", "").strip() or None,
        "ca_certificate": form_data.get("ca_certificate", "").strip(),
    }
    action = form_data.get("action", "pending")

    # Validation
    if not form["org_id"] or not form["display_name"] or not form["secret"]:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form,
                 error="Organization ID, display name, and secret are required.", success=None))

    id_err = _validate_id(form["org_id"], "Organization ID")
    if id_err:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form, error=id_err, success=None))

    if len(form["display_name"]) > _DISPLAY_NAME_MAX:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form,
                 error=f"Display name must be at most {_DISPLAY_NAME_MAX} characters.", success=None))

    webhook_err = _validate_webhook_url(form["webhook_url"] or "")
    if webhook_err:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form, error=webhook_err, success=None))

    if not form["ca_certificate"] or "BEGIN CERTIFICATE" not in form["ca_certificate"]:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form,
                 error="A valid PEM CA certificate is required.", success=None))

    existing = await get_org_by_id(db, form["org_id"])
    if existing:
        return templates.TemplateResponse("org_onboard.html",
            _ctx(request, session, active="orgs", form=form,
                 error=f"Organization '{form['org_id']}' already exists.", success=None))

    # Create org
    await register_org(
        db, org_id=form["org_id"], display_name=form["display_name"],
        secret=form["secret"],
        metadata={"contact_email": form["contact_email"]},
        webhook_url=form["webhook_url"],
    )
    await update_org_ca_cert(db, form["org_id"], form["ca_certificate"])

    # Save optional OIDC configuration
    oidc_issuer = form_data.get("oidc_issuer_url", "").strip() or None
    oidc_cid = form_data.get("oidc_client_id", "").strip() or None
    oidc_csec = form_data.get("oidc_client_secret", "").strip() or None
    if oidc_issuer and oidc_cid:
        from app.registry.org_store import update_org_oidc
        await update_org_oidc(db, form["org_id"], oidc_issuer, oidc_cid, oidc_csec)

    if action == "approve":
        await set_org_status(db, form["org_id"], "active")
        await log_event(db, "onboarding.approved", "ok", org_id=form["org_id"],
                        details={"source": "dashboard"})
        msg = f"Organization '{form['org_id']}' registered and approved."
    else:
        await set_org_status(db, form["org_id"], "pending")
        await log_event(db, "onboarding.join_request", "ok", org_id=form["org_id"],
                        details={"source": "dashboard", "contact_email": form["contact_email"]})
        msg = f"Organization '{form['org_id']}' registered as pending."

    return templates.TemplateResponse("org_onboard.html",
        _ctx(request, session, active="orgs", form={}, error=None, success=msg))


# ─────────────────────────────────────────────────────────────────────────────
# Approve / Reject Organization
# ─────────────────────────────────────────────────────────────────────────────

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
    if org and org.status == "pending":
        await set_org_status(db, org_id, "active")
        await log_event(db, "onboarding.approved", "ok", org_id=org_id,
                        details={"source": "dashboard"})
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
    if org and org.status in ("pending", "active"):
        await set_org_status(db, org_id, "rejected")
        await log_event(db, "onboarding.rejected", "denied", org_id=org_id,
                        details={"source": "dashboard"})
    return RedirectResponse(url="/dashboard/orgs", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Unlock CA Certificate (admin only)
# ─────────────────────────────────────────────────────────────────────────────

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
    if org and org.status == "active":
        await set_org_status(db, org_id, "suspended")
        await log_event(db, "onboarding.suspended", "ok", org_id=org_id,
                        details={"source": "dashboard"})
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
    if org:
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
        await log_event(db, "registry.org_deleted", "ok", org_id=org_id,
                        details={"source": "dashboard"})

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
    if org:
        meta = _json.loads(org.metadata_json or "{}")
        meta["ca_locked"] = False
        org.metadata_json = _json.dumps(meta)
        await db.commit()
        await log_event(db, "registry.ca_certificate_unlocked", "ok",
                        org_id=org_id, details={"source": "dashboard"})

    return RedirectResponse(url="/dashboard/orgs", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Admin — Upload CA certificate for an org
# ─────────────────────────────────────────────────────────────────────────────

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
                    details={"source": "dashboard_admin"})

    org = await get_org_by_id(db, org_id)
    return templates.TemplateResponse("org_upload_ca.html",
        _ctx(request, session, active="orgs", org=org,
             error=None, success="CA certificate uploaded and locked."))


# ─────────────────────────────────────────────────────────────────────────────
# Register Agent
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/agents/register", response_class=HTMLResponse)
async def agent_register_form(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    q = select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
    if not session.is_admin:
        q = q.where(OrganizationRecord.org_id == session.org_id)
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
        if not session.is_admin:
            q = q.where(OrganizationRecord.org_id == session.org_id)
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
                    details={"source": "dashboard", "capabilities": caps})

    # Auto-create and auto-approve binding
    existing_binding = await get_binding_by_org_agent(db, org_id, agent_id)
    if existing_binding and existing_binding.status != "approved":
        await approve_binding(db, existing_binding.id, approved_by="dashboard-admin")
    elif not existing_binding:
        binding = await create_binding(db, org_id, agent_id, scope=caps)
        await approve_binding(db, binding.id, approved_by="dashboard-admin")

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
                        await log_event(db, "registry.agent_cert_uploaded", "ok",
                                        agent_id=agent_id, org_id=org_id,
                                        details={"source": "dashboard", "method": "register"})
                        cert_msg = " Certificate pinned."
            except Exception:
                cert_msg = " Certificate ignored: could not parse PEM."

    return templates.TemplateResponse("agent_register.html",
        _ctx(request, session, active="agents", form={}, orgs=orgs, error=None,
             success=f"Agent '{agent_id}' registered. Binding approved.{cert_msg}"))


# ─────────────────────────────────────────────────────────────────────────────
# Manage Agent (unified settings page)
# ─────────────────────────────────────────────────────────────────────────────

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

    def _render(error=None, success=None):
        return templates.TemplateResponse("agent_manage.html",
            _ctx(request, session, active="agents",
                 agent=agent, binding=binding, ws_connected=ws_connected,
                 error=error, success=success))

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
        await log_event(db, "registry.agent_updated", "ok",
                        agent_id=agent_id, org_id=agent.org_id,
                        details={"source": "dashboard", "fields": ["display_name", "description", "capabilities"]})
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
                        details={"source": "dashboard"})
        # Refresh agent
        agent = (await db.execute(
            select(AgentRecord).where(AgentRecord.agent_id == agent_id)
        )).scalar_one_or_none()
        return _render(success=f"Certificate uploaded. Thumbprint: {new_thumbprint[:16]}...")

    return _render(error="Unknown action.")


# ─────────────────────────────────────────────────────────────────────────────
# Delete Agent
# ─────────────────────────────────────────────────────────────────────────────

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
        # Revoke binding if exists
        binding = await get_binding_by_org_agent(db, record.org_id, agent_id)
        if binding and binding.status != "revoked":
            await revoke_binding(db, binding.id)

        # Delete the agent
        await db.delete(record)
        await db.commit()
        await log_event(db, "registry.agent_deleted", "ok",
                        agent_id=agent_id, org_id=record.org_id,
                        details={"source": "dashboard"})

    return RedirectResponse(url="/dashboard/agents", status_code=303)


# ─────────────────────────────────────────────────────────────────────────────
# Agent Detail — Developer Portal Page
# ─────────────────────────────────────────────────────────────────────────────

def _broker_url_from_request(request: Request) -> str:
    """Compute the broker public URL from request headers."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.hostname)
    port = request.url.port
    if scheme == "https" and port and port != 443:
        return f"{scheme}://{host}:{port}"
    elif scheme == "http" and port and port != 80:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


@router.get("/agents/{agent_id:path}", response_class=HTMLResponse)
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
    if not session.is_admin:
        q = q.where(AuditLog.org_id == session.org_id)
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

    # Verify cert is signed by the org's CA (if CA is uploaded)
    org = await get_org_by_id(db, agent.org_id)
    if org and org.ca_certificate:
        try:
            from cryptography.x509 import load_pem_x509_certificate as _load_cert
            from cryptography.hazmat.primitives.asymmetric import padding
            ca_cert = _load_cert(org.ca_certificate.encode())
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception:
            return _render_error(
                "Certificate signature verification failed. "
                "The certificate must be signed by your organization's CA.")

    # Pin the certificate
    from app.registry.store import rotate_agent_cert
    new_thumbprint = await rotate_agent_cert(db, agent_id, cert_pem)

    await log_event(db, "registry.agent_cert_uploaded", "ok",
                    agent_id=agent_id, org_id=agent.org_id,
                    details={"source": "dashboard", "method": "upload"})

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
    from app.registry.store import rotate_agent_cert
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
                    details={"source": "dashboard"})

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}-credentials.zip"'},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Download Agent Bundle (zip with cert, key, env, scripts, start.sh)
# ─────────────────────────────────────────────────────────────────────────────

def _generate_agent_cert(agent_id: str, org_id: str, org_ca_key, org_ca_cert):
    """Generate agent cert + key in memory. Returns (key_pem, cert_pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    _, agent_name = agent_id.split("::", 1)
    spiffe_id = f"spiffe://atn.local/{org_id}/{agent_name}"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_id),
            ]),
            critical=False,
        )
        .sign(org_ca_key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


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
    from app.registry.store import rotate_agent_cert
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


# ─────────────────────────────────────────────────────────────────────────────
# Rotate Certificate
# ─────────────────────────────────────────────────────────────────────────────

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

    form_data = await request.form()
    cert_pem = form_data.get("certificate", "").strip()

    if not cert_pem:
        return templates.TemplateResponse("cert_rotate.html",
            _ctx(request, session, active="agents", agent=agent,
                 error="Certificate PEM is required.", success=None))

    # Validate the certificate
    from cryptography import x509 as crypto_x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding
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

    # Verify signed by org CA (if CA is configured)
    org = await get_org_by_id(db, agent.org_id)
    if org and org.ca_certificate:
        try:
            org_ca = crypto_x509.load_pem_x509_certificate(org.ca_certificate.encode())
            org_ca.public_key().verify(
                cert.signature, cert.tbs_certificate_bytes,
                padding.PKCS1v15(), cert.signature_hash_algorithm,
            )
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
                    details={"old_thumbprint": old_thumbprint, "new_thumbprint": new_thumbprint,
                             "source": "dashboard"})

    return templates.TemplateResponse("cert_rotate.html",
        _ctx(request, session, active="agents", agent=agent, error=None,
             success=f"Certificate rotated. New thumbprint: {new_thumbprint[:16]}…"))


# ─────────────────────────────────────────────────────────────────────────────
# Policies
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/policies", response_class=HTMLResponse)
async def policies_list(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    if session.is_admin:
        result = await db.execute(
            select(PolicyRecord)
            .where(PolicyRecord.policy_type == "session")
            .order_by(PolicyRecord.org_id, PolicyRecord.policy_id)
        )
    else:
        result = await db.execute(
            select(PolicyRecord)
            .where(PolicyRecord.policy_type == "session", PolicyRecord.org_id == session.org_id)
            .order_by(PolicyRecord.policy_id)
        )
    records = result.scalars().all()

    policy_list = []
    for r in records:
        conds = r.rules.get("conditions", {})
        policy_list.append({
            "policy_id": r.policy_id,
            "org_id": r.org_id,
            "target_orgs": conds.get("target_org_id", []),
            "capabilities": conds.get("capabilities", []),
            "effect": r.rules.get("effect", "allow"),
            "is_active": r.is_active,
        })

    return templates.TemplateResponse("policies.html",
        _ctx(request, session, active="policies", policies=policy_list))


@router.get("/policies/create", response_class=HTMLResponse)
async def policy_create_form(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    orgs = (await db.execute(
        select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
    )).scalars().all()

    return templates.TemplateResponse("policy_create.html",
        _ctx(request, session, active="policies", form={}, orgs=orgs,
             error=None, success=None))


@router.post("/policies/create", response_class=HTMLResponse)
async def policy_create_submit(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/policies", status_code=303)

    form_data = await request.form()
    org_id       = form_data.get("org_id", "").strip()
    target_org   = form_data.get("target_org_id", "").strip()
    caps_raw     = form_data.get("capabilities", "").strip()
    effect       = form_data.get("effect", "allow").strip()

    form = {"org_id": org_id, "target_org_id": target_org, "capabilities": caps_raw, "effect": effect}

    orgs = (await db.execute(
        select(OrganizationRecord).where(OrganizationRecord.status == "active").order_by(OrganizationRecord.org_id)
    )).scalars().all()

    # Org user can only create policies for their own org
    if not session.is_admin and org_id != session.org_id:
        return templates.TemplateResponse("policy_create.html",
            _ctx(request, session, active="policies", form=form, orgs=orgs,
                 error="You can only create policies for your own organization.", success=None))

    if not org_id or not target_org:
        return templates.TemplateResponse("policy_create.html",
            _ctx(request, session, active="policies", form=form, orgs=orgs,
                 error="Organization and target organization are required.", success=None))

    if org_id == target_org:
        return templates.TemplateResponse("policy_create.html",
            _ctx(request, session, active="policies", form=form, orgs=orgs,
                 error="Organization and target must be different.", success=None))

    caps = [c.strip() for c in caps_raw.split(",") if c.strip()] if caps_raw else []

    policy_id = f"{org_id}::session-{target_org}-v1"
    conditions: dict = {"target_org_id": [target_org]}
    if caps:
        conditions["capabilities"] = caps

    existing = await get_policy(db, policy_id)
    if existing:
        return templates.TemplateResponse("policy_create.html",
            _ctx(request, session, active="policies", form=form, orgs=orgs,
                 error=f"Policy '{policy_id}' already exists.", success=None))

    await create_policy(db, policy_id, org_id, "session", {"effect": effect, "conditions": conditions})
    await log_event(db, "policy.created", "ok", org_id=org_id,
                    details={"policy_id": policy_id, "target_org": target_org, "source": "dashboard"})

    return templates.TemplateResponse("policy_create.html",
        _ctx(request, session, active="policies", form={}, orgs=orgs, error=None,
             success=f"Policy '{policy_id}' created. {org_id} → {target_org} [{effect}]"))


@router.post("/policies/{policy_id:path}/deactivate", response_class=HTMLResponse)
async def policy_deactivate(request: Request, policy_id: str, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/policies", status_code=303)

    record = await get_policy(db, policy_id)
    if record:
        if not session.is_admin and record.org_id != session.org_id:
            return RedirectResponse(url="/dashboard/policies", status_code=303)
        await deactivate_policy(db, policy_id)
        await log_event(db, "policy.deactivated", "ok", org_id=record.org_id,
                        details={"policy_id": policy_id, "source": "dashboard"})

    return RedirectResponse(url="/dashboard/policies", status_code=303)
