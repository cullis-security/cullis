"""Court dashboard — Organization onboarding sub-router.

Sprint 2 / F-B-202 PR-6 of 10. Extracts the 3 onboarding routes
(generate-ca + form + submit) into a per-feature sub-router.

Routes (3):

  POST /dashboard/orgs/onboard/generate-ca   mint self-signed P-256 CA
                                              (admin-only, CSRF-gated,
                                              rate-limited per session)
  GET  /dashboard/orgs/onboard               onboarding form
  POST /dashboard/orgs/onboard               register org + attach CA

``_DISPLAY_NAME_MAX`` is imported from the parent router for now
(stays in router.py as an endpoint-specific constant per the F-B-202
PR-1 note); a future micro-refactor can promote it to
``app/dashboard/_helpers.py`` if more sub-routers need it.
"""
from __future__ import annotations

import datetime as _dt
import logging
import pathlib

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.dashboard._helpers import _ctx, _validate_id, _validate_webhook_url
from app.dashboard._template_env import build_templates
from app.dashboard.session import require_login, verify_csrf
from app.db.audit import log_event
from app.db.database import get_db
from app.registry.org_store import (
    get_org_by_id, register_org, set_org_status, update_org_ca_cert,
)

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-org-onboard"])

# Display-name max length — duplicated here from router.py so this
# sub-router stays self-contained. Both constants converge to the same
# value (256) per the F-B-202 PR-1 note; consolidation is a future
# micro-refactor.
_DISPLAY_NAME_MAX = 256


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
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    if not session.is_admin:
        return JSONResponse({"error": "admin only"}, status_code=403)
    if not await verify_csrf(request, session):
        return JSONResponse({"error": "invalid CSRF token"}, status_code=403)

    # Lightweight rate limit per admin session — cheap defense against an
    # accidental autoclicker. 20 generations per 60s is ample for real use.
    # Endpoint is already gated by admin auth + CSRF.
    try:
        from app.rate_limit.limiter import SlidingWindowLimiter
        global _onboard_ca_limiter  # type: ignore[name-defined]
        if "_onboard_ca_limiter" not in globals():
            _lim = SlidingWindowLimiter()
            _lim.register("onboard-generate-ca", window_seconds=60, max_requests=20)
            globals()["_onboard_ca_limiter"] = _lim
        await globals()["_onboard_ca_limiter"].check(
            subject="admin", bucket="onboard-generate-ca",
        )
    except HTTPException as _e:
        if _e.status_code == 429:
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
        # pathLen=1 because the proxy that inherits this Org CA then
        # mints a Mastio intermediate CA (_mint_mastio_ca) underneath
        # it and signs agent leaves under that intermediate. RFC 5280
        # §4.2.1.9: pathLen=0 would forbid the intermediate and any
        # stdlib verifier (OpenSSL, Go crypto/x509, webpki, browser)
        # would reject the full chain at federation/mTLS time. See #280.
        .add_extension(_x509.BasicConstraints(ca=True, path_length=1), critical=True)
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

    # Note: per-org OIDC settings moved to the proxy in the network-admin
    # refactor (ADR-001). The onboard form no longer collects
    # oidc_issuer_url / oidc_client_id / oidc_client_secret.

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
