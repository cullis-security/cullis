"""
Onboarding — join request and admin approval.

Flow:
  1. External company calls POST /onboarding/join
     → org created in "pending" state, CA already included
  2. Admin views requests at GET /admin/orgs/pending
  3. Admin approves with POST /admin/orgs/{org_id}/approve
     or rejects with POST /admin/orgs/{org_id}/reject
  4. Approved org → agents can authenticate
"""
from datetime import datetime, timezone, timedelta
from typing import Any

from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_types
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.database import get_db
from app.db.audit import log_event
from app.auth.revocation import revoke_cert, list_revoked_certs
from app.registry.org_store import (
    get_org_by_id,
    get_org_by_trust_domain,
    register_org,
    set_org_sealed,
    update_org_ca_cert,
    update_org_mastio_pubkey,
    update_org_secret,
    update_org_trust_domain,
    update_org_webhook,
    list_pending_orgs,
    set_org_status,
)
from app.rate_limit.limiter import get_client_ip, rate_limiter

onboarding_router = APIRouter(prefix="/onboarding", tags=["onboarding"])
admin_router      = APIRouter(prefix="/admin",      tags=["admin"])


# ── Auth helper ───────────────────────────────────────────────────────────────

def _require_admin(x_admin_secret: str = Header(...)) -> None:
    import hmac
    if not hmac.compare_digest(x_admin_secret, get_settings().admin_secret):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Invalid admin secret")


def _validate_mastio_pubkey(pem: str | None) -> None:
    """Ensure a submitted mastio pubkey is a parseable EC P-256 public key.

    Accepts None (legacy orgs skip this entirely). ES256 — the only
    algorithm the Court uses to verify counter-signatures in Phase 1 —
    requires a P-256 key, so enforce the curve at pin time to fail fast.
    """
    if pem is None:
        return
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    try:
        key = _ser.load_pem_public_key(pem.encode())
    except Exception:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="mastio_pubkey: invalid PEM",
        )
    if not isinstance(key, _ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, _ec.SECP256R1,
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="mastio_pubkey: must be an EC P-256 public key (ES256)",
        )


# ── Models ────────────────────────────────────────────────────────────────────

class JoinRequest(BaseModel):
    org_id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    display_name: str = Field(..., max_length=256)
    secret: str = Field(..., max_length=256)   # org secret — used later for binding approval
    ca_certificate: str            # PEM of the organization's CA
    contact_email: str = ""        # informational for the admin
    webhook_url: str | None = None # PDP webhook URL — None means default-deny
    invite_token: str = Field(..., max_length=64)  # required invite token
    # Optional SPIFFE trust domain — enables SVID-only auth for this org.
    trust_domain: str | None = Field(
        None, max_length=256,
        pattern=r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$",
    )
    # ADR-009 Phase 1 — mastio (proxy) ES256 public key in PEM format.
    # When set, the Court pins it and will require a matching counter-
    # signature header on subsequent auth requests. NULL keeps legacy
    # agent-direct behavior for this org until Phase 3.
    mastio_pubkey: str | None = Field(None, max_length=1024)


class JoinResponse(BaseModel):
    org_id: str
    status: str
    message: str


class RevokeCertRequest(BaseModel):
    serial_hex: str
    org_id: str
    reason: str | None = None
    revoked_by: str = "admin"
    cert_not_after: datetime | None = None   # opzionale — se omesso usa now+1d (safe default)
    agent_id: str | None = None


class RevokeCertResponse(BaseModel):
    serial_hex: str
    org_id: str
    revoked_at: datetime
    agent_id: str | None
    reason: str | None
    message: str


class RevokedCertView(BaseModel):
    serial_hex: str
    org_id: str
    revoked_at: datetime
    revoked_by: str
    reason: str | None
    agent_id: str | None

    model_config = {"from_attributes": True}


class OrgAdminView(BaseModel):
    org_id: str
    display_name: str
    status: str
    contact_email: str
    registered_at: datetime

    model_config = {"from_attributes": True}


# ── Onboarding ────────────────────────────────────────────────────────────────

@onboarding_router.post("/join", response_model=JoinResponse,
                        status_code=status.HTTP_202_ACCEPTED)
async def join_network(
    body: JoinRequest,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Access request to the network from an external organization.
    The org is created in 'pending' state until admin approval.
    Requires a valid invite token generated by the network admin.
    """
    # Rate limit by client IP to prevent registration flood
    client_ip = get_client_ip(request)
    await rate_limiter.check(client_ip, "onboarding.join")

    # ── Validate invite token (must be valid, unused, unexpired, type=org-join) ──
    from app.onboarding.invite_store import validate_and_consume, INVITE_TYPE_ORG_JOIN
    invite = await validate_and_consume(
        db, body.invite_token, body.org_id,
        expected_type=INVITE_TYPE_ORG_JOIN,
    )
    if invite is None:
        await log_event(db, "onboarding.join_rejected", "denied",
                        org_id=body.org_id,
                        details={"reason": "invalid_invite_token"})
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail="Invalid or expired invite token")

    existing = await get_org_by_id(db, body.org_id)
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail="org_id already registered")

    if body.trust_domain:
        clash = await get_org_by_trust_domain(db, body.trust_domain)
        if clash is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail=f"trust_domain '{body.trust_domain}' already claimed by another org",
            )

    _validate_mastio_pubkey(body.mastio_pubkey)

    org = await register_org(
        db,
        org_id=body.org_id,
        display_name=body.display_name,
        secret=body.secret,
        metadata={"contact_email": body.contact_email},
        webhook_url=body.webhook_url,
        trust_domain=body.trust_domain,
        mastio_pubkey=body.mastio_pubkey,
    )
    # Validate CA certificate before storing
    try:
        ca_cert = crypto_x509.load_pem_x509_certificate(body.ca_certificate.encode())
        bc = ca_cert.extensions.get_extension_for_class(crypto_x509.BasicConstraints).value
        if not bc.ca:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="Submitted certificate is not a CA (BasicConstraints CA=false)")
        # Enforce minimum key size
        pub_key = ca_cert.public_key()
        if isinstance(pub_key, rsa_types.RSAPublicKey) and pub_key.key_size < 2048:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail=f"CA RSA key too small ({pub_key.key_size} bits) — minimum 2048 required")
        # Check temporal validity
        now = datetime.now(timezone.utc)
        try:
            not_after = ca_cert.not_valid_after_utc
            not_before = ca_cert.not_valid_before_utc
        except AttributeError:
            not_after = ca_cert.not_valid_after.replace(tzinfo=timezone.utc)
            not_before = ca_cert.not_valid_before.replace(tzinfo=timezone.utc)
        if now > not_after or now < not_before:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="CA certificate is expired or not yet valid")
        # SPIFFE mode: Org CA must authorize at most one level of
        # intermediate below (SPIRE signing intermediate). See ADR-003 §2.4.
        if body.trust_domain and bc.path_length is not None and bc.path_length > 1:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=(f"CA pathLenConstraint is {bc.path_length} — when "
                        f"declaring a SPIFFE trust_domain, pathLen must be ≤ 1"),
            )
    except HTTPException:
        raise
    except Exception as exc:
        import logging
        logging.getLogger("agent_trust").warning("Invalid CA certificate from org '%s': %s", body.org_id, exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail="Invalid CA certificate: could not parse or validate the submitted PEM")

    # Set pending status and load the CA immediately
    await set_org_status(db, body.org_id, "pending")
    await update_org_ca_cert(db, body.org_id, body.ca_certificate)

    await log_event(db, "onboarding.join_request", "ok",
                    org_id=body.org_id,
                    details={"display_name": body.display_name,
                             "contact_email": body.contact_email,
                             "invite_id": invite.id})

    return JoinResponse(
        org_id=org.org_id,
        status="pending",
        message="Request received. Awaiting approval from TrustLink.",
    )


# ── Attach CA to pre-registered org ──────────────────────────────────────────

class AttachCARequest(BaseModel):
    ca_certificate: str              # PEM of the organization's CA
    invite_token: str = Field(..., max_length=64)
    secret: str = Field(..., max_length=256)  # proxy-chosen secret, replaces the placeholder set at org creation
    webhook_url: str | None = None   # PDP webhook; if set, replaces any value the admin may have stored at creation
    # Optional SPIFFE trust domain — enables SVID-only auth. If the org
    # already has a trust_domain set by the broker admin and this value
    # differs, the request is rejected with 409 to prevent silent override.
    trust_domain: str | None = Field(
        None, max_length=256,
        pattern=r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$",
    )
    # ADR-009 Phase 1 — optional mastio (proxy) ES256 public key pinned at
    # attach time. Same semantics as JoinRequest: NULL keeps legacy mode.
    mastio_pubkey: str | None = Field(None, max_length=1024)


class AttachCAResponse(BaseModel):
    org_id: str
    status: str
    message: str


class InviteInspectRequest(BaseModel):
    invite_token: str = Field(..., max_length=64)


class InviteInspectResponse(BaseModel):
    invite_type: str           # "org-join" | "attach-ca"
    org_id: str | None = None  # set only for attach-ca
    expires_at: datetime


@onboarding_router.post("/invite/inspect", response_model=InviteInspectResponse)
async def inspect_invite_endpoint(
    body: InviteInspectRequest,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Look up an invite token and return its type + bound org_id (if any),
    WITHOUT consuming it. Used by the MCP proxy setup wizard to branch
    between /join (new org) and /attach (existing org, add CA).
    """
    client_ip = get_client_ip(request)
    await rate_limiter.check(client_ip, "onboarding.invite_inspect")

    from app.onboarding.invite_store import inspect_invite
    record = await inspect_invite(db, body.invite_token)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            detail="Invite token is invalid, revoked, expired, or already used")
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return InviteInspectResponse(
        invite_type=record.invite_type,
        org_id=record.linked_org_id,
        expires_at=expires_at,
    )


@onboarding_router.post("/attach", response_model=AttachCAResponse,
                        status_code=status.HTTP_200_OK)
async def attach_ca(
    body: AttachCARequest,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Attach a CA certificate to an org that was already registered by the
    broker admin (no CA on file yet). The org_id is taken from the invite
    token's linked_org_id — never trusted from the client — so a stolen
    org-join token cannot hijack a pre-existing org.
    """
    client_ip = get_client_ip(request)
    await rate_limiter.check(client_ip, "onboarding.attach")

    from app.onboarding.invite_store import inspect_invite, validate_and_consume, INVITE_TYPE_ATTACH_CA

    # Look up the invite to discover its bound org_id (without consuming).
    peek = await inspect_invite(db, body.invite_token)
    if peek is None or peek.invite_type != INVITE_TYPE_ATTACH_CA or not peek.linked_org_id:
        await log_event(db, "onboarding.attach_rejected", "denied",
                        details={"reason": "invalid_or_wrong_type_invite"})
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail="Invalid or expired attach-ca invite")
    org_id = peek.linked_org_id

    # Target org must exist and NOT already have a CA.
    org = await get_org_by_id(db, org_id)
    if org is None:
        await log_event(db, "onboarding.attach_rejected", "denied",
                        org_id=org_id,
                        details={"reason": "org_not_found"})
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if org.ca_certificate:
        await log_event(db, "onboarding.attach_rejected", "denied",
                        org_id=org_id,
                        details={"reason": "ca_already_set"})
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail="Organization already has a CA certificate on file")

    # Validate CA PEM (same checks as /join).
    try:
        ca_cert = crypto_x509.load_pem_x509_certificate(body.ca_certificate.encode())
        bc = ca_cert.extensions.get_extension_for_class(crypto_x509.BasicConstraints).value
        if not bc.ca:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="Submitted certificate is not a CA (BasicConstraints CA=false)")
        pub_key = ca_cert.public_key()
        if isinstance(pub_key, rsa_types.RSAPublicKey) and pub_key.key_size < 2048:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail=f"CA RSA key too small ({pub_key.key_size} bits) — minimum 2048 required")
        now = datetime.now(timezone.utc)
        try:
            not_after = ca_cert.not_valid_after_utc
            not_before = ca_cert.not_valid_before_utc
        except AttributeError:
            not_after = ca_cert.not_valid_after.replace(tzinfo=timezone.utc)
            not_before = ca_cert.not_valid_before.replace(tzinfo=timezone.utc)
        if now > not_after or now < not_before:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                detail="CA certificate is expired or not yet valid")
        # SPIFFE mode: same pathLen check as /join — see ADR-003 §2.4.
        # Use the incoming trust_domain if set in this request, else the
        # one already stored on the org.
        effective_td = body.trust_domain or org.trust_domain
        if effective_td and bc.path_length is not None and bc.path_length > 1:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=(f"CA pathLenConstraint is {bc.path_length} — when "
                        f"declaring a SPIFFE trust_domain, pathLen must be ≤ 1"),
            )
    except HTTPException:
        raise
    except Exception as exc:
        import logging
        logging.getLogger("agent_trust").warning(
            "Invalid CA certificate in attach flow for org '%s': %s", org_id, exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            detail="Invalid CA certificate: could not parse or validate the submitted PEM")

    # Atomically consume the invite (re-checks type + linked_org_id match).
    invite = await validate_and_consume(
        db, body.invite_token, org_id,
        expected_type=INVITE_TYPE_ATTACH_CA,
    )
    if invite is None:
        await log_event(db, "onboarding.attach_rejected", "denied",
                        org_id=org_id,
                        details={"reason": "invite_consume_failed"})
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail="Invite token no longer valid")

    # Trust domain: set if missing, reject mismatch, accept no-op.
    if body.trust_domain:
        if org.trust_domain and org.trust_domain != body.trust_domain:
            await log_event(db, "onboarding.attach_rejected", "denied",
                            org_id=org_id,
                            details={"reason": "trust_domain_mismatch"})
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail=(f"org '{org_id}' already has trust_domain "
                        f"'{org.trust_domain}' on file"),
            )
        if not org.trust_domain:
            clash = await get_org_by_trust_domain(db, body.trust_domain)
            if clash is not None and clash.org_id != org_id:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail=(f"trust_domain '{body.trust_domain}' already "
                            f"claimed by another org"),
                )
            await update_org_trust_domain(db, org_id, body.trust_domain)

    _validate_mastio_pubkey(body.mastio_pubkey)

    await update_org_ca_cert(db, org_id, body.ca_certificate)
    # The proxy now owns the org — rotate secret_hash to the proxy-chosen value.
    # The placeholder secret set by the broker admin at creation is discarded.
    await update_org_secret(db, org_id, body.secret)
    # Optionally publish the proxy's PDP webhook URL. Keeping it optional so
    # orgs that don't run their own PDP can stay with whatever the admin
    # configured (or keep None = default-deny).
    if body.webhook_url is not None:
        await update_org_webhook(db, org_id, body.webhook_url)
    # ADR-009 Phase 1 — pin the mastio counter-sig pubkey if supplied.
    if body.mastio_pubkey is not None:
        await update_org_mastio_pubkey(db, org_id, body.mastio_pubkey)
    # Audit F-B-2 — seal the org. The proxy now owns this tenant's
    # identity plane; dashboard mutations from the broker admin require
    # a per-org re-auth gate from this point on.
    await set_org_sealed(db, org_id, True)
    await log_event(db, "onboarding.ca_attached", "ok",
                    org_id=org_id,
                    details={"invite_id": invite.id, "secret_rotated": True,
                             "webhook_updated": body.webhook_url is not None,
                             "mastio_pubkey_pinned": body.mastio_pubkey is not None,
                             "sealed": True})

    return AttachCAResponse(
        org_id=org_id,
        status=org.status,
        message="CA certificate attached and org secret claimed by proxy.",
    )


# ── Admin ─────────────────────────────────────────────────────────────────────

@admin_router.get("/orgs/pending", response_model=list[OrgAdminView],
                  dependencies=[Depends(_require_admin)])
async def list_pending(db: AsyncSession = Depends(get_db)):
    """List organizations awaiting approval."""
    orgs = await list_pending_orgs(db)
    return [
        OrgAdminView(
            org_id=o.org_id,
            display_name=o.display_name,
            status=o.status,
            contact_email=o.extra.get("contact_email", ""),
            registered_at=o.registered_at,
        )
        for o in orgs
    ]


@admin_router.post("/orgs/{org_id}/approve",
                   dependencies=[Depends(_require_admin)])
async def approve_org(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Approve an organization — becomes active and can authenticate."""
    org = await get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if org.status == "active":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Organization already active")

    await set_org_status(db, org_id, "active")
    await log_event(db, "onboarding.approved", "ok", org_id=org_id)

    return {"org_id": org_id, "status": "active",
            "message": f"Organization '{org_id}' approved."}


class MastioPubkeyPatch(BaseModel):
    mastio_pubkey: str | None = Field(None, max_length=1024)


@admin_router.patch("/orgs/{org_id}/mastio-pubkey",
                    dependencies=[Depends(_require_admin)])
async def patch_org_mastio_pubkey(
    org_id: str,
    body: MastioPubkeyPatch,
    db: AsyncSession = Depends(get_db),
):
    """ADR-009 Phase 2 — pin or clear the mastio ES256 counter-signature
    pubkey for an existing org. Enables the counter-sig enforcement flow
    post-proxy-boot (when the proxy generates its mastio identity after
    the broker onboarding has already completed).

    Body ``{mastio_pubkey: null}`` clears the column → reverts to legacy.
    """
    org = await get_org_by_id(db, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")

    _validate_mastio_pubkey(body.mastio_pubkey)
    await update_org_mastio_pubkey(db, org_id, body.mastio_pubkey)
    await log_event(
        db, "admin.mastio_pubkey_patched", "ok",
        org_id=org_id,
        details={"cleared": body.mastio_pubkey is None},
    )
    return {
        "org_id": org_id,
        "mastio_pubkey_set": body.mastio_pubkey is not None,
    }


class RequireMastioMtlsPatch(BaseModel):
    """Body for ``PATCH /v1/admin/orgs/{org_id}/require-mtls`` —
    Wave 3 U4 Phase 2 toggle.
    """
    require_mastio_mtls: bool


@admin_router.patch("/orgs/{org_id}/require-mtls",
                    dependencies=[Depends(_require_admin)])
async def patch_org_require_mastio_mtls(
    org_id: str,
    body: RequireMastioMtlsPatch,
    db: AsyncSession = Depends(get_db),
):
    """Wave 3 U4 Phase 2 — flip per-org Mastio mTLS enforcement.

    When true, federation endpoints (``/v1/auth/token``,
    ``/v1/federation/publish-agent``, ``/v1/federation/publish-stats``)
    reject Mastio calls that don't present a TLS client cert binding
    to the pinned ``mastio_pubkey``. Default false preserves the Phase 1
    verify-if-present behavior, so the flip is opt-in once the
    deployment's terminating layer is wired to surface the peer cert
    (uvicorn ``ssl_cert_reqs=optional`` or nginx ``ssl_verify_client``
    + ``X-Cullis-Mastio-Cert`` header pass-through).
    """
    org = await get_org_by_id(db, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")

    org.require_mastio_mtls = body.require_mastio_mtls
    await db.commit()
    await log_event(
        db, "admin.require_mastio_mtls_patched", "ok",
        org_id=org_id,
        details={"require_mastio_mtls": body.require_mastio_mtls},
    )
    return {
        "org_id": org_id,
        "require_mastio_mtls": body.require_mastio_mtls,
    }


class MastioPubkeyRotateRequest(BaseModel):
    """Body for ``POST /onboarding/orgs/{org_id}/mastio-pubkey/rotate``.

    ADR-012 Phase 2.1. The caller (Mastio) ships the new pubkey plus a
    key-continuity proof signed by the *old* priv key. The Court
    verifies the proof against the currently-pinned ``mastio_pubkey``
    and, on success, updates the pin. No admin auth header is
    required — the proof *is* the auth.
    """

    new_pubkey_pem: str = Field(..., max_length=1024)
    new_cert_pem: str | None = Field(None, max_length=4096)
    proof: dict = Field(...)


class MastioPubkeyRotateResponse(BaseModel):
    org_id: str
    new_kid: str
    rotated_at: str


@onboarding_router.post(
    "/orgs/{org_id}/mastio-pubkey/rotate",
    response_model=MastioPubkeyRotateResponse,
)
async def rotate_org_mastio_pubkey(
    request: Request,
    org_id: str,
    body: MastioPubkeyRotateRequest,
    db: AsyncSession = Depends(get_db),
) -> MastioPubkeyRotateResponse:
    """Rotate the pinned Mastio pubkey via a key-continuity proof.

    Flow:
      1. Rate-limit by client IP (bucket ``onboarding.rotate_mastio_pubkey``)
         so an unauthenticated attacker who guesses an org_id cannot
         burn CPU on ECDSA verify or flood the hash-chain audit log
         (issue #282).
      2. Dedupe on ``(org_id, proof.signature)`` — a legitimate operator
         retry within the 600-second freshness window returns the
         cached response verbatim, short-circuiting ECDSA verify and
         audit append. Failed attempts are NOT cached, so a transient
         failure still re-verifies on retry.
      3. Resolve the org and its currently-pinned ``mastio_pubkey``.
      4. Derive the expected ``old_kid`` from the pinned pubkey.
      5. Parse + verify the submitted continuity proof.
      6. On success, update the pin, emit an audit event, cache the
         response for idempotent retries.
    """
    from app.auth.mastio_rotation_verify import (
        ContinuityProof,
        ContinuityProofError,
        compute_kid_from_pubkey_pem,
        verify_proof,
    )
    from app.onboarding.rotate_dedupe import rotate_dedupe

    client_ip = get_client_ip(request)
    await rate_limiter.check(client_ip, "onboarding.rotate_mastio_pubkey")

    # Parse proof up-front so we have ``signature_b64u`` for the dedupe
    # key. Malformed proofs still 400 — they cannot trigger an audit
    # append, so they do not need the dedupe layer to protect against
    # hash-chain flooding.
    try:
        proof = ContinuityProof.from_dict(body.proof)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"malformed proof: {exc}",
        ) from exc

    async def _do_rotation() -> dict[str, Any]:
        """Verify-and-commit closure run under the dedupe atomic claim.

        Audit L4-H4: previously ``get → verify → store`` was three
        independent locked steps, so two concurrent retries with the
        SAME proof both passed the dedupe ``get``, both verified, and
        both appended ``admin.mastio_pubkey_rotated`` rows to the
        per-org audit chain. ``claim_or_wait`` guarantees this closure
        executes EXACTLY ONCE per ``(org_id, signature_b64u)``; concurrent
        callers attach to the same Future and observe the same result
        (or the same rejection — failures are NOT cached so a transient
        error still re-verifies on retry).
        """
        org = await get_org_by_id(db, org_id)
        if org is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
        if not org.mastio_pubkey:
            # Rotation requires a prior pin. First-pin happens via the
            # admin flow (``PATCH /admin/orgs/{id}/mastio-pubkey``) or the
            # /onboarding/join + /onboarding/attach bootstraps.
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail="organization has no pinned mastio pubkey; use the admin flow for first-pin",
            )

        _validate_mastio_pubkey(body.new_pubkey_pem)

        expected_old_kid = compute_kid_from_pubkey_pem(org.mastio_pubkey)
        try:
            verify_proof(
                proof,
                expected_old_pubkey_pem=org.mastio_pubkey,
                expected_old_kid=expected_old_kid,
            )
        except ContinuityProofError as exc:
            await log_event(
                db, "admin.mastio_pubkey_rotate_rejected", "fail",
                org_id=org_id,
                details={"reason": str(exc), "old_kid": expected_old_kid},
            )
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail=f"continuity proof rejected: {exc}",
            ) from exc

        # Proof-bound consistency: the pubkey in the body must be the one
        # the proof signed over. Defends against a rebind where an
        # attacker replays a valid proof but swaps ``new_pubkey_pem`` in
        # the envelope for a pubkey they control.
        if proof.new_pubkey_pem != body.new_pubkey_pem:
            await log_event(
                db, "admin.mastio_pubkey_rotate_rejected", "fail",
                org_id=org_id,
                details={"reason": "new_pubkey_pem mismatch between envelope and proof"},
            )
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="new_pubkey_pem in envelope does not match the one signed in the proof",
            )

        await update_org_mastio_pubkey(db, org_id, body.new_pubkey_pem)
        rotated_at = datetime.now(timezone.utc).isoformat()
        await log_event(
            db, "admin.mastio_pubkey_rotated", "ok",
            org_id=org_id,
            details={
                "old_kid": expected_old_kid,
                "new_kid": proof.new_kid,
                "rotated_at": rotated_at,
            },
        )
        return {
            "org_id": org_id,
            "new_kid": proof.new_kid,
            "rotated_at": rotated_at,
        }

    response_body = await rotate_dedupe.claim_or_wait(
        org_id, proof.signature_b64u, _do_rotation,
    )
    return MastioPubkeyRotateResponse(**response_body)


@admin_router.post("/orgs/{org_id}/reject",
                   dependencies=[Depends(_require_admin)])
async def reject_org(
    org_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Reject a join request — org transitions to 'rejected' state."""
    org = await get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if org.status not in ("pending", "active"):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail=f"Organization already in state '{org.status}'")

    await set_org_status(db, org_id, "rejected")
    await log_event(db, "onboarding.rejected", "denied", org_id=org_id)

    return {"org_id": org_id, "status": "rejected",
            "message": f"Organization '{org_id}' rejected."}


# ── Invite Tokens ────────────────────────────────────────────────────────────

class InviteCreateRequest(BaseModel):
    label: str = Field("", max_length=256)
    ttl_hours: int = Field(72, ge=1, le=8760)  # 1 hour to 1 year


class InviteResponse(BaseModel):
    id: str
    token: str | None = None  # only set on creation (plaintext shown once)
    label: str
    created_at: datetime
    expires_at: datetime
    used: bool
    used_by_org_id: str | None
    revoked: bool
    invite_type: str = "org-join"
    linked_org_id: str | None = None

    model_config = {"from_attributes": True}


@admin_router.post("/invites", response_model=InviteResponse,
                   status_code=status.HTTP_201_CREATED,
                   dependencies=[Depends(_require_admin)])
async def generate_invite(
    body: InviteCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Generate a one-time invite token for org onboarding."""
    from app.onboarding.invite_store import create_invite

    record, plaintext = await create_invite(
        db, label=body.label, ttl_hours=body.ttl_hours,
    )
    await log_event(db, "admin.invite_created", "ok",
                    details={"invite_id": record.id, "label": body.label,
                             "ttl_hours": body.ttl_hours})
    return InviteResponse(
        id=record.id,
        token=plaintext,
        label=record.label,
        created_at=record.created_at,
        expires_at=record.expires_at,
        used=record.used,
        used_by_org_id=record.used_by_org_id,
        revoked=record.revoked,
        invite_type=record.invite_type,
        linked_org_id=record.linked_org_id,
    )


class AttachInviteCreateRequest(BaseModel):
    label: str = Field("", max_length=256)
    ttl_hours: int = Field(72, ge=1, le=8760)


@admin_router.post("/orgs/{org_id}/attach-invite", response_model=InviteResponse,
                   status_code=status.HTTP_201_CREATED,
                   dependencies=[Depends(_require_admin)])
async def generate_attach_invite(
    org_id: str,
    body: AttachInviteCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a one-time invite bound to an existing org that lets the org
    admin upload its CA certificate via POST /onboarding/attach. The org
    must exist and must not already have a CA on file.
    """
    from app.onboarding.invite_store import create_invite, INVITE_TYPE_ATTACH_CA

    org = await get_org_by_id(db, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
    if org.ca_certificate:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail="Organization already has a CA certificate; "
                                   "use /registry/orgs/{id}/certificate to rotate it")

    record, plaintext = await create_invite(
        db,
        label=body.label or f"attach-ca for {org_id}",
        ttl_hours=body.ttl_hours,
        invite_type=INVITE_TYPE_ATTACH_CA,
        linked_org_id=org_id,
    )
    await log_event(db, "admin.attach_invite_created", "ok",
                    org_id=org_id,
                    details={"invite_id": record.id, "label": body.label,
                             "ttl_hours": body.ttl_hours})
    return InviteResponse(
        id=record.id,
        token=plaintext,
        label=record.label,
        created_at=record.created_at,
        expires_at=record.expires_at,
        used=record.used,
        used_by_org_id=record.used_by_org_id,
        revoked=record.revoked,
        invite_type=record.invite_type,
        linked_org_id=record.linked_org_id,
    )


@admin_router.get("/invites", response_model=list[InviteResponse],
                  dependencies=[Depends(_require_admin)])
async def list_invites_endpoint(db: AsyncSession = Depends(get_db)):
    """List all invite tokens."""
    from app.onboarding.invite_store import list_invites

    records = await list_invites(db)
    return [
        InviteResponse(
            id=r.id,
            token=None,
            label=r.label,
            created_at=r.created_at,
            expires_at=r.expires_at,
            used=r.used,
            used_by_org_id=r.used_by_org_id,
            revoked=r.revoked,
            invite_type=r.invite_type,
            linked_org_id=r.linked_org_id,
        )
        for r in records
    ]


@admin_router.post("/invites/{invite_id}/revoke",
                   dependencies=[Depends(_require_admin)])
async def revoke_invite_endpoint(
    invite_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Revoke an invite token so it can no longer be used."""
    from app.onboarding.invite_store import revoke_invite

    record = await revoke_invite(db, invite_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Invite not found")
    await log_event(db, "admin.invite_revoked", "ok",
                    details={"invite_id": invite_id})
    return {"id": invite_id, "revoked": True, "message": "Invite token revoked."}


@admin_router.post("/certs/revoke", response_model=RevokeCertResponse,
                   dependencies=[Depends(_require_admin)])
async def revoke_certificate(
    body: RevokeCertRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke an agent certificate. From this point on, any authentication
    attempt with this certificate returns 401.
    """
    # If cert_not_after is not provided, use a conservative default (now + 1y)
    # so that lazy cleanup does not remove it immediately
    cert_not_after = body.cert_not_after or (datetime.now(timezone.utc) + timedelta(days=365))

    record = await revoke_cert(
        db,
        serial_hex=body.serial_hex,
        org_id=body.org_id,
        cert_not_after=cert_not_after,
        revoked_by=body.revoked_by,
        agent_id=body.agent_id,
        reason=body.reason,
    )

    await log_event(db, "cert.revoked", "ok",
                    org_id=body.org_id,
                    agent_id=body.agent_id,
                    details={
                        "serial_hex": body.serial_hex,
                        "reason": body.reason,
                        "revoked_by": body.revoked_by,
                    })

    return RevokeCertResponse(
        serial_hex=record.serial_hex,
        org_id=record.org_id,
        revoked_at=record.revoked_at,
        agent_id=record.agent_id,
        reason=record.reason,
        message=f"Certificate {body.serial_hex} revoked.",
    )


@admin_router.get("/certs/revoked", response_model=list[RevokedCertView],
                  dependencies=[Depends(_require_admin)])
async def get_revoked_certs(
    org_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """List revoked certificates, optionally filtered by org."""
    records = await list_revoked_certs(db, org_id=org_id)
    return [RevokedCertView.model_validate(r) for r in records]


# ── Audit Log Export ─────────────────────────────────────────────────────────

@admin_router.get("/audit/export",
                  dependencies=[Depends(_require_admin)])
async def export_audit_logs(
    db: AsyncSession = Depends(get_db),
    start: datetime | None = None,
    end: datetime | None = None,
    org_id: str | None = None,
    event_type: str | None = None,
    format: str = "json",
    limit: int = 10000,
):
    """Export audit logs as JSON (NDJSON) or CSV. Admin-only."""
    import csv
    import io
    import json as json_mod
    from fastapi.responses import StreamingResponse
    from app.db.audit import query_audit_logs

    entries = await query_audit_logs(
        db, start=start, end=end, org_id=org_id,
        event_type=event_type, limit=limit,
    )

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "timestamp", "event_type", "agent_id", "session_id",
            "org_id", "result", "details", "entry_hash", "previous_hash",
        ])
        for e in entries:
            writer.writerow([
                e.id,
                e.timestamp.isoformat() if e.timestamp else "",
                e.event_type, e.agent_id or "", e.session_id or "",
                e.org_id or "", e.result, e.details or "",
                e.entry_hash or "", e.previous_hash or "",
            ])
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
        )

    # Default: NDJSON (newline-delimited JSON)
    # Each line is one of:
    #   {"kind":"entry", ...audit row fields...}
    #   {"kind":"anchor", "org_id":..., "chain_seq":..., "row_hash":...,
    #    "tsa_token_b64":..., "tsa_url":..., "created_at":...}
    # The anchor lines let an offline verifier confirm each per-org
    # chain head was timestamped by an external TSA (or the mock).
    import base64
    from sqlalchemy import select
    from app.db.audit import AuditTsaAnchor
    anchor_stmt = select(AuditTsaAnchor)
    if org_id is not None:
        anchor_stmt = anchor_stmt.where(AuditTsaAnchor.org_id == org_id)
    anchor_stmt = anchor_stmt.order_by(
        AuditTsaAnchor.org_id.asc(), AuditTsaAnchor.chain_seq.asc()
    )
    anchors = (await db.execute(anchor_stmt)).scalars().all()

    # Match the broker's hash-computation timestamp form: tz-aware UTC.
    # SQLite may return tz-naive datetimes on refresh; coerce before
    # serialization so the CLI re-hashes identically.
    from datetime import timezone as _tz

    def _iso(ts):
        if ts is None:
            return None
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_tz.utc)
        return ts.isoformat()

    def _generate():
        for e in entries:
            yield json_mod.dumps({
                "kind": "entry",
                "id": e.id,
                "timestamp": _iso(e.timestamp),
                "event_type": e.event_type,
                "agent_id": e.agent_id,
                "session_id": e.session_id,
                "org_id": e.org_id,
                "result": e.result,
                "details": e.details,
                "entry_hash": e.entry_hash,
                "previous_hash": e.previous_hash,
                "chain_seq": e.chain_seq,
                "peer_org_id": e.peer_org_id,
                "peer_row_hash": e.peer_row_hash,
            }) + "\n"
        for a in anchors:
            yield json_mod.dumps({
                "kind": "anchor",
                "org_id": a.org_id,
                "chain_seq": a.chain_seq,
                "row_hash": a.row_hash,
                "tsa_token_b64": base64.b64encode(a.tsa_token).decode("ascii"),
                "tsa_url": a.tsa_url,
                "created_at": _iso(a.created_at),
            }) + "\n"

    return StreamingResponse(
        _generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=audit_export.ndjson"},
    )
