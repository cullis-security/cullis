"""ADR-011 Phase 1b — BYOCA enrollment endpoint.

``POST /v1/admin/agents/enroll/byoca`` lets an operator bring a
pre-generated Org-CA-signed cert/key pair into a fresh
``internal_agents`` row. The Mastio verifies that the cert chains to
its loaded Org CA (preventing cross-org cert leakage at enrollment
time), extracts the SPIFFE URI SAN if present, and emits the standard
enrollment output: agent_id + cert thumbprint + DPoP jkt pinning if
the caller supplied a public JWK. ADR-014 PR-C: the cert IS the
credential, no api_key is minted.

This is the first of four ``/enroll/<method>`` endpoints in Phase 1.
The ``admin`` (plain create) method remains on the existing
``POST /v1/admin/agents``; ``connector`` is the existing device-code
flow under ``/v1/enrollment/*``; ``spiffe`` lands next in Phase 1c.

Auth: ``X-Admin-Secret``, shared with the rest of ``/v1/admin/*``.
Rate-limit: delegated to the admin-secret bucket (ADR-011 §7.4) —
enrollment is a rare operation and the admin gate is sufficient.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mcp_proxy.auth.dpop import compute_jkt
from mcp_proxy.config import get_settings
from mcp_proxy.db import get_db, log_audit


_log = logging.getLogger("mcp_proxy.admin.enroll")

# Same prefix as the existing agent CRUD router, distinct sub-path.
router = APIRouter(prefix="/v1/admin/agents/enroll", tags=["admin", "enrollment"])


# ── auth (mirrors ``admin.agents._require_admin_secret``) ────────────────

def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    import hmac
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


# ── models ───────────────────────────────────────────────────────────────

class ByocaEnrollRequest(BaseModel):
    agent_name: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    display_name: str = Field("", max_length=256)
    capabilities: list[str] = Field(default_factory=list)
    # Mandatory — this is the whole point of BYOCA enrollment.
    cert_pem: str
    private_key_pem: str
    # Optional — when supplied, pins DPoP binding at enrollment time
    # so F-B-11 ``mode=required`` works from the first request. Public
    # JWK only; ``d`` private material is rejected.
    dpop_jwk: dict | None = None
    federated: bool = False


class ByocaEnrollResponse(BaseModel):
    agent_id: str
    display_name: str
    capabilities: list[str]
    cert_thumbprint: str
    spiffe_id: str | None
    dpop_jkt: str | None


# ── helpers ──────────────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cert_thumbprint(cert: x509.Certificate) -> str:
    """SHA-256 hex of the cert's DER bytes — matches
    ``mcp_proxy.db.cert_thumbprint_from_pem`` and the broker's
    RFC 8705 cert-bound token story."""
    import hashlib
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _spiffe_uri_from_cert(cert: x509.Certificate) -> str | None:
    """Extract the SPIFFE URI from a cert's SAN.extension, if present.

    A BYOCA cert MAY carry a SPIFFE URI (``spiffe://<trust-domain>/<path>``)
    as a URI-valued SAN. When it does we lift it into ``spiffe_id`` so
    the agent gets the full identity envelope from day one — otherwise
    the column stays NULL (fine, ADR-011 §2.2 spiffe_id is optional).
    """
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None
    for name in ext.value:
        if isinstance(name, x509.UniformResourceIdentifier):
            if name.value.startswith("spiffe://"):
                return name.value
    return None


def _key_matches_cert(cert: x509.Certificate, key_pem: str) -> bool:
    """Return True iff the private key's public half matches the cert's
    public key. Guards against a caller mixing up two unrelated files —
    the BYOCA flow depends on the agent actually holding the private
    half of the cert it submits."""
    try:
        priv = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (ValueError, TypeError):
        return False
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_pub = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return cert_pub == priv_pub


def _verify_signed_by_ca(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    """Verify that ``cert`` was issued by ``ca`` — signature check only,
    no path validation (depth 1 by construction in the Org CA model).

    We intentionally don't call ``cert.verify_directly_issued_by`` (too
    new for the cryptography pin) and instead do the algorithm-branching
    verify that matches the broker's ``_verify_cert_chain`` pattern.
    """
    ca_pubkey = ca.public_key()
    try:
        if isinstance(ca_pubkey, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding
            ca_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        if isinstance(ca_pubkey, ec.EllipticCurvePublicKey):
            ca_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            return True
    except Exception:  # noqa: BLE001 — any verify failure → False
        return False
    # Unknown key type: refuse rather than false-accept.
    return False


async def _require_agent_mgr(request: Request):
    """Same gate as ``admin.agents._require_agent_mgr`` — BYOCA needs
    the Org CA to verify the submitted cert, so if the manager has no
    CA loaded the endpoint returns 503."""
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None or not getattr(mgr, "ca_loaded", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent manager not initialized — Org CA not loaded",
        )
    return mgr


def _validate_dpop_jwk(dpop_jwk: dict | None) -> str | None:
    if dpop_jwk is None:
        return None
    if not isinstance(dpop_jwk, dict) or not dpop_jwk:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="dpop_jwk must be a non-empty object",
        )
    if "d" in dpop_jwk:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="dpop_jwk must be the public JWK — private material ('d') rejected",
        )
    kty = dpop_jwk.get("kty")
    if kty not in ("EC", "RSA"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"dpop_jwk kty {kty!r} unsupported — expected 'EC' (P-256) or 'RSA'",
        )
    try:
        return compute_jkt(dpop_jwk)
    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"dpop_jwk is malformed: {exc}",
        ) from exc


# ── endpoint ─────────────────────────────────────────────────────────────

@router.post(
    "/byoca",
    response_model=ByocaEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin_secret)],
)
async def enroll_byoca(
    body: ByocaEnrollRequest,
    request: Request,
) -> ByocaEnrollResponse:
    """Enroll an agent with a caller-supplied Org-CA-signed cert.

    Verification steps:
      1. Parse ``cert_pem`` and ``private_key_pem`` as valid PEM material.
      2. Assert the private key's public half matches the cert (anti
         mix-up / copy-paste error).
      3. Assert the cert is signed by the Mastio's loaded Org CA —
         prevents cross-org cert leakage at enrollment.
      4. Extract SPIFFE URI SAN if present.
      5. Pin optional DPoP jkt.

    Returns the new ``agent_id`` (format ``<org>::<name>``), cert
    thumbprint, and the resolved SPIFFE/DPoP attributes. The agent
    authenticates to ``/v1/egress/*`` by presenting ``cert_pem`` at
    the TLS handshake — that's the credential (ADR-014).
    """
    mgr = await _require_agent_mgr(request)
    agent_name = body.agent_name
    agent_id = f"{mgr.org_id}::{agent_name}"

    # Step 1 — parse PEMs.
    try:
        cert = x509.load_pem_x509_certificate(body.cert_pem.encode())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cert_pem is not a valid X.509 PEM: {exc}",
        ) from exc

    # Step 2 — key matches cert.
    if not _key_matches_cert(cert, body.private_key_pem):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="private_key_pem does not match cert_pem public key",
        )

    # Step 3 — cert signed by the Org CA currently loaded on the Mastio.
    org_ca = getattr(mgr, "_org_ca_cert", None)
    if org_ca is None:
        # _require_agent_mgr should catch this; belt-and-suspenders.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Org CA cert not available on the Mastio",
        )
    if not _verify_signed_by_ca(cert, org_ca):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cert_pem is not signed by this Mastio's Org CA",
        )

    # Step 4 — SPIFFE URI SAN (optional).
    spiffe_id = _spiffe_uri_from_cert(cert)

    # Step 5 — DPoP jkt pinning (optional).
    dpop_jkt = _validate_dpop_jwk(body.dpop_jwk)

    # Persist private key via Vault if available, fall back to proxy_config
    # (identical pattern to ``admin.agents.create_agent``).
    try:
        await mgr._store_key_vault(agent_id, body.private_key_pem)
    except Exception as exc:  # noqa: BLE001
        from mcp_proxy.db import set_config
        _log.info("Vault unavailable for %s (%s) — stashing in proxy_config",
                  agent_id, exc)
        await set_config(f"agent_key:{agent_id}", body.private_key_pem)

    ts = _now_iso()

    try:
        async with get_db() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO internal_agents (
                        agent_id, display_name, capabilities,
                        cert_pem, created_at, is_active,
                        federated, federated_at, federation_revision,
                        enrollment_method, spiffe_id, enrolled_at, dpop_jkt
                    ) VALUES (
                        :aid, :name, :caps,
                        :cert, :now, 1,
                        :federated, NULL, 1,
                        'byoca', :spiffe, :now, :dpop_jkt
                    )
                    """
                ),
                {
                    "aid": agent_id,
                    "name": body.display_name or agent_name,
                    "caps": json.dumps(body.capabilities),
                    "cert": body.cert_pem,
                    "now": ts,
                    "federated": bool(body.federated),
                    "spiffe": spiffe_id,
                    "dpop_jkt": dpop_jkt,
                },
            )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"agent {agent_id} already enrolled",
        ) from exc

    await log_audit(
        agent_id=agent_id,
        action="admin.agent_enroll_byoca",
        status="ok",
        detail=(
            f"org={mgr.org_id} thumbprint={_cert_thumbprint(cert)[:16]} "
            f"spiffe={spiffe_id or '-'} dpop_bound={bool(dpop_jkt)}"
        ),
    )

    return ByocaEnrollResponse(
        agent_id=agent_id,
        display_name=body.display_name or agent_name,
        capabilities=body.capabilities,
        cert_thumbprint=_cert_thumbprint(cert),
        spiffe_id=spiffe_id,
        dpop_jkt=dpop_jkt,
    )


# ─────────────────────────────────────────────────────────────────────────
# ADR-011 Phase 1c — SPIFFE enrollment.
#
# ``/v1/admin/agents/enroll/spiffe`` verifies an SVID (X.509-SVID per
# SPIFFE spec) against a SPIRE trust bundle and emits the standard
# enrollment output: agent_id, one-shot API key, pinned SPIFFE URI.
#
# Trust bundle resolution (first hit wins):
#   1. ``body.trust_bundle_pem`` — useful for sandbox/CI, one-off enroll.
#   2. ``proxy_config.spire_trust_bundle`` — operator-configured baseline.
# Missing both → 503. A future admin endpoint can PATCH the config row.
# ─────────────────────────────────────────────────────────────────────────

class SpiffeEnrollRequest(BaseModel):
    agent_name: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    display_name: str = Field("", max_length=256)
    capabilities: list[str] = Field(default_factory=list)
    # The X.509-SVID leaf + its private key. The SVID MUST carry a
    # ``spiffe://`` URI SAN; that URI becomes the persisted ``spiffe_id``.
    svid_pem: str
    svid_key_pem: str
    # Optional per-request bundle — overrides the proxy_config baseline.
    # Lets CI and sandbox test isolated trust domains without mutating
    # the shared config row.
    trust_bundle_pem: str | None = None
    dpop_jwk: dict | None = None
    federated: bool = False


class SpiffeEnrollResponse(BaseModel):
    agent_id: str
    display_name: str
    capabilities: list[str]
    cert_thumbprint: str
    spiffe_id: str       # MANDATORY for SPIFFE enrollment, unlike BYOCA
    dpop_jkt: str | None


async def _resolve_trust_bundle(body_override: str | None) -> x509.Certificate:
    """Find the SPIRE trust bundle, parse it, return as an x509 Certificate.

    Raises 503 when neither a body override nor a persisted config row
    is available, and 400 when the PEM is syntactically invalid. Kept
    as a thin helper so a future ``PATCH /v1/admin/spire/bundle`` can
    wire in without touching the endpoint body.
    """
    from mcp_proxy.db import get_config
    pem = body_override or await get_config("spire_trust_bundle")
    if not pem:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "SPIRE trust bundle not configured — supply "
                "`trust_bundle_pem` in the body or set the "
                "`spire_trust_bundle` proxy_config key"
            ),
        )
    try:
        return x509.load_pem_x509_certificate(pem.encode())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"trust_bundle_pem is not a valid X.509 PEM: {exc}",
        ) from exc


def _require_spiffe_uri(cert: x509.Certificate) -> str:
    """SPIFFE enrollment requires an SVID — no URI SAN means the cert
    is not a valid SVID and the call must fail before we persist anything."""
    uri = _spiffe_uri_from_cert(cert)
    if uri is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="svid_pem carries no SPIFFE URI SAN — not a valid SVID",
        )
    return uri


@router.post(
    "/spiffe",
    response_model=SpiffeEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin_secret)],
)
async def enroll_spiffe(
    body: SpiffeEnrollRequest,
    request: Request,
) -> SpiffeEnrollResponse:
    """Enroll an agent with a caller-supplied SVID + SPIRE trust bundle.

    Verification:
      1. Parse ``svid_pem`` + ``svid_key_pem`` as valid PEM.
      2. Private key's public half matches the SVID.
      3. SVID has a ``spiffe://`` URI SAN (else the cert is not an SVID).
      4. SVID signed by the resolved SPIRE trust bundle.
      5. Optional DPoP jkt pinning identical to BYOCA.

    Persists ``enrollment_method='spiffe'``, ``spiffe_id=<URI>``, and
    the current SVID bytes under ``cert_pem``. The SVID rotates on the
    SPIRE schedule — future runtime login via API-key+DPoP doesn't
    depend on the stored cert remaining live, so the row is forever
    valid even after the SVID it was enrolled with expires.
    """
    mgr = await _require_agent_mgr(request)
    agent_name = body.agent_name
    agent_id = f"{mgr.org_id}::{agent_name}"

    # Step 1 — parse SVID.
    try:
        svid = x509.load_pem_x509_certificate(body.svid_pem.encode())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"svid_pem is not a valid X.509 PEM: {exc}",
        ) from exc

    # Step 2 — key matches SVID.
    if not _key_matches_cert(svid, body.svid_key_pem):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="svid_key_pem does not match svid_pem public key",
        )

    # Step 3 — SPIFFE URI SAN mandatory for SPIFFE enrollment.
    spiffe_id = _require_spiffe_uri(svid)

    # Step 4 — signed by SPIRE trust bundle.
    bundle = await _resolve_trust_bundle(body.trust_bundle_pem)
    if not _verify_signed_by_ca(svid, bundle):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="svid_pem is not signed by the configured SPIRE trust bundle",
        )

    # Step 5 — DPoP jkt pinning (optional).
    dpop_jkt = _validate_dpop_jwk(body.dpop_jwk)

    try:
        await mgr._store_key_vault(agent_id, body.svid_key_pem)
    except Exception as exc:  # noqa: BLE001
        from mcp_proxy.db import set_config
        _log.info("Vault unavailable for %s (%s) — stashing in proxy_config",
                  agent_id, exc)
        await set_config(f"agent_key:{agent_id}", body.svid_key_pem)

    ts = _now_iso()

    try:
        async with get_db() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO internal_agents (
                        agent_id, display_name, capabilities,
                        cert_pem, created_at, is_active,
                        federated, federated_at, federation_revision,
                        enrollment_method, spiffe_id, enrolled_at, dpop_jkt
                    ) VALUES (
                        :aid, :name, :caps,
                        :cert, :now, 1,
                        :federated, NULL, 1,
                        'spiffe', :spiffe, :now, :dpop_jkt
                    )
                    """
                ),
                {
                    "aid": agent_id,
                    "name": body.display_name or agent_name,
                    "caps": json.dumps(body.capabilities),
                    "cert": body.svid_pem,
                    "now": ts,
                    "federated": bool(body.federated),
                    "spiffe": spiffe_id,
                    "dpop_jkt": dpop_jkt,
                },
            )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"agent {agent_id} already enrolled",
        ) from exc

    await log_audit(
        agent_id=agent_id,
        action="admin.agent_enroll_spiffe",
        status="ok",
        detail=(
            f"org={mgr.org_id} spiffe={spiffe_id} "
            f"thumbprint={_cert_thumbprint(svid)[:16]} "
            f"dpop_bound={bool(dpop_jkt)}"
        ),
    )

    return SpiffeEnrollResponse(
        agent_id=agent_id,
        display_name=body.display_name or agent_name,
        capabilities=body.capabilities,
        cert_thumbprint=_cert_thumbprint(svid),
        spiffe_id=spiffe_id,
        dpop_jkt=dpop_jkt,
    )
