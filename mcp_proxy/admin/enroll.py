"""ADR-011 Phase 1b — BYOCA enrollment endpoint.

``POST /v1/admin/agents/enroll/byoca`` lets an operator bring a
pre-generated Org-CA-signed cert/key pair into a fresh
``internal_agents`` row. The Mastio verifies that the cert chains to
its loaded Org CA (preventing cross-org cert leakage at enrollment
time), extracts the SPIFFE URI SAN if present, and emits the standard
enrollment output: agent_id + one-shot API key + DPoP jkt pinning if
the caller supplied a public JWK.

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

import bcrypt
import secrets
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
    api_key: str  # plaintext — shown exactly once
    cert_thumbprint: str
    spiffe_id: str | None
    dpop_jkt: str | None


# ── helpers ──────────────────────────────────────────────────────────────

def _api_key_for(agent_name: str) -> str:
    """Match the pattern used by ``admin.agents._api_key_for`` so audit
    trails and key-hygiene scripts see a consistent prefix."""
    return f"sk_local_{agent_name}_{secrets.token_hex(16)}"


def _bcrypt_hash(raw: str) -> str:
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt(rounds=12)).decode()


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
      5. Issue an API key + pin optional DPoP jkt.

    Returns the new ``agent_id`` (format ``<org>::<name>``), the
    one-shot plaintext API key (shown once), cert thumbprint, and the
    resolved SPIFFE/DPoP attributes.
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

    api_key = _api_key_for(agent_name)
    api_key_hash = _bcrypt_hash(api_key)
    ts = _now_iso()

    try:
        async with get_db() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO internal_agents (
                        agent_id, display_name, capabilities, api_key_hash,
                        cert_pem, created_at, is_active,
                        federated, federated_at, federation_revision,
                        enrollment_method, spiffe_id, enrolled_at, dpop_jkt
                    ) VALUES (
                        :aid, :name, :caps, :hash,
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
                    "hash": api_key_hash,
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
        api_key=api_key,
        cert_thumbprint=_cert_thumbprint(cert),
        spiffe_id=spiffe_id,
        dpop_jkt=dpop_jkt,
    )
