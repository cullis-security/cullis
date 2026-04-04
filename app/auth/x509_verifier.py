"""
x509 certificate verification for agent authentication.

Flow:
  1. The agent constructs a JWT (client_assertion) signed with its private key.
     The header contains x5c: [<base64(DER(agent-cert))>].
  2. The broker extracts the cert from the header, verifies its chain against the org CA
     (registered in DB), then verifies the JWT signature using the cert's public key.
  3. If everything is OK, returns (agent_id, org_id, cert_pem, cert_thumbprint).
"""
import base64
import datetime
import hashlib
import time as _time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from fastapi import HTTPException, status
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jti_blacklist import check_and_consume_jti
from app.auth.revocation import check_cert_not_revoked
from app.registry.org_store import get_org_by_id
from app.config import get_settings
from app.spiffe import internal_id_to_spiffe
from app.telemetry import tracer
from app.telemetry_metrics import X509_VERIFY_DURATION_HISTOGRAM

_AUDIENCE = "agent-trust-broker"
_ALLOWED_HASH_ALGORITHMS = (hashes.SHA256, hashes.SHA384, hashes.SHA512)


async def verify_client_assertion(assertion: str, db: AsyncSession) -> tuple[str, str, str, str]:
    """
    Verify a client_assertion JWT and return (agent_id, org_id, cert_pem, cert_thumbprint).
    cert_pem is the agent certificate extracted from x5c — it is saved in DB
    by the auth router to allow verification of message signatures.
    cert_thumbprint is the SHA-256 hex digest of the DER-encoded certificate.

    Raises HTTPException 401/403 if verification fails.
    """
    _t0 = _time.monotonic()
    with tracer.start_as_current_span("auth.x509_verify") as _span:
      return await _verify_client_assertion_inner(assertion, db, _span, _t0)


async def _verify_client_assertion_inner(assertion, db, _span, _t0):
    # ── 1. Header without verification ──────────────────────────────────────
    try:
        header = jwt.get_unverified_header(assertion)
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid client_assertion")

    x5c = header.get("x5c")
    if not x5c or not isinstance(x5c, list) or len(x5c) == 0:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="x5c header absent or empty")

    # ── 2. Load agent cert from x5c[0] and compute thumbprint ──────────────
    try:
        cert_der = base64.b64decode(x5c[0])
        agent_cert = x509.load_der_x509_certificate(cert_der)
        cert_thumbprint = hashlib.sha256(cert_der).hexdigest()
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid agent certificate")

    # ── 3. Extract CN (agent_id) and O (org_id) ──────────────────────────────
    try:
        cn_attrs = agent_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        org_attrs = agent_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if not cn_attrs or not org_attrs:
            raise ValueError("CN or O missing from certificate")
        agent_id = cn_attrs[0].value
        org_id = org_attrs[0].value
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Cert missing CN or O")

    # ── 4. Load org CA from DB and verify it is a true CA ────────────────────
    org = await get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Organisation '{org_id}' not found")
    if org.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            detail=f"Organisation '{org_id}' not yet approved")
    if not org.ca_certificate:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"CA not configured for org '{org_id}'")

    try:
        org_ca = x509.load_pem_x509_certificate(org.ca_certificate.encode())
        bc = org_ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            raise ValueError("registered org CA certificate does not have BasicConstraints CA=true")
    except Exception as exc:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Broker configuration error: invalid org CA — {exc}",
        )

    # ── 5. Enforce algorithm whitelist, then verify chain ────────────────────
    if not isinstance(agent_cert.signature_hash_algorithm, _ALLOWED_HASH_ALGORITHMS):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Agent certificate uses a weak signature algorithm — SHA-256 or stronger required",
        )

    with tracer.start_as_current_span("auth.x509_chain_verify"):
        try:
            org_ca.public_key().verify(
                agent_cert.signature,
                agent_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                agent_cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="Agent certificate not signed by the registered org CA",
            )
        except Exception as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=f"Chain verification failed: {exc}")

    # ── 6. Verify cert temporal validity ─────────────────────────────────────
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        not_after = agent_cert.not_valid_after_utc
        not_before = agent_cert.not_valid_before_utc
    except AttributeError:
        # cryptography < 42 uses naive attributes
        not_after = agent_cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        not_before = agent_cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

    if now > not_after or now < not_before:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Agent certificate expired or not yet valid")

    # ── 7. Revocation check ──────────────────────────────────────────────────
    serial_hex = format(agent_cert.serial_number, 'x')
    await check_cert_not_revoked(db, serial_hex)

    # ── 8. Extract agent public key for JWT signature verification ────────────
    pub_key_pem = agent_cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # ── 9. Verify JWT signature and payload ──────────────────────────────────
    try:
        payload = jwt.decode(
            assertion,
            pub_key_pem,
            algorithms=["RS256"],
            audience=_AUDIENCE,
            options={"verify_aud": True, "verify_exp": True},
        )
    except JWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=f"Invalid client_assertion signature: {exc}")

    # ── 10. Verify sub and iss — bind JWT tightly to the authenticated agent ──
    settings = get_settings()
    expected_spiffe = internal_id_to_spiffe(agent_id, settings.trust_domain)

    sub = payload.get("sub")
    if sub not in (agent_id, expected_spiffe):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="'sub' in JWT does not match the agent CN or SPIFFE URI",
        )

    iss = payload.get("iss")
    if iss not in (agent_id, expected_spiffe):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="'iss' in JWT is missing or does not match the authenticated agent",
        )

    # ── 11. Verify SPIFFE SAN (if present or required) ───────────────────────
    try:
        san_ext = agent_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
        spiffe_sans = [u for u in uri_sans if u.startswith("spiffe://")]
    except x509.ExtensionNotFound:
        spiffe_sans = []

    if spiffe_sans:
        if expected_spiffe not in spiffe_sans:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="SPIFFE ID nel SAN non corrisponde all'agente registrato",
            )
    elif settings.require_spiffe_san:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Certificato privo di SPIFFE SAN URI (require_spiffe_san=true)",
        )

    # ── 12. JTI blacklist — replay protection ────────────────────────────────
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="client_assertion missing jti",
        )
    exp_ts = payload.get("exp")
    expires_at = datetime.datetime.fromtimestamp(exp_ts, tz=datetime.timezone.utc)
    await check_and_consume_jti(db, jti, expires_at)

    cert_pem = agent_cert.public_bytes(serialization.Encoding.PEM).decode()
    _span.set_attribute("cert.thumbprint", cert_thumbprint)
    X509_VERIFY_DURATION_HISTOGRAM.record((_time.monotonic() - _t0) * 1000)
    return agent_id, org_id, cert_pem, cert_thumbprint
