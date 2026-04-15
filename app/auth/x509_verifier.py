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
import hmac
import time as _time
import urllib.parse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from fastapi import HTTPException, Request, status
import jwt
from jwt.exceptions import InvalidTokenError as JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jti_blacklist import check_and_consume_jti
from app.auth.revocation import check_cert_not_revoked
from app.registry.org_store import get_org_by_id, get_org_by_trust_domain
from app.config import get_settings
from app.spiffe import internal_id_to_spiffe, parse_spiffe_san
from app.telemetry import tracer
from app.telemetry_metrics import X509_VERIFY_DURATION_HISTOGRAM

_AUDIENCE = "agent-trust-broker"
_ALLOWED_HASH_ALGORITHMS = (hashes.SHA256, hashes.SHA384, hashes.SHA512)


async def verify_client_assertion(
    assertion: str,
    db: AsyncSession,
    request: Request | None = None,
) -> tuple[str, str, str, str]:
    """
    Verify a client_assertion JWT and return (agent_id, org_id, cert_pem, cert_thumbprint).
    cert_pem is the agent certificate extracted from x5c — it is saved in DB
    by the auth router to allow verification of message signatures.
    cert_thumbprint is the SHA-256 hex digest of the DER-encoded certificate.

    When ``request`` is provided and ``mtls_binding`` is enabled in settings,
    also enforces RFC 8705-style confirmation that the mTLS client cert
    forwarded by the reverse proxy matches the cert in x5c.

    Raises HTTPException 401/403 if verification fails.
    """
    _t0 = _time.monotonic()
    with tracer.start_as_current_span("auth.x509_verify") as _span:
      return await _verify_client_assertion_inner(assertion, db, _span, _t0, request)


async def _verify_client_assertion_inner(assertion, db, _span, _t0, request=None):
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

    # ── 3. Extract agent_id and org_id ───────────────────────────────────────
    # Two supported modes:
    #   (a) Classic agent cert — CN = agent_id, O = org_id
    #   (b) SPIRE-style SVID — no CN/O in subject, identity encoded only
    #       in the SPIFFE URI SAN. Look up the org by trust_domain and
    #       derive agent_id from the path's last segment.
    svid_mode = False
    svid_spiffe_uri: str | None = None
    cn_attrs = agent_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    org_attrs = agent_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if cn_attrs and org_attrs:
        agent_id = cn_attrs[0].value
        org_id = org_attrs[0].value
        org = await get_org_by_id(db, org_id)
    else:
        try:
            san_ext = agent_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
            spiffe_sans = [u for u in uri_sans if u.startswith("spiffe://")]
        except x509.ExtensionNotFound:
            spiffe_sans = []
        if not spiffe_sans:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="Cert missing CN/O and no SPIFFE SAN URI present",
            )
        svid_spiffe_uri = spiffe_sans[0]
        try:
            trust_domain, spiffe_path = parse_spiffe_san(svid_spiffe_uri)
        except ValueError:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, detail="Malformed SPIFFE URI in SAN",
            )
        org = await get_org_by_trust_domain(db, trust_domain)
        if org is None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"No organization registered for trust domain '{trust_domain}'",
            )
        agent_name = spiffe_path.rsplit("/", 1)[-1]
        agent_id = f"{org.org_id}::{agent_name}"
        org_id = org.org_id
        svid_mode = True

    # ── 4. Load org CA from DB and verify it is a true CA ────────────────────
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
        import logging
        logging.getLogger("agent_trust").error("Invalid org CA for '%s': %s", org_id, exc)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Broker configuration error: invalid org CA certificate",
        )

    # ── 5. Enforce algorithm whitelist, then verify chain ────────────────────
    if not isinstance(agent_cert.signature_hash_algorithm, _ALLOWED_HASH_ALGORITHMS):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Agent certificate uses a weak signature algorithm — SHA-256 or stronger required",
        )

    with tracer.start_as_current_span("auth.x509_chain_verify"):
        try:
            ca_pub = org_ca.public_key()
            if isinstance(ca_pub, rsa.RSAPublicKey):
                ca_pub.verify(
                    agent_cert.signature,
                    agent_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    agent_cert.signature_hash_algorithm,
                )
            elif isinstance(ca_pub, ec.EllipticCurvePublicKey):
                ca_pub.verify(
                    agent_cert.signature,
                    agent_cert.tbs_certificate_bytes,
                    ec.ECDSA(agent_cert.signature_hash_algorithm),
                )
            else:
                raise ValueError(f"Unsupported CA key type: {type(ca_pub).__name__}")
        except InvalidSignature:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="Agent certificate not signed by the registered org CA",
            )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Certificate chain verification failed")

    # ── 5b. Enforce minimum RSA key size (2048 bits) ──────────────────────
    agent_pub_key = agent_cert.public_key()
    if isinstance(agent_pub_key, rsa.RSAPublicKey):
        if agent_pub_key.key_size < 2048:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail=f"Agent RSA key too small ({agent_pub_key.key_size} bits) — minimum 2048 required",
            )
    elif isinstance(agent_pub_key, ec.EllipticCurvePublicKey):
        _ALLOWED_EC_CURVES = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
        if not isinstance(agent_pub_key.curve, _ALLOWED_EC_CURVES):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail=f"Agent EC curve '{agent_pub_key.curve.name}' not allowed — use P-256, P-384, or P-521",
            )

    # ── 5c. Verify Extended Key Usage includes clientAuth (if EKU present) ──
    try:
        eku_ext = agent_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku_ext.value:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="Agent certificate EKU does not include clientAuth (1.3.6.1.5.5.7.3.2)",
            )
    except x509.ExtensionNotFound:
        pass  # No EKU extension — acceptable for backwards compatibility

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
            algorithms=["RS256", "ES256"],
            audience=_AUDIENCE,
            options={"verify_aud": True, "verify_exp": True},
        )
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid client_assertion signature")

    # ── 10. Verify sub and iss — bind JWT tightly to the authenticated agent ──
    settings = get_settings()
    if svid_mode and svid_spiffe_uri is not None:
        # In SVID mode the SPIFFE URI IS the authoritative identity;
        # accept it (and the internal agent_id) as sub/iss.
        expected_spiffe = svid_spiffe_uri
    else:
        org_td = org.trust_domain or settings.trust_domain
        expected_spiffe = internal_id_to_spiffe(agent_id, org_td)

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
    # In svid_mode we already extracted + trusted the SAN above, so skip
    # the redundant match check (would be tautological).
    if not svid_mode:
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
                    detail="SPIFFE ID in SAN does not match the registered agent",
                )
        elif settings.require_spiffe_san:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="Certificate missing SPIFFE SAN URI (require_spiffe_san=true)",
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

    # ── 13. mTLS binding (RFC 8705 §3) ───────────────────────────────────────
    # When a reverse proxy terminates mTLS and forwards the client cert via
    # header, verify it matches the cert in x5c. A stolen JWT is useless
    # without the corresponding private key used to open the TLS tunnel.
    settings = get_settings()
    mtls_mode = getattr(settings, "mtls_binding", "off")
    if request is not None and mtls_mode != "off":
        header_name = getattr(settings, "mtls_client_cert_header", "X-SSL-Client-Cert")
        raw = request.headers.get(header_name)
        if raw:
            try:
                # nginx $ssl_client_escaped_cert is URL-encoded (\n → %0A, etc).
                # Traefik passthrough headers are plain PEM. Handle both.
                decoded = urllib.parse.unquote(raw)
                mtls_cert = x509.load_pem_x509_certificate(decoded.encode())
                mtls_thumbprint = hashlib.sha256(
                    mtls_cert.public_bytes(serialization.Encoding.DER)
                ).hexdigest()
            except Exception:
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED,
                    detail="mTLS client certificate header is malformed",
                )
            if not hmac.compare_digest(mtls_thumbprint, cert_thumbprint):
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED,
                    detail="mTLS cert does not match client_assertion cert (RFC 8705 binding)",
                )
        elif mtls_mode == "required":
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="mTLS binding required but client certificate header absent",
            )

    cert_pem = agent_cert.public_bytes(serialization.Encoding.PEM).decode()
    _span.set_attribute("cert.thumbprint", cert_thumbprint)
    X509_VERIFY_DURATION_HISTOGRAM.record((_time.monotonic() - _t0) * 1000)
    return agent_id, org_id, cert_pem, cert_thumbprint
