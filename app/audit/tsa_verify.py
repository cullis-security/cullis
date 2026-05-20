"""Cryptographic verification of RFC 3161 TimeStampToken (audit F-A-405).

Before this module existed, ``Rfc3161TsaClient.verify`` only matched the
``message_imprint`` field against the row hash. That made the anchor
forgeable: any party knowing the row hash could fabricate a
TimeStampToken with matching imprint and pass verify. The anchor was
operationally equivalent to a row in the broker's own DB and the
dispute-grade claim collapsed.

This module implements the missing checks:

  1. ``message_imprint`` matches the expected sha256 digest.
  2. Exactly one ``SignerInfo`` in the CMS SignedData.
  3. Signing certificate carries ``extKeyUsage = id-kp-timeStamping``
     (RFC 3161 §2.3 — a TSA cert must be marked for time-stamping and
     no other purpose).
  4. CMS signature verifies against the signing cert public key over
     the DER-encoded ``signedAttrs`` (the standard CMS detached-attr
     mode that RFC 3161 mandates).
  5. The signing cert chains up to one of the operator-configured
     trust anchors in the PEM bundle. Intermediates may be included in
     the token's ``certificates`` field or in the bundle.
  6. The TSA's ``genTime`` is within ``max_clock_skew_seconds`` of the
     wall clock recorded at anchor issue. Catches clock-rewind /
     anchor-replay attacks.

Anything short of all six returns ``False`` with a WARNING log.

The module imports ``asn1crypto`` lazily so the broker boots on a
minimal install that hasn't pulled ``rfc3161-client`` (which brings
asn1crypto transitively). When the lib is missing and the caller asked
for ``rfc3161`` verification, we raise ``RuntimeError`` rather than
silently returning ``False`` — a verifier that returns "unverified"
when its own crypto stack is missing is the worst of both worlds
(audit F-A-405 recommendation 4).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

_log = logging.getLogger("audit.tsa.verify")


# RFC 3161 §2.3 — id-kp-timeStamping OID.
_ID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

# CMS signedData OID — sanity-check the outer ContentInfo.
_ID_SIGNED_DATA = "1.2.840.113549.1.7.2"


class TsaVerifyDependencyError(RuntimeError):
    """Raised when the verifier cannot run because optional crypto
    dependencies (``asn1crypto``) are not installed. The caller catches
    this only when it explicitly accepts "verifier unavailable" as a
    distinct outcome from "verification failed"."""


def _load_signing_cert_from_token(signed_data, signer_info):
    """Locate the certificate that signed this SignerInfo by matching
    the ``sid`` against entries in the token's ``certificates`` field.
    Returns the DER-encoded leaf, or ``None`` if not found.
    """
    sid = signer_info["sid"]
    certs = signed_data["certificates"] if "certificates" in signed_data else None
    if certs is None:
        return None
    for cert_choice in certs:
        if cert_choice.name != "certificate":
            continue
        cert = cert_choice.chosen
        if sid.name == "issuer_and_serial_number":
            iss_ser = sid.chosen
            if (
                cert.issuer == iss_ser["issuer"]
                and cert.serial_number == iss_ser["serial_number"].native
            ):
                return cert.dump()
        elif sid.name == "subject_key_identifier":
            target_ski = sid.chosen.native
            try:
                ski = cert.key_identifier
            except KeyError:
                continue
            if ski == target_ski:
                return cert.dump()
    return None


def _load_trust_anchors(trust_anchor_pem: bytes):
    """Parse a PEM bundle into ``cryptography.x509.Certificate`` list."""
    from cryptography import x509

    anchors: list = []
    blob = trust_anchor_pem
    # Iterate over PEM blocks
    start = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    pos = 0
    while True:
        s = blob.find(start, pos)
        if s == -1:
            break
        e = blob.find(end, s)
        if e == -1:
            break
        pem = blob[s : e + len(end)] + b"\n"
        anchors.append(x509.load_pem_x509_certificate(pem))
        pos = e + len(end)
    return anchors


def _verify_cert_signature(child, parent) -> bool:
    """Return True if ``child.signature`` verifies against
    ``parent.public_key()`` over ``child.tbs_certificate_bytes``.
    Handles RSA-PKCS1v15 and ECDSA, the two algorithms TSA certs ship
    with in practice. RSA-PSS is allowed in theory but rare for TSA
    leaves and would be added on demand.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    pub = parent.public_key()
    sig_hash_oid = child.signature_hash_algorithm
    if sig_hash_oid is None:
        return False
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                sig_hash_oid,
            )
            return True
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(sig_hash_oid),
            )
            return True
    except InvalidSignature:
        return False
    return False


def _walk_chain_to_trust_anchor(leaf_der: bytes, extra_certs_der, trust_anchors) -> bool:
    """Find a path from ``leaf`` to any trust anchor.

    Strategy is intentionally simple: O(N^2) issuer-match through the
    pool of candidate parents (extras + anchors). TSA chains in practice
    are leaf → 0-2 intermediates → root, so the cost is negligible.
    """
    from cryptography import x509

    leaf = x509.load_der_x509_certificate(leaf_der)
    pool = [x509.load_der_x509_certificate(d) for d in extra_certs_der]
    pool_used = set()

    current = leaf
    # Bound the walk depth to defend against pathological cycles.
    for _depth in range(8):
        # Direct trust anchor match.
        for anchor in trust_anchors:
            if anchor.subject == current.issuer:
                if _verify_cert_signature(current, anchor):
                    return True
        # Step up through an intermediate.
        for i, candidate in enumerate(pool):
            if i in pool_used:
                continue
            if candidate.subject != current.issuer:
                continue
            if not _verify_cert_signature(current, candidate):
                continue
            pool_used.add(i)
            current = candidate
            break
        else:
            return False
    return False


def _verify_cms_signature(signing_cert_der: bytes, signer_info) -> bool:
    """Verify the CMS SignerInfo signature against the signing cert.

    RFC 5652 §5.4 — when ``signedAttrs`` is present (always true for
    RFC 3161 TST), the value signed is the DER-encoded SET OF
    ``signedAttrs`` (not the IMPLICIT [0] tag that appears on the wire).
    """
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    try:
        from asn1crypto import core  # type: ignore[import-not-found]
    except ImportError as exc:
        raise TsaVerifyDependencyError(
            "asn1crypto required for RFC 3161 verify"
        ) from exc

    cert = x509.load_der_x509_certificate(signing_cert_der)
    pub = cert.public_key()

    signed_attrs = signer_info["signed_attrs"]
    if not signed_attrs or len(signed_attrs) == 0:
        _log.warning("RFC 3161 verify: SignerInfo lacks signed_attrs")
        return False

    # Re-encode signed_attrs as a SET OF (RFC 5652 §5.4) by switching
    # the implicit tag back to universal SET. asn1crypto exposes this
    # via the SetOf class.
    class _SetOfAttribute(core.SetOf):
        _child_spec = type(signed_attrs[0])

    to_sign = _SetOfAttribute([attr for attr in signed_attrs]).dump()

    digest_algo = signer_info["digest_algorithm"]["algorithm"].native
    sig_algo = signer_info["signature_algorithm"]["algorithm"].native
    signature = signer_info["signature"].native

    hash_obj: hashes.HashAlgorithm
    if digest_algo in {"sha256"}:
        hash_obj = hashes.SHA256()
    elif digest_algo in {"sha384"}:
        hash_obj = hashes.SHA384()
    elif digest_algo in {"sha512"}:
        hash_obj = hashes.SHA512()
    else:
        _log.warning("RFC 3161 verify: unsupported digest %s", digest_algo)
        return False

    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if sig_algo in {"rsassa_pkcs1v15", "rsa", "sha256_rsa"}:
                pub.verify(signature, to_sign, padding.PKCS1v15(), hash_obj)
            elif sig_algo == "rsassa_pss":
                pub.verify(
                    signature,
                    to_sign,
                    padding.PSS(mgf=padding.MGF1(hash_obj), salt_length=padding.PSS.DIGEST_LENGTH),
                    hash_obj,
                )
            else:
                _log.warning("RFC 3161 verify: unsupported RSA sig algo %s", sig_algo)
                return False
            return True
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, to_sign, ec.ECDSA(hash_obj))
            return True
    except InvalidSignature:
        _log.warning("RFC 3161 verify: signature verification failed")
        return False
    _log.warning("RFC 3161 verify: unsupported key type %s", type(pub).__name__)
    return False


def verify_rfc3161_token(
    token_der: bytes,
    *,
    expected_digest_hex: str,
    trust_anchor_pem: bytes | None,
    max_clock_skew_seconds: int = 86400,
    expected_created_at: datetime | None = None,
) -> bool:
    """Cryptographically verify a raw RFC 3161 TimeStampToken (DER).

    The 2-byte ``T1|`` magic prefix used by ``Rfc3161TsaClient`` is
    stripped by the caller; this function expects pure DER.

    Returns ``True`` only when every check passes. Returns ``False``
    with a WARNING log entry on any check failure. Raises
    ``TsaVerifyDependencyError`` if ``asn1crypto`` is not importable.
    """
    if not trust_anchor_pem:
        _log.warning(
            "RFC 3161 verify: no trust anchor configured — refusing to "
            "treat token as verified",
        )
        return False
    try:
        from asn1crypto import cms, tsp  # type: ignore[import-not-found]
    except ImportError as exc:
        raise TsaVerifyDependencyError(
            "asn1crypto required for RFC 3161 verify — install rfc3161-client",
        ) from exc

    try:
        token = tsp.TimeStampToken.load(token_der)
    except Exception as exc:  # noqa: BLE001 — asn1crypto raises broadly
        _log.warning("RFC 3161 verify: token DER parse failed: %s", exc)
        return False

    if token["content_type"].native != _ID_SIGNED_DATA:
        _log.warning(
            "RFC 3161 verify: outer ContentInfo is %s, expected signedData",
            token["content_type"].native,
        )
        return False

    signed_data = token["content"]
    encap = signed_data["encap_content_info"]
    try:
        tst_info = encap["content"].parsed
    except Exception as exc:  # noqa: BLE001
        _log.warning("RFC 3161 verify: TSTInfo parse failed: %s", exc)
        return False

    # 1. Imprint match.
    imprint_digest = tst_info["message_imprint"]["hashed_message"].native.hex()
    if imprint_digest != expected_digest_hex:
        _log.warning("RFC 3161 verify: message_imprint mismatch")
        return False

    # 2. Exactly one SignerInfo.
    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) != 1:
        _log.warning(
            "RFC 3161 verify: expected exactly one SignerInfo, got %d",
            len(signer_infos),
        )
        return False
    signer = signer_infos[0]

    # Resolve signing cert from embedded certs.
    signing_cert_der = _load_signing_cert_from_token(signed_data, signer)
    if signing_cert_der is None:
        _log.warning(
            "RFC 3161 verify: signing certificate not embedded in token — "
            "token issued without cert_req=True",
        )
        return False

    # 3. EKU id-kp-timeStamping check.
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    leaf = x509.load_der_x509_certificate(signing_cert_der)
    try:
        eku_ext = leaf.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE,
        )
        eku_oids = [usage.dotted_string for usage in eku_ext.value]
        if _ID_KP_TIME_STAMPING not in eku_oids:
            _log.warning(
                "RFC 3161 verify: signing cert lacks id-kp-timeStamping EKU",
            )
            return False
    except x509.ExtensionNotFound:
        _log.warning("RFC 3161 verify: signing cert has no EKU extension")
        return False

    # 4. CMS signature verify.
    if not _verify_cms_signature(signing_cert_der, signer):
        return False

    # 5. Chain to trust anchor.
    trust_anchors = _load_trust_anchors(trust_anchor_pem)
    if not trust_anchors:
        _log.warning(
            "RFC 3161 verify: trust anchor bundle has no parseable certs",
        )
        return False
    extra_certs_der: list[bytes] = []
    certs_field = signed_data["certificates"] if "certificates" in signed_data else None
    if certs_field is not None:
        for cert_choice in certs_field:
            if cert_choice.name != "certificate":
                continue
            der = cert_choice.chosen.dump()
            if der == signing_cert_der:
                continue
            extra_certs_der.append(der)

    if not _walk_chain_to_trust_anchor(signing_cert_der, extra_certs_der, trust_anchors):
        _log.warning(
            "RFC 3161 verify: signing cert does not chain to a trusted root",
        )
        return False

    # 6. genTime within bounded skew of the broker-side issue time.
    gen_time = tst_info["gen_time"].native
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)
    if expected_created_at is not None:
        ref = expected_created_at
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        skew = abs((gen_time - ref).total_seconds())
        if skew > max_clock_skew_seconds:
            _log.warning(
                "RFC 3161 verify: genTime skew %.0fs exceeds limit %ds",
                skew,
                max_clock_skew_seconds,
            )
            return False

    return True
