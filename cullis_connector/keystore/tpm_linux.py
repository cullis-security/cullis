"""Linux TPM 2.0 :class:`KeyStore` via ``tpm2-pytss`` (ADR-032 F3 Phase 1).

Generates a non-extractable ECC P-256 key (``fixedTPM | fixedParent |
sensitiveDataOrigin``) inside the TPM, makes it persistent at a configurable
NV handle (default 0x81010001), and exposes it through the
:class:`~cullis_connector.keystore.base.KeyStore` interface. The private
half never leaves the chip; signatures, public-key reads, and the AIK
quote all round-trip through the TPM driver.

The optional dependency lives in ``[project.optional-dependencies] tpm``;
when missing, :class:`LinuxTpmKeyStore` raises :class:`KeyStoreUnavailable`
and :func:`detect_best_keystore` falls back to the soft backend.

Phase 1 limitations explicit in the prompt:

* EK CA chain verification is deferred (ADR-032 Decision Q8). Strength
  is ``hw_attested`` only when the EK certificate is present AND the
  manufacturer is in the Phase 1 whitelist; otherwise ``hw_isolated``.
* No PCR policy binding; Phase 1 reads PCR 0..7 into the quote but
  does not enforce a measured-boot allowlist.
"""
from __future__ import annotations

import logging
from typing import Any

from cullis_connector.keystore.base import (
    AttestationClaim,
    AttestationStrength,
    KeyStore,
    KeyStoreUnavailable,
)

_log = logging.getLogger("cullis_connector.keystore.tpm_linux")

# ADR-032 Decision Q8; Phase 1 manufacturer whitelist. Mirrors the value
# in ``mcp_proxy/attestation/tpm_verify.py``. A future ADR will move this
# to a refreshable remote bundle; for now both ends hard-code the same set
# so a customer-supplied chip outside the list still enrolls (downgraded
# to ``hw_isolated``) without a Mastio config bump.
TPM_MANUFACTURER_WHITELIST: frozenset[str] = frozenset(
    {"Infineon", "Microsoft", "ST", "Nuvoton", "Intel"},
)


class LinuxTpmKeyStore(KeyStore):
    """TPM 2.0-backed EC P-256 keystore (Linux, ``tpm2-pytss`` ≥ 2.0)."""

    def __init__(self, persistent_handle: int = 0x81010001) -> None:
        try:
            import tpm2_pytss  # type: ignore[import-not-found]
        except ImportError as exc:
            raise KeyStoreUnavailable(
                "tpm2-pytss is not installed; `pip install"
                " 'cullis-connector[tpm]'` to enable Linux TPM attestation",
            ) from exc

        try:
            self._esapi = tpm2_pytss.ESAPI()  # type: ignore[attr-defined]
        except Exception as exc:
            # Common causes: /dev/tpmrm0 missing, EACCES on tcti socket,
            # swtpm not running. The fallback path in detect_best_keystore
            # catches this and continues with the soft backend.
            raise KeyStoreUnavailable(
                f"TPM 2.0 device not reachable: {exc}",
            ) from exc

        self._tss = tpm2_pytss
        self._handle = persistent_handle
        self._ek_cert_present = False
        self._cached_pub_pem: str | None = None
        self._cached_manufacturer: str | None = None
        self._ensure_key()

    # ── Lifecycle ────────────────────────────────────────────────────────

    def _ensure_key(self) -> None:
        """Idempotent persistent-key provisioning.

        Reads the persistent handle; if absent, creates an ECC P-256
        primary under the Endorsement hierarchy and evicts it to the
        handle. Subsequent process restarts hit the read path and reuse
        the chip-resident key.
        """
        try:
            self._read_existing_public()
            return
        except _PersistentHandleMissing:
            pass

        self._create_and_persist()
        self._read_existing_public()

    def _read_existing_public(self) -> None:
        tss = self._tss
        try:
            # TPM2_ReadPublic on the persistent handle. tpm2-pytss exposes
            # this as ``ESAPI.tr_from_tpmpublic`` + ``read_public``.
            obj_handle = self._esapi.tr_from_tpmpublic(self._handle)
            public, _name, _qname = self._esapi.read_public(obj_handle)
        except Exception as exc:
            # Discriminate "no such handle" from real errors. tpm2-pytss
            # raises ``TSS2_Exception`` with rc_handle / rc_value subcodes
            # but the import surface varies between releases; match on
            # the well-known TPM_RC_HANDLE bit instead of class.
            msg = str(exc).lower()
            if "handle" in msg and ("0x18b" in msg or "value" in msg or "not found" in msg):
                raise _PersistentHandleMissing(self._handle) from exc
            raise

        self._cached_pub_pem = _ecc_public_to_pem(public, tss)

    def _create_and_persist(self) -> None:
        tss = self._tss

        ek_template = _ek_template(tss)
        primary, _outp, _name, _qname = self._esapi.create_primary(
            in_sensitive=tss.TPM2B_SENSITIVE_CREATE(),
            in_public=ek_template,
            primary_handle=tss.ESYS_TR.ENDORSEMENT,
            outside_info=tss.TPM2B_DATA(),
            creation_pcr=tss.TPML_PCR_SELECTION(),
        )

        try:
            ecc_template = _ecc_signing_template(tss)
            child, _cpub, _cname, _cqname, _ck = self._esapi.create(
                parent_handle=primary,
                in_sensitive=tss.TPM2B_SENSITIVE_CREATE(),
                in_public=ecc_template,
                outside_info=tss.TPM2B_DATA(),
                creation_pcr=tss.TPML_PCR_SELECTION(),
            )

            loaded = self._esapi.load(
                parent_handle=primary,
                in_private=child,
                in_public=_cpub,
            )

            self._esapi.evict_control(
                auth=tss.ESYS_TR.OWNER,
                object_handle=loaded,
                persistent_handle=self._handle,
            )
        finally:
            try:
                self._esapi.flush_context(primary)
            except Exception:
                pass

        # Phase 1 best-effort EK cert read. NV index 0x01C00002 is the
        # canonical low-range RSA EK cert location per TCG EK Credential
        # Profile §2.2. A missing index just means the chip ships without
        # a manufacturer cert (common on vTPM / swtpm); strength drops to
        # hw_isolated and enrollment continues.
        self._probe_ek_certificate()

    def _probe_ek_certificate(self) -> None:
        tss = self._tss
        ek_nv = 0x01C00002  # TCG EK Credential Profile, low-range RSA
        try:
            handle = self._esapi.tr_from_tpmpublic(ek_nv)
            nv_pub, _name = self._esapi.nv_read_public(handle)
            size = int(nv_pub.nvPublic.dataSize)
            if size <= 0:
                return
            data = self._esapi.nv_read(
                auth_handle=tss.ESYS_TR.OWNER,
                nv_index=handle,
                size=size,
                offset=0,
            )
            self._ek_cert_present = True
            self._cached_manufacturer = _ek_cert_manufacturer(bytes(data))
        except Exception:
            # vTPM / swtpm / locked-down chip; degrade silently to
            # hw_isolated. Mastio refuses ``_attested`` capability so
            # the absence of the cert never grants extra trust.
            self._ek_cert_present = False
            self._cached_manufacturer = None

    # ── KeyStore interface ──────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        tss = self._tss
        digest = _sha256(message)
        obj_handle = self._esapi.tr_from_tpmpublic(self._handle)
        scheme = tss.TPMT_SIG_SCHEME(
            scheme=tss.TPM2_ALG.ECDSA,
            details=tss.TPMU_SIG_SCHEME(ecdsa=tss.TPMS_SCHEME_HASH(hashAlg=tss.TPM2_ALG.SHA256)),
        )
        validation = tss.TPMT_TK_HASHCHECK(
            tag=tss.TPM2_ST.HASHCHECK,
            hierarchy=tss.ESYS_TR.OWNER,
            digest=tss.TPM2B_DIGEST(),
        )
        signature = self._esapi.sign(
            key_handle=obj_handle,
            digest=tss.TPM2B_DIGEST(digest),
            in_scheme=scheme,
            validation=validation,
        )
        return _ecdsa_sig_to_der(signature)

    def public_key_pem(self) -> str:
        if self._cached_pub_pem is None:
            self._read_existing_public()
        assert self._cached_pub_pem is not None
        return self._cached_pub_pem

    def attestation_strength(self) -> AttestationStrength:
        if self._ek_cert_present and self._cached_manufacturer in TPM_MANUFACTURER_WHITELIST:
            return "hw_attested"
        return "hw_isolated"

    def attestation_claim(self) -> AttestationClaim:
        return AttestationClaim(
            hardware="tpm_2.0",
            strength=self.attestation_strength(),
            manufacturer=self._cached_manufacturer,
        )

    def generate_aik_quote(self, nonce: bytes) -> bytes:
        """Produce an AIK-signed quote over PCR 0..7 + ``nonce``.

        Phase 1 reuses the persistent signing key as the AIK. A proper
        restricted attestation key per TCG AIK Credential Profile is on
        the Phase 2 roadmap once EK CA chain verify ships.
        """
        tss = self._tss
        obj_handle = self._esapi.tr_from_tpmpublic(self._handle)
        pcr_selection = _pcr_selection_sha256(tss, pcrs=range(0, 8))

        scheme = tss.TPMT_SIG_SCHEME(
            scheme=tss.TPM2_ALG.ECDSA,
            details=tss.TPMU_SIG_SCHEME(ecdsa=tss.TPMS_SCHEME_HASH(hashAlg=tss.TPM2_ALG.SHA256)),
        )
        quote, signature = self._esapi.quote(
            sign_handle=obj_handle,
            pcr_select=pcr_selection,
            qualifying_data=tss.TPM2B_DATA(nonce),
            in_scheme=scheme,
        )
        # Serialize quote + signature as a length-prefixed pair so the
        # verifier can split them deterministically without re-asking
        # tpm2-pytss for parser internals.
        quote_bytes = bytes(quote)
        sig_bytes = _ecdsa_sig_to_der(signature)
        return _pack_quote_envelope(quote_bytes, sig_bytes, nonce)


# ── Module-private helpers ───────────────────────────────────────────────


class _PersistentHandleMissing(Exception):
    """Raised when the persistent NV handle is empty (first-run path)."""

    def __init__(self, handle: int) -> None:
        super().__init__(f"persistent handle 0x{handle:08X} not provisioned")
        self.handle = handle


def _sha256(data: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(data).digest()


def _ek_template(tss: Any) -> Any:
    """Minimal EK ECC P-256 template suitable for create_primary."""
    return tss.TPM2B_PUBLIC(
        publicArea=tss.TPMT_PUBLIC(
            type=tss.TPM2_ALG.ECC,
            nameAlg=tss.TPM2_ALG.SHA256,
            objectAttributes=(
                tss.TPMA_OBJECT.FIXEDTPM
                | tss.TPMA_OBJECT.FIXEDPARENT
                | tss.TPMA_OBJECT.SENSITIVEDATAORIGIN
                | tss.TPMA_OBJECT.USERWITHAUTH
                | tss.TPMA_OBJECT.RESTRICTED
                | tss.TPMA_OBJECT.DECRYPT
            ),
            parameters=tss.TPMU_PUBLIC_PARMS(
                eccDetail=tss.TPMS_ECC_PARMS(
                    symmetric=tss.TPMT_SYM_DEF_OBJECT(
                        algorithm=tss.TPM2_ALG.AES,
                        keyBits=tss.TPMU_SYM_KEY_BITS(aes=128),
                        mode=tss.TPMU_SYM_MODE(aes=tss.TPM2_ALG.CFB),
                    ),
                    scheme=tss.TPMT_ECC_SCHEME(scheme=tss.TPM2_ALG.NULL),
                    curveID=tss.TPM2_ECC.NIST_P256,
                    kdf=tss.TPMT_KDF_SCHEME(scheme=tss.TPM2_ALG.NULL),
                ),
            ),
            unique=tss.TPMU_PUBLIC_ID(ecc=tss.TPMS_ECC_POINT()),
        ),
    )


def _ecc_signing_template(tss: Any) -> Any:
    """ECC P-256 signing-only template (fixedTPM, fixedParent, sign)."""
    return tss.TPM2B_PUBLIC(
        publicArea=tss.TPMT_PUBLIC(
            type=tss.TPM2_ALG.ECC,
            nameAlg=tss.TPM2_ALG.SHA256,
            objectAttributes=(
                tss.TPMA_OBJECT.FIXEDTPM
                | tss.TPMA_OBJECT.FIXEDPARENT
                | tss.TPMA_OBJECT.SENSITIVEDATAORIGIN
                | tss.TPMA_OBJECT.USERWITHAUTH
                | tss.TPMA_OBJECT.SIGN_ENCRYPT
            ),
            parameters=tss.TPMU_PUBLIC_PARMS(
                eccDetail=tss.TPMS_ECC_PARMS(
                    symmetric=tss.TPMT_SYM_DEF_OBJECT(algorithm=tss.TPM2_ALG.NULL),
                    scheme=tss.TPMT_ECC_SCHEME(
                        scheme=tss.TPM2_ALG.ECDSA,
                        details=tss.TPMU_ASYM_SCHEME(
                            ecdsa=tss.TPMS_SCHEME_HASH(hashAlg=tss.TPM2_ALG.SHA256),
                        ),
                    ),
                    curveID=tss.TPM2_ECC.NIST_P256,
                    kdf=tss.TPMT_KDF_SCHEME(scheme=tss.TPM2_ALG.NULL),
                ),
            ),
            unique=tss.TPMU_PUBLIC_ID(ecc=tss.TPMS_ECC_POINT()),
        ),
    )


def _ecc_public_to_pem(public: Any, tss: Any) -> str:
    """Lift a TPM2B_PUBLIC into a portable PEM SubjectPublicKeyInfo."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pub_area = public.publicArea
    x = bytes(pub_area.unique.ecc.x.buffer)
    y = bytes(pub_area.unique.ecc.y.buffer)
    # SECP256R1 = NIST P-256. Phase 1 emits only this curve so the assert
    # is a tripwire for future curve additions; callers don't catch it.
    assert int(pub_area.parameters.eccDetail.curveID) == int(tss.TPM2_ECC.NIST_P256), (
        "Phase 1 expects NIST P-256; rebuild templates if widening"
    )

    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"),
        y=int.from_bytes(y, "big"),
        curve=ec.SECP256R1(),
    )
    cryptography_pub = public_numbers.public_key()
    return cryptography_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _ecdsa_sig_to_der(signature: Any) -> bytes:
    """Convert a TPMT_SIGNATURE (ECDSA-SHA256) into the standard ASN.1 DER form."""
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )

    r_buf = bytes(signature.signature.ecdsa.signatureR.buffer)
    s_buf = bytes(signature.signature.ecdsa.signatureS.buffer)
    return encode_dss_signature(
        int.from_bytes(r_buf, "big"),
        int.from_bytes(s_buf, "big"),
    )


def _pcr_selection_sha256(tss: Any, *, pcrs: Any) -> Any:
    """Build a TPML_PCR_SELECTION over SHA-256 bank for the given PCR indices."""
    bitmap = bytearray(3)  # 24 PCRs default → 3 bytes mask
    for pcr in pcrs:
        bitmap[pcr // 8] |= 1 << (pcr % 8)
    return tss.TPML_PCR_SELECTION(
        pcrSelections=[
            tss.TPMS_PCR_SELECTION(
                hash=tss.TPM2_ALG.SHA256,
                sizeofSelect=len(bitmap),
                pcrSelect=bytes(bitmap),
            ),
        ],
    )


# Envelope format for the AIK quote:
#
#   magic         : b"CULLIS-Q1"
#   nonce_len     : uint16 BE
#   nonce
#   quote_len     : uint32 BE
#   quote bytes (TPMS_ATTEST marshalled form)
#   sig_len       : uint32 BE
#   signature DER (ECDSA-SHA256)
#
# Kept simple on purpose: the verifier in ``mcp_proxy/attestation/tpm_verify``
# unpacks it without depending on tpm2-pytss being installed server-side.

_QUOTE_MAGIC = b"CULLIS-Q1"


def _pack_quote_envelope(quote: bytes, sig: bytes, nonce: bytes) -> bytes:
    if len(nonce) > 0xFFFF:
        raise ValueError("nonce too long for envelope (max 65535 bytes)")
    out = bytearray()
    out += _QUOTE_MAGIC
    out += len(nonce).to_bytes(2, "big")
    out += nonce
    out += len(quote).to_bytes(4, "big")
    out += quote
    out += len(sig).to_bytes(4, "big")
    out += sig
    return bytes(out)


def unpack_quote_envelope(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """Reverse of :func:`_pack_quote_envelope`. Exported for the verifier."""
    if len(blob) < len(_QUOTE_MAGIC) + 2 + 4 + 4:
        raise ValueError("quote envelope truncated")
    if blob[: len(_QUOTE_MAGIC)] != _QUOTE_MAGIC:
        raise ValueError("quote envelope magic mismatch")
    pos = len(_QUOTE_MAGIC)
    nonce_len = int.from_bytes(blob[pos : pos + 2], "big")
    pos += 2
    nonce = blob[pos : pos + nonce_len]
    pos += nonce_len
    quote_len = int.from_bytes(blob[pos : pos + 4], "big")
    pos += 4
    quote = blob[pos : pos + quote_len]
    pos += quote_len
    sig_len = int.from_bytes(blob[pos : pos + 4], "big")
    pos += 4
    sig = blob[pos : pos + sig_len]
    if len(sig) != sig_len:
        raise ValueError("quote envelope signature truncated")
    return nonce, quote, sig


def _ek_cert_manufacturer(der: bytes) -> str | None:
    """Best-effort manufacturer string extracted from an EK certificate.

    Looks at the Subject DN's OU + the Subject Alternative Name's
    DirectoryName, where TPM EK certs typically embed
    ``TPMManufacturer=...`` / ``OU=Infineon Technologies AG``.
    """
    try:
        from cryptography import x509
        from cryptography.x509 import NameOID
    except Exception:
        return None

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    candidates: list[str] = []
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME):
            candidates.append(str(attr.value))
    except Exception:
        pass
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME):
            candidates.append(str(attr.value))
    except Exception:
        pass

    for candidate in candidates:
        normalised = _normalise_manufacturer(candidate)
        if normalised is not None:
            return normalised
    return None


def _normalise_manufacturer(raw: str) -> str | None:
    """Map a free-form vendor string onto the Phase 1 whitelist label."""
    lowered = raw.lower()
    table = {
        "infineon": "Infineon",
        "ifx": "Infineon",
        "microsoft": "Microsoft",
        "mscm": "Microsoft",
        "stmicro": "ST",
        "st micro": "ST",
        " st ": "ST",
        "nuvoton": "Nuvoton",
        "ntc": "Nuvoton",
        "intel": "Intel",
        "intc": "Intel",
    }
    for needle, label in table.items():
        if needle in lowered:
            return label
    return None
