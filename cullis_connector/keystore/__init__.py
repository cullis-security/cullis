"""Key backends for the Connector identity material (ADR-032 F3).

The :class:`KeyStore` abstraction lets the enrollment flow swap between
software-only keys (existing default), Linux TPM 2.0 hardware-bound keys,
and (future) macOS Secure Enclave / Windows TPM backends without rewriting
the call sites. Only the TPM backend can produce an attestation claim with
``strength="hw_attested"``; the soft backend reports ``None`` and the
server downgrades the effective tier accordingly.
"""
from cullis_connector.keystore.base import (
    AttestationClaim,
    KeyStore,
    KeyStoreUnavailable,
)
from cullis_connector.keystore.soft import SoftKeyStore

__all__ = [
    "AttestationClaim",
    "KeyStore",
    "KeyStoreUnavailable",
    "SoftKeyStore",
    "detect_best_keystore",
]


def detect_best_keystore(
    *,
    soft_key_path=None,
    tpm_persistent_handle: int = 0x81010001,
    prefer_hardware: bool = True,
):
    """Return the strongest available :class:`KeyStore` for this host.

    Phase 1 attempts Linux TPM 2.0 first when ``prefer_hardware`` is set,
    falling back to a soft keystore on any import / device / permission
    error. The fallback is intentional; a Connector without a TPM should
    still enroll, just at a lower effective tier (see ADR-032 Decision K).
    """
    if prefer_hardware:
        try:
            from cullis_connector.keystore.tpm_linux import LinuxTpmKeyStore

            return LinuxTpmKeyStore(persistent_handle=tpm_persistent_handle)
        except KeyStoreUnavailable:
            pass
        except Exception:
            # Defensive: any TPM hiccup falls back rather than hard-failing
            # the enrollment flow. Mastio refuses ``_attested`` capability
            # without a verified claim, so this is a UX choice not a
            # security one (memoria
            # feedback_h4_convergent_pattern_fallback_insecure_default).
            pass
    return SoftKeyStore(private_key_path=soft_key_path)
