"""Linux TPM keystore; exercises the import-gated paths.

The bulk of the TPM behaviour needs a real (or vTPM/swtpm-backed) device
and is skipped by default; CI / NixOS / laptops without ``tpm2-pytss`` go
through the import-failure path which is the most exercised branch in
production today. The full hardware run is gated on:

* ``tpm2-pytss`` installed (optional extra ``[tpm]``)
* ``CULLIS_TPM_TEST_TCTI`` env (e.g. ``swtpm:port=2321``) pointing at
  a swtpm or kernel resource manager

When both are present the test provisions the persistent handle, signs a
canonical buffer, and round-trips the signature through ``cryptography``
so we get a real ECDSA-SHA256 verify rather than a tpm2-pytss self-check.
"""
from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cullis_connector.keystore.base import KeyStoreUnavailable
from cullis_connector.keystore.soft import SoftKeyStore


_TPM_PYTSS_AVAILABLE = False
try:  # pragma: no cover; environment-dependent
    import tpm2_pytss  # noqa: F401

    _TPM_PYTSS_AVAILABLE = True
except Exception:
    pass


_HARDWARE_GATE = bool(os.environ.get("CULLIS_TPM_TEST_TCTI"))


def test_detect_best_keystore_falls_back_to_soft_when_tpm_unavailable(monkeypatch):
    """When the optional TPM dep is absent or the device is unreachable,
    the public detector returns a :class:`SoftKeyStore` instead of
    raising. This is the production path on Windows / macOS / vTPM-less
    Linux hosts and the most important invariant for the spike.
    """

    # Force LinuxTpmKeyStore to raise KeyStoreUnavailable regardless of the
    # actual host (some CI runners do have a TPM). We patch the import
    # surface used by detect_best_keystore.
    from cullis_connector import keystore as ks_pkg

    class _Boom:
        def __init__(self, *_a, **_kw):
            raise KeyStoreUnavailable("forced by test")

    monkeypatch.setattr(
        "cullis_connector.keystore.tpm_linux.LinuxTpmKeyStore",
        _Boom,
        raising=True,
    )
    # Re-import path also has to see the patched class; detect_best_keystore
    # does ``from cullis_connector.keystore.tpm_linux import LinuxTpmKeyStore``
    # at call time so the monkeypatch takes effect.
    chosen = ks_pkg.detect_best_keystore(prefer_hardware=True)
    assert isinstance(chosen, SoftKeyStore)
    assert chosen.attestation_claim() is None


@pytest.mark.skipif(not _TPM_PYTSS_AVAILABLE, reason="tpm2-pytss not installed")
@pytest.mark.skipif(not _HARDWARE_GATE, reason="CULLIS_TPM_TEST_TCTI not set")
def test_linux_tpm_keystore_signs_with_real_device():  # pragma: no cover
    """Real-device path. Gated on CULLIS_TPM_TEST_TCTI so CI stays green
    on hosts without a vTPM/swtpm available.
    """
    from cullis_connector.keystore.tpm_linux import LinuxTpmKeyStore

    ks = LinuxTpmKeyStore(persistent_handle=0x81010099)
    pem = ks.public_key_pem()
    pub = serialization.load_pem_public_key(pem.encode())
    assert isinstance(pub, ec.EllipticCurvePublicKey)

    sig = ks.sign(b"hello-tpm")
    pub.verify(sig, b"hello-tpm", ec.ECDSA(hashes.SHA256()))

    claim = ks.attestation_claim()
    assert claim is not None
    assert claim.hardware == "tpm_2.0"
    assert claim.strength in {"hw_attested", "hw_isolated"}

    quote = ks.generate_aik_quote(b"\x01" * 32)
    assert quote.startswith(b"CULLIS-Q1")
