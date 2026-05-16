"""Device attestation: server-side authoritative compute + TPM verify.

Two halves of the ADR-032 claim live here:

* F2 (Layer 1, MDM): tier algorithm, claim builder, stale-window helper.
  Locked against ``imp/attestation-claim-schema.md`` v1.0 sez. 1 + 2 + 5.
* F3 (Phase 1, hardware): TPM 2.0 quote verifier + single-use nonce store
  used by ``POST /v1/enrollment/start``.

Exports:

* :func:`compute_effective_tier`, :func:`is_stale`,
  :func:`build_attestation_claim` (from :mod:`.tier`).
* :func:`verify_tpm_quote`, :exc:`TpmQuoteVerificationError`,
  :data:`TPM_MANUFACTURER_WHITELIST` (from :mod:`.tpm_verify`).
* :func:`issue_nonce`, :func:`consume_nonce`,
  :func:`set_attestation_nonce_redis_pool`,
  :func:`reset_memory_store_for_tests`, :class:`IssuedNonce`
  (from :mod:`.nonce_store`).
"""
from mcp_proxy.attestation.nonce_store import (
    IssuedNonce,
    consume_nonce,
    issue_nonce,
    reset_memory_store_for_tests,
    set_attestation_nonce_redis_pool,
)
from mcp_proxy.attestation.tier import (
    build_attestation_claim,
    compute_effective_tier,
    is_stale,
)
from mcp_proxy.attestation.tpm_verify import (
    TPM_MANUFACTURER_WHITELIST,
    TpmQuoteVerificationError,
    verify_tpm_quote,
)

__all__ = [
    "IssuedNonce",
    "TPM_MANUFACTURER_WHITELIST",
    "TpmQuoteVerificationError",
    "build_attestation_claim",
    "compute_effective_tier",
    "consume_nonce",
    "is_stale",
    "issue_nonce",
    "reset_memory_store_for_tests",
    "set_attestation_nonce_redis_pool",
    "verify_tpm_quote",
]
