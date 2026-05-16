"""Pydantic schemas for the enrollment API."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EnrollmentStartRequest(BaseModel):
    """Initial request from a Connector to begin enrollment.

    The Connector generates its keypair locally, extracts the public key in
    PEM, and submits it along with the self-declared identity. The private
    key never leaves the caller's machine.
    """

    pubkey_pem: str = Field(..., min_length=100, max_length=8192)
    requester_name: str = Field(..., min_length=1, max_length=200)
    requester_email: str = Field(..., min_length=3, max_length=320)
    reason: str | None = Field(None, max_length=1000)

    @field_validator("requester_email")
    @classmethod
    def _validate_email(cls, value: str) -> str:
        # Lightweight check — admin does the real vetting during approval.
        # Keeps us off the ``email-validator`` dependency for a v1 MVP.
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            raise ValueError("requester_email is not a valid email address")
        return value
    device_info: str | None = Field(
        None,
        max_length=500,
        description=(
            "Free-form device/client info (OS, hostname, Connector version)."
            " Not used for auth — helps admin decide and appears in audit."
        ),
    )
    dpop_jwk: dict | None = Field(
        None,
        description=(
            "Public JWK of the DPoP keypair the Connector generated locally."
            " Must be a PUBLIC key (no ``d`` field); kty ``EC`` (P-256) or"
            " ``RSA``. The server computes the RFC 7638 thumbprint and stores"
            " it on the pending row; on approve it becomes"
            " internal_agents.dpop_jkt and the egress dep (#199 + #204)"
            " enforces proofs signed by this specific keypair."
            " Optional for backward compat with pre-Phase-3c SDKs — omitting"
            " leaves dpop_jkt NULL and the agent stays on the mode=optional"
            " grace path until the operator populates it via the admin"
            " endpoint (#206) or re-enrolls (audit F-B-11 Phase 3b)."
        ),
    )
    pop_signature: str | None = Field(
        None,
        max_length=2048,
        description=(
            "H-csr-pop audit fix — base64url proof of possession over"
            " the keypair whose public half is in ``pubkey_pem``. The"
            " Connector signs ``\"enrollment-pop:v1|<pubkey-sha256-hex>\"``"
            " (RSA-PSS or ECDSA, dispatched by key type) and submits"
            " the signature here. The server verifies before persisting,"
            " so an attacker cannot enroll a stolen / observed public"
            " key whose private half they don't control. Optional for"
            " a transition window — pre-fix Connectors still enroll"
            " but the server logs a WARNING. Will become required in"
            " a follow-up release."
        ),
    )
    # ── ADR-032 F3: TPM attestation (optional) ────────────────────────
    attestation_nonce_id: str | None = Field(
        None,
        max_length=128,
        description=(
            "Opaque identifier of the server-issued nonce the Connector"
            " consumed when generating ``tpm_quote_b64``. Returned by"
            " ``GET /v1/enrollment/attestation-nonce``. Required iff"
            " ``tpm_quote_b64`` is set."
        ),
    )
    tpm_quote_b64: str | None = Field(
        None,
        max_length=16384,
        description=(
            "ADR-032 F3 Phase 1: base64url AIK quote envelope produced"
            " by the Linux TPM keystore (see"
            " ``cullis_connector.keystore.tpm_linux``). Optional. When"
            " present, the server verifies the quote against"
            " ``pubkey_pem`` + the nonce identified by"
            " ``attestation_nonce_id`` and, on success, persists the"
            " hardware-side claim ({hardware, strength, manufacturer})"
            " for the eventual ``effective_tier`` recomputation."
        ),
    )
    tpm_manufacturer: str | None = Field(
        None,
        max_length=64,
        description=(
            "Self-declared TPM EK manufacturer (Infineon / ST / etc)."
            " Cross-checked against ``TPM_MANUFACTURER_WHITELIST`` on"
            " the server; an unknown vendor downgrades ``strength`` to"
            " ``hw_isolated`` (Phase 1 EK CA chain deferred per Q8)."
        ),
    )
    tpm_ek_cert_present: bool = Field(
        False,
        description=(
            "Whether the Connector found an EK certificate in NV index"
            " 0x01C00002. Used together with ``tpm_manufacturer`` to"
            " gate ``hw_attested`` strength. swtpm / vTPM environments"
            " typically report ``False`` and stay at ``hw_isolated``."
        ),
    )


class EnrollmentStartResponse(BaseModel):
    session_id: str
    status: Literal["pending"]
    poll_url: str
    enroll_url: str
    poll_interval_s: int
    expires_at: str


class EnrollmentStatusResponse(BaseModel):
    session_id: str
    status: Literal["pending", "approved", "rejected", "expired"]
    # Populated only when status == "approved"
    agent_id: str | None = None
    cert_pem: str | None = None
    capabilities: list[str] | None = None
    # Populated only when status == "rejected"
    rejection_reason: str | None = None


class EnrollmentApproveRequest(BaseModel):
    """Admin decision to approve a pending enrollment."""

    agent_id: str = Field(..., min_length=1, max_length=200)
    capabilities: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)


class EnrollmentRejectRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)


class PendingEnrollmentSummary(BaseModel):
    """Single item in the admin list of pending enrollments."""

    session_id: str
    requester_name: str
    requester_email: str
    reason: str | None
    device_info: str | None
    pubkey_fingerprint: str
    created_at: str
    expires_at: str
