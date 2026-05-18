"""WebAuthn registration ceremony — issue options, verify attestation.

The Connector dashboard drives this in three steps:

1. ``POST /v1/principals/{pid}/webauthn/register/start`` — returns the
   ``publicKeyCredentialCreationOptions`` JSON that the browser feeds
   to ``navigator.credentials.create``. The Mastio mints a random
   challenge bound to ``(principal_id, "register")`` and stores it
   with TTL ``webauthn_challenge_ttl_seconds``.

2. Browser prompts the user for a gesture (Touch ID, YubiKey tap,
   Windows Hello). Returns an ``AttestationResponse`` (clientDataJSON,
   attestationObject, transports).

3. ``POST /v1/principals/{pid}/webauthn/register/finish`` — Mastio
   consumes the challenge atomically, verifies the attestation
   against py_webauthn, persists the resulting credential, returns
   the public ``credential_id``.

Attestation verification today trusts the authenticator's self-claim
(no MDS root chain). Production deployments that require strict
authenticator attestation can extend the verification call with an
explicit list of trusted AAGUIDs; the storage layer already keeps
``aaguid`` per credential for that purpose.
"""
from __future__ import annotations

import base64
import json
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Iterable

from mcp_proxy.auth.webauthn._lib import load_lib
from mcp_proxy.auth.webauthn.errors import WebAuthnVerificationFailedError

_log = logging.getLogger("mcp_proxy.auth.webauthn.registration")


@dataclass(frozen=True)
class RegistrationOptions:
    """Payload returned to the dashboard for ``navigator.credentials.create``."""

    options_json: dict
    challenge_b64url: str


@dataclass(frozen=True)
class VerifiedRegistration:
    """Result of a successful attestation verification."""

    credential_id: bytes
    credential_public_key: bytes
    sign_count: int
    aaguid: bytes | None
    transports: list[str] | None


def _principal_user_id(principal_id: str) -> bytes:
    """Stable, opaque user-handle bytes for a principal.

    py_webauthn requires the ``user.id`` field to be ``bytes`` and not
    contain PII (Apple/Google sync passkeys round-trip this verbatim
    through the user's cloud). We derive a 16-byte SHAKE digest of the
    principal id so a leak of the credential set does not reveal the
    raw user_name embedded inside it.
    """
    import hashlib

    return hashlib.shake_256(principal_id.encode("utf-8")).digest(16)


def generate_options(
    *,
    rp_id: str,
    rp_name: str,
    principal_id: str,
    user_name: str,
    display_name: str | None,
    existing_credentials: Iterable[bytes] = (),
) -> RegistrationOptions:
    """Mint a fresh registration challenge + options blob.

    ``existing_credentials`` is a list of ``credential_id`` bytes the
    user already has registered — passed to py_webauthn as
    ``exclude_credentials`` so the browser refuses to re-register the
    same authenticator twice (a UX win, not a security control).
    """
    webauthn = load_lib()
    challenge = secrets.token_bytes(32)
    structs = webauthn.helpers.structs

    user_id_bytes = _principal_user_id(principal_id)
    exclude = [
        structs.PublicKeyCredentialDescriptor(id=cid)
        for cid in existing_credentials
        if cid
    ]
    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id_bytes,
        user_name=user_name,
        user_display_name=display_name or user_name,
        challenge=challenge,
        exclude_credentials=exclude,
    )
    options_dict = json.loads(
        webauthn.options_to_json(options),
    )
    return RegistrationOptions(
        options_json=options_dict,
        challenge_b64url=_b64url(challenge),
    )


def verify_response(
    *,
    rp_id: str,
    expected_origins: list[str],
    expected_challenge_b64url: str,
    credential_response: dict,
) -> VerifiedRegistration:
    """Validate the attestation returned by the browser.

    Raises :class:`WebAuthnVerificationFailedError` with an
    operator-friendly message for every failure (challenge mismatch,
    origin not allowed, bad signature, malformed JSON). The exception
    text is safe to put into audit chain entries — no signature bytes,
    no challenge raw.
    """
    webauthn = load_lib()
    if not expected_origins:
        raise WebAuthnVerificationFailedError(
            "no expected origin configured for WebAuthn verification; "
            "set MCP_PROXY_WEBAUTHN_EXPECTED_ORIGIN or derive a default "
            "from MCP_PROXY_WEBAUTHN_RP_ID before enforcing.",
        )
    challenge = _b64url_decode(expected_challenge_b64url)

    try:
        registration_credential = webauthn.helpers.parse_registration_credential_json(
            json.dumps(credential_response),
        )
    except Exception as exc:
        raise WebAuthnVerificationFailedError(
            f"malformed registration credential payload: {exc.__class__.__name__}",
        ) from exc

    last_exc: Exception | None = None
    for origin in expected_origins:
        try:
            verification = webauthn.verify_registration_response(
                credential=registration_credential,
                expected_challenge=challenge,
                expected_rp_id=rp_id,
                expected_origin=origin,
                require_user_verification=True,
            )
            transports = _extract_transports(credential_response)
            return VerifiedRegistration(
                credential_id=verification.credential_id,
                credential_public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
                aaguid=_extract_aaguid(verification),
                transports=transports,
            )
        except Exception as exc:
            last_exc = exc
            continue

    assert last_exc is not None  # at least one origin tried
    raise WebAuthnVerificationFailedError(
        f"registration verification failed: {last_exc.__class__.__name__}",
    ) from last_exc


def _extract_aaguid(verification: Any) -> bytes | None:
    """Pull the ``aaguid`` out of the verification result if present."""
    raw = getattr(verification, "aaguid", None)
    if not raw:
        return None
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode("utf-8")
    return None


def _extract_transports(credential_response: dict) -> list[str] | None:
    """Read the optional ``transports`` array reported by the browser."""
    response = credential_response.get("response") or {}
    transports = response.get("transports")
    if isinstance(transports, list) and all(isinstance(t, str) for t in transports):
        return transports
    return None


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
