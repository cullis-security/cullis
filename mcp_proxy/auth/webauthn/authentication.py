"""WebAuthn authentication ceremony — issue options, verify assertion.

Counterpart to :mod:`registration`. The Connector dashboard calls
``/v1/principals/{pid}/webauthn/authenticate/start`` whenever it needs
a fresh user assertion (typically right before emitting a new user
session token). The resulting options blob is fed to
``navigator.credentials.get`` in the browser; the assertion is then
forwarded to the Mastio inline with the session emission request.

Verification is strict: the signature must validate against the
credential public key on file, the challenge must match the one we
minted, and ``sign_count`` must move forward (the authenticator
specifies a monotonic counter and a rewind is the published WebAuthn
signal for credential cloning).
"""
from __future__ import annotations

import base64
import json
import logging
import secrets
from dataclasses import dataclass
from typing import Iterable

from mcp_proxy.auth.webauthn._lib import load_lib
from mcp_proxy.auth.webauthn.errors import WebAuthnVerificationFailedError

_log = logging.getLogger("mcp_proxy.auth.webauthn.authentication")


@dataclass(frozen=True)
class AuthenticationOptions:
    """Payload returned to the dashboard for ``navigator.credentials.get``."""

    options_json: dict
    challenge_b64url: str


@dataclass(frozen=True)
class CredentialRecord:
    """Stored credential row, passed in by the storage layer.

    The fields here mirror columns on ``user_webauthn_credentials`` —
    we keep the dataclass narrow to the data verification actually needs
    so the verification function stays mockable without spinning up DB
    fixtures in unit tests.
    """

    credential_id: bytes
    credential_public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class VerifiedAssertion:
    """Result of a successful assertion verification."""

    credential_id: bytes
    new_sign_count: int


def generate_options(
    *,
    rp_id: str,
    allowed_credentials: Iterable[CredentialRecord],
) -> AuthenticationOptions:
    """Mint a fresh authentication challenge + options blob.

    ``allowed_credentials`` constrains the browser to credentials we
    actually know about — important on platforms (Windows Hello, Touch
    ID) that would otherwise prompt for any platform authenticator.
    """
    webauthn = load_lib()
    structs = webauthn.helpers.structs

    challenge = secrets.token_bytes(32)
    descriptors = [
        structs.PublicKeyCredentialDescriptor(id=cr.credential_id)
        for cr in allowed_credentials
        if cr.credential_id
    ]
    if not descriptors:
        raise WebAuthnVerificationFailedError(
            "no registered credentials for this principal; "
            "register an authenticator before requesting authentication.",
        )

    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=descriptors,
    )
    options_dict = json.loads(
        webauthn.options_to_json(options),
    )
    return AuthenticationOptions(
        options_json=options_dict,
        challenge_b64url=_b64url(challenge),
    )


def verify_response(
    *,
    rp_id: str,
    expected_origins: list[str],
    expected_challenge_b64url: str,
    credential_response: dict,
    credentials: Iterable[CredentialRecord],
) -> VerifiedAssertion:
    """Validate the assertion returned by the browser.

    Looks up the matching ``credential_id`` in ``credentials`` (the row
    set the storage layer fetched for this principal), then verifies
    the signature with py_webauthn. Raises
    :class:`WebAuthnVerificationFailedError` on any mismatch.
    """
    webauthn = load_lib()
    if not expected_origins:
        raise WebAuthnVerificationFailedError(
            "no expected origin configured for WebAuthn verification; "
            "set MCP_PROXY_WEBAUTHN_EXPECTED_ORIGIN or derive a default "
            "from MCP_PROXY_WEBAUTHN_RP_ID before enforcing.",
        )

    challenge = _b64url_decode(expected_challenge_b64url)
    cred_id_raw = credential_response.get("rawId") or credential_response.get("id")
    if not cred_id_raw:
        raise WebAuthnVerificationFailedError(
            "credential response missing rawId; cannot match credential.",
        )
    cred_id_bytes = _b64url_decode(cred_id_raw) if isinstance(cred_id_raw, str) else cred_id_raw

    record = _match_credential(cred_id_bytes, credentials)
    if record is None:
        raise WebAuthnVerificationFailedError(
            "credential id not registered for this principal.",
        )

    try:
        auth_credential = webauthn.helpers.parse_authentication_credential_json(
            json.dumps(credential_response),
        )
    except Exception as exc:
        raise WebAuthnVerificationFailedError(
            f"malformed assertion payload: {exc.__class__.__name__}",
        ) from exc

    last_exc: Exception | None = None
    for origin in expected_origins:
        try:
            verification = webauthn.verify_authentication_response(
                credential=auth_credential,
                expected_challenge=challenge,
                expected_rp_id=rp_id,
                expected_origin=origin,
                credential_public_key=record.credential_public_key,
                credential_current_sign_count=record.sign_count,
                require_user_verification=True,
            )
            new_count = int(verification.new_sign_count)
            return VerifiedAssertion(
                credential_id=record.credential_id,
                new_sign_count=new_count,
            )
        except Exception as exc:
            last_exc = exc
            continue

    assert last_exc is not None
    raise WebAuthnVerificationFailedError(
        f"assertion verification failed: {last_exc.__class__.__name__}",
    ) from last_exc


def _match_credential(
    cred_id_bytes: bytes, credentials: Iterable[CredentialRecord],
) -> CredentialRecord | None:
    for record in credentials:
        if record.credential_id == cred_id_bytes:
            return record
    return None


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
